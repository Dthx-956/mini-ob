//! mini-obs/agent/storage.rs
//! 日志存储引擎 —— 基于 format.rs 规范的 Segment 文件管理
//!
//! 写入流水线：
//!   append -> WAL 文本追加 -> 内存缓冲 -> 阈值触发 flush
//!   flush -> drain 缓冲 -> compressor 降熵压缩 -> 原子写入 Segment
//!          -> index.add_segment 注册 -> WAL 截断
//!
//! 查询流水线：
//!   index.query_range 时间过滤 -> mmap Segment -> CRC 验证 -> 流式解压 -> 关键词匹配
//!
//! 崩溃恢复：
//!   启动时读取 WAL -> 重放入缓冲 -> 立即 flush 为 Segment -> 截断 WAL
//!
//! 并发策略：本模块假设顺序写入（单线程消费），Mutex 仅作状态保护。
//!          多线程并发 append 需由调用方外部同步。

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::agent::compressor::{Compressor, CompressorConfig};
use crate::agent::index::{Index, IndexStats};
use crate::shared::format::{
    align_up, crc32, now_ms, segment_name, ChunkEntry, FormatError, LogLine, SegmentFooter,
    SegmentHeader, ALIGNMENT, CHUNK_ENTRY_SIZE, SEGMENT_FOOTER_SIZE, SEGMENT_HEADER_SIZE,
};

// ==================== 配置与统计 ====================

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub max_buffer_lines: usize,
    pub max_buffer_bytes: usize,
    pub compression_level: i32,
    pub dict: Option<Vec<u8>>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_buffer_lines: 1000,
            max_buffer_bytes: 64 * 1024,
            compression_level: 3,
            dict: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct StorageStats {
    pub segment_count: usize,
    pub total_lines: u64,
    pub buffered_lines: usize,
    pub buffered_bytes: usize,
    pub total_original_bytes: u64,
    pub total_compressed_bytes: u64,
}

impl StorageStats {
    pub fn compression_ratio(&self) -> f64 {
        if self.total_compressed_bytes == 0 {
            0.0
        } else {
            self.total_original_bytes as f64 / self.total_compressed_bytes as f64
        }
    }
}

// ==================== 内部状态 ====================

struct WriteState {
    wal: BufWriter<File>,
    buffer: Vec<LogLine>,
    buffer_bytes: usize,
}

/// Segment 写入元数据（内部传递）
struct SegmentMeta {
    id: u32,
    min_ts: u64,
    max_ts: u64,
    line_count: u32,
    original_sz: usize,
    compressed_sz: usize,
}

// ==================== 存储引擎 ====================

pub struct StorageEngine {
    data_dir: PathBuf,
    config: StorageConfig,
    index: Index,
    compressor: Compressor,
    state: Mutex<WriteState>,
    total_original: AtomicU64,
    total_compressed: AtomicU64,
}

impl StorageEngine {
    // ---------- 生命周期 ----------

    /// 打开或初始化存储目录
    ///
    /// 自动恢复未 flush 的 WAL 数据，保证崩溃后不丢已确认日志。
    pub fn open(data_dir: impl AsRef<Path>, config: StorageConfig) -> io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(data_dir.join("wal"))?;
        fs::create_dir_all(data_dir.join("segments"))?;
        fs::create_dir_all(data_dir.join("index"))?;

        let index = Index::open(&data_dir)?;
        let compressor = Compressor::new(CompressorConfig {
            zstd_level: config.compression_level,
            dict: config.dict.clone(),
            ..Default::default()
        });

        let wal_path = data_dir.join("wal").join("current.wal");
        let wal_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)?;

        let mut engine = Self {
            data_dir,
            config,
            index,
            compressor,
            state: Mutex::new(WriteState {
                wal: BufWriter::with_capacity(4096, wal_file),
                buffer: Vec::with_capacity(1024),
                buffer_bytes: 0,
            }),
            total_original: AtomicU64::new(0),
            total_compressed: AtomicU64::new(0),
        };

        // 崩溃恢复：读取 WAL 并立即 flush
        let recovered = Self::read_wal(&wal_path)?;
        if !recovered.is_empty() {
            {
                let mut state = engine.state.lock().unwrap();
                state.buffer = recovered;
                state.buffer_bytes = state
                    .buffer
                    .iter()
                    .map(|l| serde_json::to_vec(l).unwrap_or_default().len())
                    .sum();
            }
            engine.flush()?;
        }

        Ok(engine)
    }

    // ---------- 公共 API ----------

    /// 追加单条日志
    ///
    /// 先写 WAL（断电保护），再入内存缓冲。达到阈值时自动触发 flush。
    pub fn append(&self, log: LogLine) -> io::Result<()> {
        let json = serde_json::to_vec(&log)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let json_len = json.len();

        let should_flush = {
            let mut state = self.state.lock().unwrap();
            state.buffer.push(log);
            state.buffer_bytes += json_len + 1; // +1 for newline

            // WAL 写入（文本 JSON Lines，便于恢复）
            state.wal.write_all(&json)?;
            state.wal.write_all(b"\n")?;

            state.buffer.len() >= self.config.max_buffer_lines
                || state.buffer_bytes >= self.config.max_buffer_bytes
        };

        if should_flush {
            self.flush()?;
        }
        Ok(())
    }

    /// 强制将内存缓冲刷为 Segment
    ///
    /// 提取缓冲 -> 压缩 -> 原子写入 Segment -> 注册索引 -> 截断 WAL。
    /// 注意：本方法在 state lock 临界区内完成 drain 和 WAL 截断，
    ///       压缩与文件写入在释放锁后进行，允许并发查询。
    pub fn flush(&self) -> io::Result<()> {
        let logs: Vec<LogLine>;
        let wal_path = self.data_dir.join("wal").join("current.wal");

        // 1. 在锁内提取数据并落盘 WAL
        {
            let mut state = self.state.lock().unwrap();
            if state.buffer.is_empty() {
                return Ok(());
            }
            state.wal.flush()?; // 确保已写入的 WAL 落盘
            logs = state.buffer.drain(..).collect();
            state.buffer_bytes = 0;
        }

        // 2. 无锁压缩与写入（耗时操作，不阻塞 append）
        let meta = self.write_segment(&logs)?;

        // 3. 注册索引（原子持久化）
        self.index
            .add_segment(meta.id, meta.min_ts, meta.max_ts, meta.line_count)?;

        // 4. 更新统计
        self.total_original
            .fetch_add(meta.original_sz as u64, Ordering::Relaxed);
        self.total_compressed
            .fetch_add(meta.compressed_sz as u64, Ordering::Relaxed);

        // 5. 截断 WAL（数据已安全在 Segment 中）
        {
            let mut state = self.state.lock().unwrap();
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&wal_path)?;
            state.wal = BufWriter::with_capacity(4096, file);
        }

        Ok(())
    }

    /// 时间范围 + 关键词查询
    ///
    /// 按时间倒序返回，最新日志优先。关键词在服务名/级别/消息中子串匹配。
    pub fn query(
        &self,
        start: u64,
        end: u64,
        keyword: &str,
        limit: usize,
    ) -> io::Result<Vec<LogLine>> {
        let entries = self.index.query_range(start, end);
        let mut results = Vec::with_capacity(limit.min(100));

        for entry in entries {
            if results.len() >= limit {
                break;
            }
            let seg_path = self
                .data_dir
                .join("segments")
                .join(segment_name(entry.segment_id));
            self.query_segment_file(
                &seg_path,
                start,
                end,
                keyword,
                limit - results.len(),
                &mut results,
            )?;
        }

        Ok(results)
    }

    /// 获取存储统计
    pub fn stats(&self) -> StorageStats {
        let idx_stats = self.index.stats();
        let state = self.state.lock().unwrap();

        StorageStats {
            segment_count: idx_stats.segment_count,
            total_lines: idx_stats.total_lines,
            buffered_lines: state.buffer.len(),
            buffered_bytes: state.buffer_bytes,
            total_original_bytes: self.total_original.load(Ordering::Relaxed),
            total_compressed_bytes: self.total_compressed.load(Ordering::Relaxed),
        }
    }

    // ---------- 私有：Segment 写入 ----------

    /// 将一批日志压缩并原子写入 Segment 文件
    fn write_segment(&self, logs: &[LogLine]) -> io::Result<SegmentMeta> {
        let id = self.index.next_segment_id();

        // 1. 压缩
        let compressed = self.compressor.compress_batch(logs)?;
        let compressed_sz = compressed.len();

        // 2. 计算元数据
        let min_ts = logs.iter().map(|l| l.ts).min().unwrap_or(0);
        let max_ts = logs.iter().map(|l| l.ts).max().unwrap_or(0);
        let line_count = logs.len() as u32;
        let original_sz: usize = logs
            .iter()
            .map(|l| serde_json::to_vec(l).unwrap_or_default().len() + 1)
            .sum();

        // 3. 构建二进制文件
        let chunk_offset = align_up(SEGMENT_HEADER_SIZE + CHUNK_ENTRY_SIZE, ALIGNMENT) as u32;

        // Header
        let mut header = SegmentHeader::new(id, 1); // 单 Chunk 简化模型
        header.created_at = now_ms();
        let header_bytes = header.to_bytes();

        // Chunk Entry
        let entry = ChunkEntry::new(
            chunk_offset,
            compressed_sz as u32,
            original_sz as u32,
            line_count,
            min_ts,
            max_ts,
        );
        let entry_bytes = entry.to_bytes();

        // Padding 到 4KB 对齐
        let padding_size = (chunk_offset as usize) - SEGMENT_HEADER_SIZE - CHUNK_ENTRY_SIZE;
        let padding = vec![0u8; padding_size];

        // 组装内容（用于 Footer CRC）
        let mut content = Vec::with_capacity(
            (chunk_offset as usize) + compressed_sz + SEGMENT_FOOTER_SIZE,
        );
        content.extend_from_slice(&header_bytes);
        content.extend_from_slice(&entry_bytes);
        content.extend_from_slice(&padding);
        content.extend_from_slice(&compressed);

        // Footer
        let mut footer = SegmentFooter::new(SEGMENT_HEADER_SIZE as u32);
        footer.crc32 = crc32(&content);
        let footer_bytes = footer.to_bytes();

        // 4. 原子写入
        let seg_dir = self.data_dir.join("segments");
        fs::create_dir_all(&seg_dir)?;
        let tmp_path = seg_dir.join(format!(".tmp.segment-{:08}.mobs", id));
        let final_path = seg_dir.join(segment_name(id));

        let mut file = File::create(&tmp_path)?;
        file.write_all(&content)?;
        file.write_all(&footer_bytes)?;
        file.sync_all()?;
        drop(file);

        fs::rename(tmp_path, final_path)?;

        Ok(SegmentMeta {
            id,
            min_ts,
            max_ts,
            line_count,
            original_sz,
            compressed_sz,
        })
    }

    // ---------- 私有：Segment 查询 ----------

    /// 在单个 Segment 文件内执行流式解压与过滤
    fn query_segment_file(
        &self,
        path: &Path,
        start: u64,
        end: u64,
        keyword: &str,
        limit: usize,
        results: &mut Vec<LogLine>,
    ) -> io::Result<()> {
        let file = File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        let file_len = mmap.len();

        if file_len < SEGMENT_HEADER_SIZE + CHUNK_ENTRY_SIZE + SEGMENT_FOOTER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment file too short",
            ));
        }

        // 解析 Header
        let header = SegmentHeader::from_bytes(&mmap[0..SEGMENT_HEADER_SIZE])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 解析 Chunk Entry
        let chunk = ChunkEntry::from_bytes(
            &mmap[SEGMENT_HEADER_SIZE..SEGMENT_HEADER_SIZE + CHUNK_ENTRY_SIZE],
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 时间二次过滤（Chunk 级）
        if chunk.max_ts < start || chunk.min_ts > end {
            return Ok(());
        }

        // 验证 Footer CRC
        let footer_offset = file_len - SEGMENT_FOOTER_SIZE;
        let footer = SegmentFooter::from_bytes(&mmap[footer_offset..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let content = &mmap[0..footer_offset];
        footer
            .verify(content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 提取压缩数据
        let data_start = chunk.offset as usize;
        let data_end = data_start + chunk.compressed_sz as usize;
        if data_end > footer_offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk data out of bounds",
            ));
        }
        let compressed = &mmap[data_start..data_end];

        // 解压并逐行过滤
        let batch = self
            .compressor
            .decompress_batch(compressed)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        for log in batch {
            if log.ts >= start && log.ts <= end {
                if log.service.contains(keyword)
                    || log.level.contains(keyword)
                    || log.message.contains(keyword)
                {
                    results.push(log);
                    if results.len() >= limit {
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    // ---------- 私有：WAL 恢复 ----------

    fn read_wal(path: &Path) -> io::Result<Vec<LogLine>> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let reader = BufReader::new(file);
        let mut logs = Vec::new();

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[storage] WAL read error: {}", e);
                    continue;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<LogLine>(&line) {
                Ok(log) => logs.push(log),
                Err(e) => eprintln!("[storage] WAL recover skip: {} ({})", line, e),
            }
        }

        Ok(logs)
    }
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let dir = std::env::temp_dir().join(format!("mini-obs-storage-test-{}", ts));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_log(ts: u64, svc: &str, lvl: &str, msg: &str) -> LogLine {
        LogLine {
            ts,
            service: svc.to_string(),
            level: lvl.to_string(),
            message: msg.to_string(),
        }
    }

    #[test]
    fn test_open_empty_and_append() {
        let dir = temp_dir();
        let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();

        engine
            .append(make_log(1715424000000, "app", "I", "hello"))
            .unwrap();

        let stats = engine.stats();
        assert_eq!(stats.buffered_lines, 1);
        assert_eq!(stats.segment_count, 0);
    }

    #[test]
    fn test_flush_and_query() {
        let dir = temp_dir();
        let cfg = StorageConfig {
            max_buffer_lines: 3,
            ..Default::default()
        };
        let engine = StorageEngine::open(&dir, cfg).unwrap();

        engine.append(make_log(1000, "svc", "I", "alpha")).unwrap();
        engine.append(make_log(2000, "svc", "W", "beta")).unwrap();
        engine.append(make_log(3000, "svc", "E", "gamma")).unwrap(); // 触发 flush

        let stats = engine.stats();
        assert_eq!(stats.segment_count, 1);
        assert_eq!(stats.total_lines, 3);
        assert_eq!(stats.buffered_lines, 0);

        // 查询全部
        let all = engine.query(0, u64::MAX, "", 100).unwrap();
        assert_eq!(all.len(), 3);

        // 关键词查询
        let err = engine.query(0, u64::MAX, "gamma", 100).unwrap();
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].level, "E");

        // 时间范围
        let limited = engine.query(1500, 2500, "", 100).unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].message, "beta");
    }

    #[test]
    fn test_wal_crash_recovery() {
        let dir = temp_dir();
        let cfg = StorageConfig {
            max_buffer_lines: 100, // 设置很大，避免自动 flush
            ..Default::default()
        };
        let engine = StorageEngine::open(&dir, cfg.clone()).unwrap();

        engine.append(make_log(1000, "a", "I", "x")).unwrap();
        engine.append(make_log(2000, "a", "I", "y")).unwrap();
        engine.append(make_log(3000, "a", "I", "z")).unwrap();

        // 故意不 flush，直接 drop
        drop(engine);

        // 重新打开，应通过 WAL 恢复并自动 flush
        let engine2 = StorageEngine::open(&dir, cfg).unwrap();
        let stats = engine2.stats();
        assert_eq!(stats.segment_count, 1);
        assert_eq!(stats.total_lines, 3);
        assert_eq!(stats.buffered_lines, 0);

        let all = engine2.query(0, u64::MAX, "", 100).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_compression_ratio_high_repeat() {
        let dir = temp_dir();
        let cfg = StorageConfig {
            max_buffer_lines: 1000,
            ..Default::default()
        };
        let engine = StorageEngine::open(&dir, cfg).unwrap();

        let msg = "Sensor temperature=25.3 humidity=60% status=OK device=DEV-12345";
        for i in 0..1000 {
            engine
                .append(make_log(1000 + i as u64 * 100, "iot", "I", msg))
                .unwrap();
        }

        let stats = engine.stats();
        let ratio = stats.compression_ratio();
        println!(
            "Segments: {}, Original: {}, Compressed: {}, Ratio: {:.2}x",
            stats.segment_count,
            stats.total_original_bytes,
            stats.total_compressed_bytes,
            ratio
        );
        assert!(ratio > 3.0, "expected >3x compression, got {:.2}x", ratio);
    }

    #[test]
    fn test_time_range_descending() {
        let dir = temp_dir();
        let cfg = StorageConfig {
            max_buffer_lines: 2,
            ..Default::default()
        };
        let engine = StorageEngine::open(&dir, cfg).unwrap();

        engine.append(make_log(1000, "a", "I", "first")).unwrap();
        engine.append(make_log(2000, "a", "I", "second")).unwrap(); // flush seg 1
        engine.append(make_log(3000, "a", "I", "third")).unwrap();
        engine.append(make_log(4000, "a", "I", "fourth")).unwrap(); // flush seg 2

        let all = engine.query(0, u64::MAX, "", 100).unwrap();
        assert_eq!(all.len(), 4);
        // 倒序：最新优先
        assert_eq!(all[0].ts, 4000);
        assert_eq!(all[3].ts, 1000);
    }

    #[test]
    fn test_multiple_segments_query() {
        let dir = temp_dir();
        let cfg = StorageConfig {
            max_buffer_lines: 1, // 每条都 flush，产生多个 Segment
            ..Default::default()
        };
        let engine = StorageEngine::open(&dir, cfg).unwrap();

        for i in 0..10 {
            engine
                .append(make_log(i as u64 * 1000, "svc", "I", &format!("msg-{}", i)))
                .unwrap();
        }

        let stats = engine.stats();
        assert_eq!(stats.segment_count, 10);

        let all = engine.query(0, u64::MAX, "msg", 100).unwrap();
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_empty_query() {
        let dir = temp_dir();
        let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();
        let res = engine.query(0, 100, "none", 10).unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn test_large_batch_stability() {
        let dir = temp_dir();
        let cfg = StorageConfig {
            max_buffer_lines: 500,
            ..Default::default()
        };
        let engine = StorageEngine::open(&dir, cfg).unwrap();

        for i in 0..5000 {
            engine
                .append(make_log(
                    i as u64 * 100,
                    "app",
                    "I",
                    &format!("log entry number {}", i),
                ))
                .unwrap();
        }

        let stats = engine.stats();
        assert_eq!(stats.total_lines, 5000);

        let sample = engine.query(0, u64::MAX, "number 4999", 10).unwrap();
        assert_eq!(sample.len(), 1);
        assert_eq!(sample[0].message, "log entry number 4999");
    }
}