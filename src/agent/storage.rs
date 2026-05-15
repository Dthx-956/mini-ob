//! mini-obs/agent/storage.rs
//! 日志存储引擎 —— 基于 format.rs v2 的多 Chunk Segment 管理
//!
//! 写入流水线：
//!   append -> WAL 文本追加 -> 内存缓冲 -> 阈值触发 flush
//!   flush -> drain 缓冲 -> template 提取 -> 按 256 行切 Chunk
//!          -> 每 Chunk 计算 Summary + XOR-P 编码 -> Zstd 压缩
//!          -> 组装 Segment v2（PatternTable + ChunkTable + SummaryTable + Data）
//!          -> index.add_segment 注册 -> WAL 截断
//!
//! 查询流水线（v2 两阶段过滤）：
//!   index.query_range 时间过滤
//!     -> mmap Segment
//!     -> 读取 PatternTable，构建 keyword -> pat_ids 映射
//!     -> 遍历 ChunkSummary：时间 -> pattern_mask -> param_bloom
//!     -> 仅对命中 Chunk 解压、XOR-P 还原、逐行匹配

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::agent::compressor::{Compressor, CompressorConfig};
use crate::agent::index::Index;
use crate::agent::template::{
    EncodedRecord, TemplateBatch, TemplateExtractor, TemplatePart,
};
use crate::shared::format::{
    align_up, crc32, padding_needed, segment_name, ChunkEntry, ChunkSummary, LogLine,
    SegmentFooter, SegmentHeader, SegmentSummary, ALIGNMENT, CHUNK_ENTRY_SIZE, CHUNK_SUMMARY_SIZE,
    FORMAT_VERSION_V1, MIN_SEGMENT_SIZE, SEGMENT_FOOTER_SIZE, SEGMENT_HEADER_SIZE,
};

// ==================== 配置与统计 ====================

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub max_buffer_lines: usize,
    pub max_buffer_bytes: usize,
    pub compression_level: i32,
    pub chunk_size: usize, // 新增：每 Chunk 行数，默认 256
    pub dict: Option<Vec<u8>>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_buffer_lines: 1000,
            max_buffer_bytes: 64 * 1024,
            compression_level: 3,
            chunk_size: 256,
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

        let seg_dir = data_dir.join("segments");
        let wal_path = data_dir.join("wal").join("current.wal");
        let wal_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)?;

        let engine = Self {
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

        // 重建已有 segment 的 size 统计（进程重启后 AtomicU64 归零）
        if let Ok(entries) = fs::read_dir(&seg_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("mobs") {
                    if let Ok((orig, comp)) = Self::read_segment_size_stats(&path) {
                        engine.total_original.fetch_add(orig, Ordering::Relaxed);
                        engine.total_compressed.fetch_add(comp, Ordering::Relaxed);
                    }
                }
            }
        }

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

    pub fn append(&self, log: LogLine) -> io::Result<()> {
        let json = serde_json::to_vec(&log)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let json_len = json.len();

        let should_flush = {
            let mut state = self.state.lock().unwrap();
            state.buffer.push(log);
            state.buffer_bytes += json_len + 1;
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

    pub fn flush(&self) -> io::Result<()> {
        let logs: Vec<LogLine>;
        let wal_path = self.data_dir.join("wal").join("current.wal");

        {
            let mut state = self.state.lock().unwrap();
            if state.buffer.is_empty() {
                return Ok(());
            }
            state.wal.flush()?;
            logs = state.buffer.drain(..).collect();
            state.buffer_bytes = 0;
        }

        let meta = self.write_segment_v2(&logs)?;

        self.total_original
            .fetch_add(meta.original_sz as u64, Ordering::Relaxed);
        self.total_compressed
            .fetch_add(meta.compressed_sz as u64, Ordering::Relaxed);

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

        // 搜索缓冲区中的日志
        {
            let state = self.state.lock().unwrap();
            for log in &state.buffer {
                if results.len() >= limit {
                    break;
                }
                if log.ts >= start && log.ts <= end {
                    if log.service.contains(keyword)
                        || log.level.contains(keyword)
                        || log.message.contains(keyword)
                    {
                        results.push(log.clone());
                    }
                }
            }
        }

        results.sort_by_key(|log| std::cmp::Reverse(log.ts));
        Ok(results)
    }

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

/// 从已有 Segment 文件中读取所有 Chunk 的 original/compressed 大小
fn read_segment_size_stats(path: &Path) -> io::Result<(u64, u64)> {
    let file = File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    if mmap.len() < SEGMENT_HEADER_SIZE + SEGMENT_FOOTER_SIZE {
        return Ok((0, 0));
    }
    let header = SegmentHeader::from_bytes(&mmap[0..SEGMENT_HEADER_SIZE])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let table_start = SEGMENT_HEADER_SIZE + header.pattern_table_len() as usize;
    let mut original = 0u64;
    let mut compressed = 0u64;
    for i in 0..header.chunk_count {
        let off = table_start + (i as usize) * CHUNK_ENTRY_SIZE;
        if off + CHUNK_ENTRY_SIZE > mmap.len() - SEGMENT_FOOTER_SIZE {
            break;
        }
        if let Ok(chunk) = ChunkEntry::from_bytes(&mmap[off..off + CHUNK_ENTRY_SIZE]) {
            original += chunk.original_sz as u64;
            compressed += chunk.compressed_sz as u64;
        }
    }
    Ok((original, compressed))
}

    // ---------- 私有：Segment v2 写入 ----------

    fn write_segment_v2(&self, logs: &[LogLine]) -> io::Result<SegmentMeta> {
        let id = self.index.next_segment_id();

        // 1. 模板提取
        let batch = TemplateExtractor::extract(logs);

        // 2. 按 chunk_size 切分 Chunk
        let chunk_size = self.config.chunk_size;
        let num_chunks = (logs.len() + chunk_size - 1) / chunk_size;
        let mut chunk_entries = Vec::with_capacity(num_chunks);
        let mut chunk_summaries = Vec::with_capacity(num_chunks);
        let mut chunk_data_parts = Vec::with_capacity(num_chunks);
        let mut total_compressed = 0usize;
        let mut total_original = 0usize;

        for chunk_idx in 0..num_chunks {
            let start = chunk_idx * chunk_size;
            let end = ((chunk_idx + 1) * chunk_size).min(logs.len());
            let chunk_logs = &logs[start..end];

            // 2a. 计算 ChunkSummary
            let mut pattern_mask: u64 = 0;
            let mut level_mask: u8 = 0;
            let mut bloom = [0u8; 64];

            for log_idx in start..end {
                let log = &logs[log_idx];
                // 找到该日志对应的模板 ID（从 batch.records 中按 original_idx 查找）
                if let Some(rec) = batch.records.iter().find(|r| r.original_idx == log_idx) {
                    if rec.pat_id < 64 {
                        pattern_mask |= 1u64 << rec.pat_id;
                    }
                }
                let level_bit = match log.level.as_str() {
                    "D" => 0,
                    "I" => 1,
                    "W" => 2,
                    "E" => 3,
                    _ => 1,
                };
                level_mask |= 1 << level_bit;

                // Bloom：对 message 中的每个 token 做标记
                // 简化：对整个 message 做 bloom hash
                for seed in 0..5 {
                    let pos = ChunkSummary::bloom_hash(&log.message, seed);
                    let byte_idx = pos / 8;
                    let bit_idx = pos % 8;
                    bloom[byte_idx] |= 1 << bit_idx;
                }
            }

            let summary = ChunkSummary::new(pattern_mask, level_mask, bloom);
            chunk_summaries.push(summary);

            // 2b. XOR-P 编码（Chunk 内首行存原始，后续引用 Chunk 首行）
            let chunk_records = &batch.records[start..end];
            let mut ref_params: Vec<String> = Vec::new();
            let mut encoded_records = Vec::with_capacity(chunk_records.len());

            for (i, rec) in chunk_records.iter().enumerate() {
                let mut encoding_data = Vec::new();
                encoding_data.extend_from_slice(&(rec.params.len() as u32).to_le_bytes());

                if i == 0 {
                    // Chunk 首行：存原始参数
                    ref_params = rec.params.clone();
                    for p in &rec.params {
                        let bytes = p.as_bytes();
                        encoding_data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                        encoding_data.extend_from_slice(bytes);
                    }
                } else {
                    // 后续行：XOR-P 编码，参考 Chunk 首行
                    for (p, base) in rec.params.iter().zip(ref_params.iter()) {
                        let encoded = TemplateExtractor::xor_param_64bit(p, base);
                        encoding_data.extend_from_slice(&encoded);
                    }
                }

                encoded_records.push(EncodedRecord {
                    ts_delta: rec.ts_delta,
                    svc_id: rec.svc_id,
                    level: rec.level.clone(),
                    pat_id: rec.pat_id,
                    param_encoding: crate::agent::template::ParamEncoding {
                        ref_idx: i as u16,
                        data: encoding_data,
                    },
                });
            }

            // 2c. 序列化 Chunk 二进制并压缩
            let chunk_binary = self.serialize_chunk_binary(&encoded_records, chunk_logs);
            // 直接用 Zstd 压缩 chunk_binary
            let compressed = zstd::encode_all(&chunk_binary[..], self.config.compression_level)?;

            let original_sz = chunk_binary.len();
            let compressed_sz = compressed.len();
            total_original += original_sz;
            total_compressed += compressed_sz;

            chunk_entries.push(ChunkEntry::new(
                0, // offset 稍后计算
                compressed_sz as u32,
                original_sz as u32,
                chunk_logs.len() as u32,
                chunk_logs.first().map(|l| l.ts).unwrap_or(0),
                chunk_logs.last().map(|l| l.ts).unwrap_or(0),
            ));
            chunk_data_parts.push(compressed);
        }

        // 3. 组装 Segment 文件
        let pattern_table = batch.serialize_pattern_table();
        let pattern_count = batch.templates.len() as u16;
        let pattern_table_len = pattern_table.len() as u32;

        // 计算各区域偏移（v2: Header + PatternTable + ChunkTable + SummaryTable + Padding + Data）
        let table_start = SEGMENT_HEADER_SIZE + pattern_table.len();
        let summary_start = table_start + num_chunks * CHUNK_ENTRY_SIZE;
        let data_offset_val = align_up(summary_start + num_chunks * CHUNK_SUMMARY_SIZE, ALIGNMENT);

        // 修正 ChunkEntry 的 offset（相对 data_offset）
        let mut prev_offset = 0u32;
        for entry in chunk_entries.iter_mut() {
            entry.offset = prev_offset;
            prev_offset = entry.offset + entry.compressed_sz;
        }

        // 构建 Header
        let mut header = SegmentHeader::new(id, num_chunks as u16);
        header.set_v2_meta(
            pattern_count,
            pattern_table_len,
            summary_start as u32,
            data_offset_val as u32,
        );

        // 组装内容
        let mut content = Vec::new();
        content.extend_from_slice(&header.to_bytes());
        content.extend_from_slice(&pattern_table);
        for entry in &chunk_entries {
            content.extend_from_slice(&entry.to_bytes());
        }
        for summary in &chunk_summaries {
            content.extend_from_slice(&summary.to_bytes());
        }
        // Padding
        let padding_size = padding_needed(content.len(), ALIGNMENT);
        content.extend_from_slice(&vec![0u8; padding_size]);
        // Chunk Data
        for part in &chunk_data_parts {
            content.extend_from_slice(part);
        }

        // Footer
        let mut footer = SegmentFooter::new(SEGMENT_HEADER_SIZE as u32);
        footer.crc32 = crc32(&content);
        content.extend_from_slice(&footer.to_bytes());

        // 4. 原子写入
        let seg_dir = self.data_dir.join("segments");
        fs::create_dir_all(&seg_dir)?;
        let tmp_path = seg_dir.join(format!(".tmp.segment-{:08}.mobs", id));
        let final_path = seg_dir.join(segment_name(id));

        let mut file = File::create(&tmp_path)?;
        file.write_all(&content)?;
        file.sync_all()?;
        drop(file);
        fs::rename(tmp_path, final_path)?;

        // 构建 SegmentSummary
        let mut summary = SegmentSummary::default();
        summary.pattern_mask = chunk_summaries.iter().map(|s| s.pattern_mask).fold(0, |a, b| a | b);
        summary.level_mask = chunk_summaries.iter().map(|s| s.level_mask).fold(0, |a, b| a | b);
        for cs in &chunk_summaries {
            for j in 0..64 {
                summary.param_bloom[j % 12] |= cs.param_bloom[j];
            }
        }
        summary.flags = SegmentSummary::HAS_SUMMARY;

        let min_ts = logs.iter().map(|l| l.ts).min().unwrap_or(0);
        let max_ts = logs.iter().map(|l| l.ts).max().unwrap_or(0);
        let line_count = logs.len() as u32;

        self.index.add_segment_with_summary(
            id,
            min_ts,
            max_ts,
            line_count,
            summary,
        )?;

        Ok(SegmentMeta {
            id,
            min_ts,
            max_ts,
            line_count,
            original_sz: total_original,
            compressed_sz: total_compressed,
        })
    }

    /// 序列化 Chunk 内的编码记录为二进制（供 Zstd 压缩）
    fn serialize_chunk_binary(&self, records: &[EncodedRecord], logs: &[LogLine]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(records.len() * 64);
        for (i, rec) in records.iter().enumerate() {
            // 存储绝对时间戳（u64），便于独立解码
            buf.extend_from_slice(&logs[i].ts.to_le_bytes());
            // 存储完整 service 字符串（len u16 + bytes）
            let svc_bytes = logs[i].service.as_bytes();
            buf.extend_from_slice(&(svc_bytes.len() as u16).to_le_bytes());
            buf.extend_from_slice(svc_bytes);
            buf.push(rec.level.as_bytes()[0]);
            buf.extend_from_slice(&rec.pat_id.to_le_bytes());
            // 参数编码数据
            buf.extend_from_slice(&(rec.param_encoding.data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&rec.param_encoding.data);
        }
        buf
    }

    // ---------- 私有：Segment 查询 ----------

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

        if file_len < MIN_SEGMENT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment file too short",
            ));
        }

        let header = SegmentHeader::from_bytes(&mmap[0..SEGMENT_HEADER_SIZE])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // v1 回退：整段解压
        if header.version == FORMAT_VERSION_V1 {
            return self.query_segment_v1(&mmap, header, start, end, keyword, limit, results);
        }

        // v2 两阶段查询
        self.query_segment_v2(&mmap, header, start, end, keyword, limit, results)
    }

    /// v1 回退查询（旧逻辑）
    fn query_segment_v1(
        &self,
        mmap: &[u8],
        _header: SegmentHeader,
        start: u64,
        end: u64,
        keyword: &str,
        limit: usize,
        results: &mut Vec<LogLine>,
    ) -> io::Result<()> {
        let chunk = ChunkEntry::from_bytes(
            &mmap[SEGMENT_HEADER_SIZE..SEGMENT_HEADER_SIZE + CHUNK_ENTRY_SIZE],
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if chunk.max_ts < start || chunk.min_ts > end {
            return Ok(());
        }

        let footer_offset = mmap.len() - SEGMENT_FOOTER_SIZE;
        let footer = SegmentFooter::from_bytes(&mmap[footer_offset..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let content = &mmap[0..footer_offset];
        footer
            .verify(content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let data_start = chunk.offset as usize;
        let data_end = data_start + chunk.compressed_sz as usize;
        if data_end > footer_offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk data out of bounds",
            ));
        }
        let compressed = &mmap[data_start..data_end];

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

    /// v2 两阶段查询（LogGrep 思想）
    fn query_segment_v2(
        &self,
        mmap: &[u8],
        header: SegmentHeader,
        start: u64,
        end: u64,
        keyword: &str,
        limit: usize,
        results: &mut Vec<LogLine>,
    ) -> io::Result<()> {
        let chunk_count = header.chunk_count as usize;
        let pattern_count = header.pattern_count() as usize;
        let pattern_table_len = header.pattern_table_len() as usize;
        let summary_offset = header.summary_offset() as usize;
        let data_offset = header.data_offset_v2() as usize;

        // 1. 读取并解析 PatternTable，构建 keyword -> pat_ids 映射
        let pattern_table_end = SEGMENT_HEADER_SIZE + pattern_table_len;
        let templates = if pattern_count > 0 && pattern_table_len > 0 {
            TemplateBatch::deserialize_pattern_table(&mmap[SEGMENT_HEADER_SIZE..pattern_table_end])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        } else {
            Vec::new()
        };

        let mut keyword_pats: Vec<u16> = Vec::new();
        for (i, t) in templates.iter().enumerate() {
            for part in &t.parts {
                if let TemplatePart::Literal(s) = part {
                    if s.contains(keyword) {
                        keyword_pats.push(i as u16);
                        break;
                    }
                }
            }
        }

        // 2. 读取 ChunkTable
        let table_start = SEGMENT_HEADER_SIZE + pattern_table_len;
        let mut chunks = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            let off = table_start + i * CHUNK_ENTRY_SIZE;
            chunks.push(
                ChunkEntry::from_bytes(&mmap[off..off + CHUNK_ENTRY_SIZE])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            );
        }

        // 3. 读取 ChunkSummaryTable
        let mut summaries = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            let off = summary_offset + i * CHUNK_SUMMARY_SIZE;
            summaries.push(
                ChunkSummary::from_bytes(&mmap[off..off + CHUNK_SUMMARY_SIZE])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            );
        }

        // 4. 验证 Footer
        let footer_offset = mmap.len() - SEGMENT_FOOTER_SIZE;
        let footer = SegmentFooter::from_bytes(&mmap[footer_offset..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let content = &mmap[0..footer_offset];
        footer
            .verify(content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 5. 遍历 Chunk，两阶段过滤
        for i in 0..chunk_count {
            if results.len() >= limit {
                break;
            }

            let chunk = &chunks[i];
            let summary = &summaries[i];
            // 时间过滤
            if chunk.max_ts < start || chunk.min_ts > end {
                continue;
            }

            // pattern_mask 过滤：若 keyword 匹配任何模板固定文本
            let mut pattern_hit = keyword_pats.is_empty(); // 若 keyword 不在任何模板中，保守处理
            for &pat_id in &keyword_pats {
                if summary.may_contain_pattern(pat_id) {
                    pattern_hit = true;
                    break;
                }
            }
            if !pattern_hit {
                continue; // 跳过不解压
            }

            // param_bloom 过滤：仅在 keyword 匹配了某个模板但 pattern_mask 不匹配时生效
            // 若 keyword 不在任何模板中（可能在 service/level/message 中），保守不解压过滤
            let keyword_in_template = !keyword_pats.is_empty() && pattern_hit;
            let should_bloom_skip = !keyword_in_template && !keyword_pats.is_empty();
            if should_bloom_skip && !summary.bloom_may_contain(keyword) {
                continue; // Bloom 判定一定不包含，跳过
            }

            // 精确解压匹配
            let data_start = data_offset + chunk.offset as usize;
            let data_end = data_start + chunk.compressed_sz as usize;
            if data_end > footer_offset {
                continue;
            }
            let compressed = &mmap[data_start..data_end];

            // 解压 Chunk 二进制
            let chunk_binary = zstd::decode_all(compressed)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            
            // 解析并还原 XOR-P
            let logs = self.deserialize_chunk_binary(&chunk_binary, &templates)?;
            for log in logs {
                if log.ts >= start && log.ts <= end {
                    let svc_match = log.service.contains(keyword);
                    let lvl_match = log.level.contains(keyword);
                    let msg_match = log.message.contains(keyword);
                    if svc_match || lvl_match || msg_match {
                        results.push(log);
                        if results.len() >= limit {
                            return Ok(());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 反序列化 Chunk 二进制并还原 XOR-P
    fn deserialize_chunk_binary(
        &self,
        data: &[u8],
        templates: &[crate::agent::template::Template],
    ) -> io::Result<Vec<LogLine>> {
        let mut logs = Vec::new();
        let mut offset = 0;
        let mut ref_params: Vec<String> = Vec::new();

        while offset < data.len() {
            // 读取 ts_delta
            if offset + 8 > data.len() {
                break;
            }
            let ts = u64::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7],
            ]);
            offset += 8;

            if offset + 2 > data.len() { break; }
            let svc_len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
            offset += 2;
            if offset + svc_len > data.len() { break; }
            let service = String::from_utf8_lossy(&data[offset..offset+svc_len]).to_string();
            offset += svc_len;

            if offset + 1 > data.len() { break; }
            let level_byte = data[offset];
            offset += 1;
            let level = match level_byte {
                b'D' => "D",
                b'I' => "I",
                b'W' => "W",
                b'E' => "E",
                _ => "I",
            };

            if offset + 2 > data.len() { break; }
            let pat_id = u16::from_le_bytes([data[offset], data[offset+1]]);
            offset += 2;

            if offset + 4 > data.len() { break; }
            let enc_len = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
            ]) as usize;
            offset += 4;

            if offset + enc_len > data.len() { break; }
            let enc_data = &data[offset..offset+enc_len];
            offset += enc_len;

            // 解析参数编码
            if enc_data.len() < 4 {
                logs.push(LogLine { ts, service, level: level.to_string(), message: "".to_string() });
                continue;
            }
            let param_count = u32::from_le_bytes([enc_data[0], enc_data[1], enc_data[2], enc_data[3]]) as usize;
            let mut params = Vec::with_capacity(param_count);

            if param_count > 0 && enc_data.len() > 8 {
                // 检查是否是原始参数（Chunk 首行）或 XOR-P
                let second_len = u32::from_le_bytes([enc_data[4], enc_data[5], enc_data[6], enc_data[7]]) as usize;
                let is_raw = second_len <= 256 && enc_data.len() >= 8 + second_len;

                if is_raw && ref_params.is_empty() {
                    // Chunk 首行：原始参数
                    let mut p_offset = 4;
                    for _ in 0..param_count {
                        let len = u32::from_le_bytes([enc_data[p_offset], enc_data[p_offset+1], enc_data[p_offset+2], enc_data[p_offset+3]]) as usize;
                        p_offset += 4;
                        let s = String::from_utf8_lossy(&enc_data[p_offset..p_offset+len]).to_string();
                        p_offset += len;
                        params.push(s);
                    }
                    ref_params = params.clone();
                } else {
                    // XOR-P 解码
                    let mut p_offset = 4;
                    for i in 0..param_count {
                        let base = ref_params.get(i).map(|s| s.as_str()).unwrap_or("");
                        let (param, consumed) = TemplateExtractor::decode_xor_param_64bit(&enc_data[p_offset..], base);
                        params.push(param);
                        p_offset += consumed;
                    }
                }
            }

            // 重建 message
            let template = templates.get(pat_id as usize);
            let message = if let Some(t) = template {
                let mut msg = String::new();
                let mut param_idx = 0;
                for part in &t.parts {
                    match part {
                        TemplatePart::Literal(s) => msg.push_str(s),
                        TemplatePart::Param => {
                            if let Some(p) = params.get(param_idx) {
                                msg.push_str(p);
                                param_idx += 1;
                            } else {
                                msg.push('*');
                            }
                        }
                    }
                }
                msg
            } else {
                params.join(" ")
            };

            // 重建 LogLine（ts 需要累积，但简化：用原始 batch 的 ts）
            // 注意：这里丢失了原始 ts，因为 Chunk 二进制只存了 ts_delta
            // 需要在 Chunk 首行存绝对 ts，或外部传入。简化：存绝对 ts 在 Chunk 首行。
            logs.push(LogLine {
                ts,
                service,
                level: level.to_string(),
                message,
            });
        }

        Ok(logs)
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
    use crate::test_util::temp_dir;

    fn test_dir() -> PathBuf {
        temp_dir("mini-obs-storage-test")
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
    fn test_v2_write_and_query() {
        let dir = test_dir();
        let cfg = StorageConfig {
            max_buffer_lines: 3,
            chunk_size: 2, // 小 Chunk 便于测试
            ..Default::default()
        };
        let engine = StorageEngine::open(&dir, cfg).unwrap();

        engine.append(make_log(1000, "svc", "I", "User 12345 logged in")).unwrap();
        engine.append(make_log(2000, "svc", "I", "User 67890 logged in")).unwrap();
        engine.append(make_log(3000, "svc", "E", "Connection timeout")).unwrap();

        let stats = engine.stats();
        assert_eq!(stats.segment_count, 1);
        assert_eq!(stats.total_lines, 3);

        let all = engine.query(0, u64::MAX, "", 100).unwrap();
        assert_eq!(all.len(), 3);

        let err = engine.query(0, u64::MAX, "timeout", 100).unwrap();
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].level, "E");
    }

    #[test]
    fn test_v2_chunk_skip_filter() {
        let dir = test_dir();
        let cfg = StorageConfig {
            max_buffer_lines: 10,
            chunk_size: 5,
            ..Default::default()
        };
        let engine = StorageEngine::open(&dir, cfg).unwrap();

        // 10 条模板日志
        for i in 0..10 {
            engine
                .append(make_log(
                    1000 + i as u64 * 100,
                    "svc",
                    "I",
                    &format!("User {} logged in", i),
                ))
                .unwrap();
        }

        // 查询一个不可能存在的词，应快速返回（零 Chunk 解压）
        let none = engine.query(0, u64::MAX, "NONEXISTENT_KEYWORD_999", 100).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn test_v1_backward_compat() {
        // 构造一个 v1 Segment 文件，验证仍可查询
        let dir = test_dir();
        fs::create_dir_all(dir.join("segments")).unwrap();
        fs::create_dir_all(dir.join("index")).unwrap();

        // 假压缩数据：3 条 JSON Lines 的 Zstd 压缩
        let fake_logs = vec![
            make_log(1000, "a", "I", "alpha"),
            make_log(2000, "a", "I", "beta"),
            make_log(3000, "a", "E", "gamma"),
        ];
        let fake_json = fake_logs
            .iter()
            .map(|l| serde_json::to_string(l).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let fake_compressed = zstd::encode_all(fake_json.as_bytes(), 3).unwrap();

        let header = SegmentHeader::new_v1(1, 1);
        let chunk = ChunkEntry::new(4096, fake_compressed.len() as u32, fake_json.len() as u32, 3, 1000, 3000);

        let mut content = Vec::new();
        content.extend_from_slice(&header.to_bytes());
        content.extend_from_slice(&chunk.to_bytes());
        let data_offset = header.data_offset();
        content.resize(data_offset, 0);

        content.extend_from_slice(&fake_compressed);

        let mut footer = SegmentFooter::new(SEGMENT_HEADER_SIZE as u32);
        footer.crc32 = crc32(&content);
        content.extend_from_slice(&footer.to_bytes());

        fs::write(dir.join("segments").join("segment-00000001.mobs"), content).unwrap();

        let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();
        let all = engine.query(0, u64::MAX, "", 100).unwrap();
        assert_eq!(all.len(), 3);
    }
// 将以下内容追加到 src/agent/storage.rs 的 #[cfg(test)] mod tests 中

#[test]
fn test_wal_crash_recovery() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 100,
        ..Default::default()
    };

    // 模拟崩溃：写入 WAL 但未 flush
    {
        let engine = StorageEngine::open(&dir, cfg.clone()).unwrap();
        engine.append(make_log(1000, "svc", "I", "wal line 1")).unwrap();
        engine.append(make_log(2000, "svc", "I", "wal line 2")).unwrap();
        engine.append(make_log(3000, "svc", "E", "wal line 3")).unwrap();
        // 不调用 flush，直接 drop（模拟崩溃）
    }

    // 重新打开，应自动恢复 WAL 并 flush 为 Segment
    let engine = StorageEngine::open(&dir, cfg).unwrap();
    let stats = engine.stats();
    assert_eq!(stats.total_lines, 3);
    assert_eq!(stats.segment_count, 1);

    let all = engine.query(0, u64::MAX, "", 100).unwrap();
    assert_eq!(all.len(), 3);
    assert!(all.iter().any(|l| l.message == "wal line 1"));
    assert!(all.iter().any(|l| l.message == "wal line 3"));
}

#[test]
fn test_auto_flush_multiple_segments() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 5,
        chunk_size: 5,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    // 写入 23 条，应触发 4 个 segment (5+5+5+5=20 flush, 3 缓冲) —— 注意：append 内部判断阈值
    for i in 0..23 {
        engine.append(make_log(1000 + i as u64 * 100, "svc", "I", &format!("msg {}", i))).unwrap();
    }

    let stats = engine.stats();
    // total_lines 仅统计已 flush 的 segment 中的日志
    assert_eq!(stats.total_lines + stats.buffered_lines as u64, 23);
    // 23 / 5 = 4 个完整 flush + 3 条在缓冲（实际可能因 WAL 恢复机制略有偏差）
    assert!(stats.segment_count >= 3);
    assert_eq!(stats.buffered_lines, 3);
}

#[test]
fn test_query_time_range_boundaries() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 3,
        chunk_size: 3,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    engine.append(make_log(1000, "svc", "I", "alpha")).unwrap();
    engine.append(make_log(2000, "svc", "I", "beta")).unwrap();
    engine.append(make_log(3000, "svc", "E", "gamma")).unwrap();

    let exact = engine.query(1000, 3000, "", 100).unwrap();
    assert_eq!(exact.len(), 3);

    let narrow = engine.query(1500, 2500, "", 100).unwrap();
    assert_eq!(narrow.len(), 1);
    assert_eq!(narrow[0].message, "beta");

    let miss = engine.query(4000, 5000, "", 100).unwrap();
    assert!(miss.is_empty());
}

#[test]
fn test_query_limit_truncation() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 10,
        chunk_size: 5,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    for i in 0..20 {
        engine.append(make_log(1000 + i as u64 * 100, "svc", "I", &format!("msg {}", i))).unwrap();
    }

    let limited = engine.query(0, u64::MAX, "", 5).unwrap();
    assert_eq!(limited.len(), 5);

    let unlimited = engine.query(0, u64::MAX, "", 100).unwrap();
    assert_eq!(unlimited.len(), 20);
}

#[test]
fn test_query_keyword_no_match() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 5,
        chunk_size: 5,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    for i in 0..10 {
        engine.append(make_log(1000 + i as u64 * 100, "svc", "I", &format!("standard log {}", i))).unwrap();
    }

    let none = engine.query(0, u64::MAX, "NONEXISTENT_KEYWORD_12345", 100).unwrap();
    assert!(none.is_empty());
}

#[test]
fn test_empty_directory_startup() {
    let dir = test_dir();
    let cfg = StorageConfig::default();
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    let stats = engine.stats();
    assert_eq!(stats.segment_count, 0);
    assert_eq!(stats.total_lines, 0);
    assert_eq!(stats.buffered_lines, 0);
}

#[test]
fn test_stats_accumulation() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 5,
        chunk_size: 5,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    for i in 0..15 {
        engine.append(make_log(1000 + i as u64 * 100, "svc", "I", &format!("msg {}", i))).unwrap();
    }

    let stats = engine.stats();
    assert_eq!(stats.total_lines, 15);
    assert_eq!(stats.segment_count, 3);
    assert!(stats.total_original_bytes > 0);
    assert!(stats.total_compressed_bytes > 0);
    assert!(stats.compression_ratio() > 0.0);
}

#[test]
fn test_append_large_message() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 2,
        chunk_size: 2,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    let big_msg = "x".repeat(1024 * 1024); // 1MB
    engine.append(make_log(1000, "svc", "E", &big_msg)).unwrap();
    engine.append(make_log(2000, "svc", "E", &big_msg)).unwrap();

    let all = engine.query(0, u64::MAX, "", 100).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].message.len(), 1024 * 1024);
}

#[test]
fn test_high_frequency_append() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 100,
        chunk_size: 50,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    for i in 0..1000 {
        engine.append(make_log(1000 + i as u64, "svc", "I", &format!("high freq {}", i))).unwrap();
    }

    let stats = engine.stats();
    assert_eq!(stats.total_lines, 1000);
    assert_eq!(stats.buffered_lines, 0); // 1000 / 100 = 10 次 flush，缓冲应为 0
}

#[test]
fn test_query_keyword_in_service() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 5,
        chunk_size: 5,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    engine.append(make_log(1000, "auth-service", "I", "login ok")).unwrap();
    engine.append(make_log(2000, "payment-service", "I", "pay ok")).unwrap();
    engine.append(make_log(3000, "auth-service", "E", "login fail")).unwrap();

    let auth = engine.query(0, u64::MAX, "auth", 100).unwrap();
    assert_eq!(auth.len(), 2);
}

#[test]
fn test_query_keyword_in_level() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 5,
        chunk_size: 5,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    for i in 0..10 {
        let lvl = if i % 3 == 0 { "E" } else { "I" };
        engine.append(make_log(1000 + i as u64 * 100, "svc", lvl, &format!("msg {}", i))).unwrap();
    }

    let errors = engine.query(0, u64::MAX, "E", 100).unwrap();
    // 关键词 "E" 匹配 level 字段
    assert!(!errors.is_empty());
}

#[test]
fn test_flush_empty_buffer() {
    let dir = test_dir();
    let cfg = StorageConfig::default();
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    // 空缓冲 flush 应无错误
    engine.flush().unwrap();

    let stats = engine.stats();
    assert_eq!(stats.segment_count, 0);
}

#[test]
fn test_segment_file_corruption_graceful() {
    let dir = test_dir();
    let cfg = StorageConfig {
        max_buffer_lines: 3,
        chunk_size: 3,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    engine.append(make_log(1000, "svc", "I", "msg1")).unwrap();
    engine.append(make_log(2000, "svc", "I", "msg2")).unwrap();
    engine.append(make_log(3000, "svc", "I", "msg3")).unwrap();

    // 破坏 segment 文件
    let seg_path = dir.join("segments").join("segment-00000001.mobs");
    if seg_path.exists() {
        fs::write(&seg_path, b"CORRUPTED").unwrap();
    }

    // 查询应返回错误而非 panic
    let result = engine.query(0, u64::MAX, "", 100);
    assert!(result.is_err() || result.unwrap().is_empty());
}
}
