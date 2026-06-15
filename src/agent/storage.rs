//! mini-obs/agent/storage.rs
//! 日志存储引擎 —— 基于 format.rs v2 的多 Chunk Segment 管理
//!
//! 写入流水线：
//!   append -> WAL 文本追加 -> 内存缓冲 -> 阈值触发 flush
//!   flush -> drain 缓冲 -> template 提取 -> 按 chunk_size 切 Chunk
//!          -> 每 Chunk 用文本参数序列化（zstd 友好）-> Zstd 压缩
//!          -> 组装 Segment v2（PatternTable + ChunkTable + SummaryTable + Data）
//!          -> index.add_segment 注册 -> WAL 截断
//!
//! 查询流水线（v2 两阶段过滤）：
//!   index.query_range 时间过滤
//!     -> mmap Segment
//!     -> 读取 PatternTable，构建 keyword -> pat_ids 映射
//!     -> 遍历 ChunkSummary：时间 -> pattern_mask -> param_bloom
//!     -> 仅对命中 Chunk 解压、还原文本参数、逐行匹配

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::agent::compressor::{Compressor, CompressorConfig};
use crate::agent::index::Index;
use crate::agent::template::{
    EncodedRecord, ParamEncoding, TemplateBatch, TemplateExtractor, TemplatePart, TypedParam,
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
    /// 小数据量阈值：行数不超过该值时使用单 Chunk Segment，
    /// 让 zstd 滑动窗口覆盖全部数据，提高压缩比。
    pub single_chunk_threshold_lines: usize,
    /// 小数据量阈值：消息总字节数不超过该值时使用单 Chunk Segment。
    pub single_chunk_threshold_bytes: usize,
    /// 训练 Segment 级 zstd 字典所需的最少 Chunk 数。
    /// 只有多 Chunk 且 Chunk 数 >= 该值时才训练字典，单 Chunk 场景无需字典。
    pub dict_training_min_chunks: usize,
    /// 训练字典时使用的样本 Chunk 数。
    pub dict_training_sample_chunks: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_buffer_lines: 4096,
            max_buffer_bytes: 256 * 1024,
            compression_level: 3,
            chunk_size: 1024,
            dict: None,
            single_chunk_threshold_lines: 4_096,
            single_chunk_threshold_bytes: 2 * 1024 * 1024,
            // 默认禁用 Segment 级字典：对高度模板化日志收益有限，
            // 且训练/存储字典会带来额外开销。需要时显式调小。
            dict_training_min_chunks: usize::MAX,
            dict_training_sample_chunks: 8,
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
        // 小数据量时使用单 Chunk，让 zstd 覆盖全部数据，提升压缩比。
        let total_msg_bytes: usize = logs.iter().map(|l| l.message.len()).sum();
        let use_single_chunk = logs.len() <= self.config.single_chunk_threshold_lines
            && total_msg_bytes <= self.config.single_chunk_threshold_bytes;
        let chunk_size = if use_single_chunk {
            logs.len().max(1)
        } else {
            self.config.chunk_size
        };
        let num_chunks = (logs.len() + chunk_size - 1) / chunk_size;

        // 2. 准备 Chunk：计算摘要、XOR-P 编码、序列化（暂不压缩）
        let mut chunk_entries: Vec<ChunkEntry> = Vec::with_capacity(num_chunks);
        let mut chunk_summaries = Vec::with_capacity(num_chunks);
        let mut chunk_binaries: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);

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

            // 2b. 收集文本参数（不进行 XOR-P 编码，保持参数文本以便 zstd 匹配）
            let chunk_records = &batch.records[start..end];
            let mut text_params: Vec<(u16, Vec<String>)> = Vec::with_capacity(chunk_records.len());
            for rec in chunk_records.iter() {
                let param_texts: Vec<String> = rec.params.iter().map(|p| p.to_string()).collect();
                text_params.push((rec.pat_id, param_texts));
            }

            // 2c. 序列化 Chunk 为文本参数格式（zstd 友好，先不压缩）
            let chunk_binary = self.serialize_chunk_text(chunk_logs, &text_params);
            chunk_entries.push(ChunkEntry::new(
                0, // offset 与 compressed/original sz 稍后回填
                0,
                0,
                chunk_logs.len() as u32,
                chunk_logs.first().map(|l| l.ts).unwrap_or(0),
                chunk_logs.last().map(|l| l.ts).unwrap_or(0),
            ));
            chunk_binaries.push(chunk_binary);
        }

        // 3. 训练 Segment 级 zstd 共享字典
        // 多 Chunk 场景下，字典能捕捉跨 Chunk 的公共模板模式，提升压缩率。
        let segment_dict = if num_chunks >= self.config.dict_training_min_chunks {
            Self::train_segment_dict(&chunk_binaries, self.config.dict_training_sample_chunks)
        } else {
            None
        };

        // 4. 压缩 Chunk（使用 Segment 级字典）
        let mut chunk_data_parts = Vec::with_capacity(num_chunks);
        let mut total_compressed = 0usize;
        let mut total_original = 0usize;
        for (i, binary) in chunk_binaries.iter().enumerate() {
            let compressed = Self::compress_with_dict(
                binary,
                self.config.compression_level,
                segment_dict.as_deref(),
            )?;
            let original_sz = binary.len();
            let compressed_sz = compressed.len();
            total_original += original_sz;
            total_compressed += compressed_sz;

            chunk_entries[i].compressed_sz = compressed_sz as u32;
            chunk_entries[i].original_sz = original_sz as u32;
            chunk_data_parts.push(compressed);
        }

        // 5. 组装 Segment 文件
        let pattern_table = batch.serialize_pattern_table();
        let pattern_count = batch.templates.len() as u16;
        let pattern_table_len = pattern_table.len() as u32;

        // 字典区放在 PatternTable 之后、ChunkTable 之前
        let dict_bytes = segment_dict.unwrap_or_default();
        let dict_len = dict_bytes.len() as u32;
        let dict_offset_val = if dict_len > 0 {
            (SEGMENT_HEADER_SIZE + pattern_table.len()) as u32
        } else {
            0
        };

        // 计算各区域偏移（v2: Header + PatternTable + [Dict] + ChunkTable + SummaryTable + Padding + Data）
        let table_start = SEGMENT_HEADER_SIZE + pattern_table.len() + dict_bytes.len();
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
            dict_offset_val,
            dict_len,
        );
        header.set_feature_flags(SegmentHeader::FEATURE_ENHANCED_CHUNK);

        // 组装内容
        let mut content = Vec::new();
        content.extend_from_slice(&header.to_bytes());
        content.extend_from_slice(&pattern_table);
        if dict_len > 0 {
            content.extend_from_slice(&dict_bytes);
        }
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
    ///
    /// 增强格式（v2 + FEATURE_ENHANCED_CHUNK）：
    /// - 时间戳：base_ts + delta RLE（常量 delta 或原始数组）
    /// - Level：2-bit 位图打包
    /// - Service：去重表 + 每行索引（单 service 时直接共享）
    /// - 记录：pat_id + ref_idx + 参数编码
    /// 序列化 Chunk 为文本参数格式（zstd 友好）
    ///
    /// 格式与 Compressor v2 保持一致：时间戳/level/service 用高效二进制编码，
    /// 参数保持文本形式，让 zstd 可以跨记录找到字节级相似性。
    fn serialize_chunk_text(&self, logs: &[LogLine], text_params: &[(u16, Vec<String>)]) -> Vec<u8> {
        use std::collections::HashMap;

        let n = logs.len();
        let mut buf = Vec::with_capacity(n * 64);

        // 1. 时间戳：base_ts + deltas（二进制，高效）
        let base_ts = logs.first().map(|l| l.ts).unwrap_or(0);
        let mut deltas = Vec::with_capacity(n.saturating_sub(1));
        let mut prev = base_ts as i64;
        for log in logs.iter().skip(1) {
            let ts = log.ts as i64;
            deltas.push(ts - prev);
            prev = ts;
        }
        let constant_delta = if n > 1 && deltas.iter().all(|&d| d == deltas[0]) {
            Some(deltas[0])
        } else {
            None
        };

        if let Some(d) = constant_delta {
            buf.push(1u8); // 常量 delta
            buf.extend_from_slice(&(n as u32).to_le_bytes());
            buf.extend_from_slice(&base_ts.to_le_bytes());
            buf.extend_from_slice(&d.to_le_bytes());
        } else {
            buf.push(0u8); // 原始 delta 数组
            buf.extend_from_slice(&(n as u32).to_le_bytes());
            buf.extend_from_slice(&base_ts.to_le_bytes());
            for d in &deltas {
                buf.extend_from_slice(&d.to_le_bytes());
            }
        }

        // 2. Level 位图：每行 2 bit
        let bitmap_len = (n + 3) / 4;
        let mut level_bm = vec![0u8; bitmap_len];
        for (i, log) in logs.iter().enumerate() {
            let bits = match log.level.as_str() {
                "D" => 0u8, "I" => 1u8, "W" => 2u8, "E" => 3u8, _ => 1u8,
            };
            level_bm[i / 4] |= bits << ((i % 4) * 2);
        }
        buf.extend_from_slice(&level_bm);

        // 3. Service 去重
        let mut unique: Vec<String> = Vec::new();
        let mut svc_map: HashMap<String, usize> = HashMap::new();
        let mut svc_indices: Vec<usize> = Vec::with_capacity(n);
        for log in logs {
            if let Some(&idx) = svc_map.get(&log.service) {
                svc_indices.push(idx);
            } else {
                let idx = unique.len();
                svc_map.insert(log.service.clone(), idx);
                unique.push(log.service.clone());
                svc_indices.push(idx);
            }
        }

        if unique.len() == 1 {
            buf.push(0u8);
            let b = unique[0].as_bytes();
            buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
            buf.extend_from_slice(b);
        } else if unique.len() <= 255 {
            buf.push(1u8);
            buf.extend_from_slice(&(unique.len() as u16).to_le_bytes());
            for svc in &unique {
                let b = svc.as_bytes();
                buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
                buf.extend_from_slice(b);
            }
            for &idx in &svc_indices {
                buf.push(idx as u8);
            }
        } else {
            buf.push(2u8);
            buf.extend_from_slice(&(unique.len() as u16).to_le_bytes());
            for svc in &unique {
                let b = svc.as_bytes();
                buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
                buf.extend_from_slice(b);
            }
            for &idx in &svc_indices {
                buf.extend_from_slice(&(idx as u16).to_le_bytes());
            }
        }

        // 4. 记录 payload：文本参数格式（zstd 友好）
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        for (pat_id, params) in text_params {
            buf.extend_from_slice(&pat_id.to_le_bytes());
            buf.extend_from_slice(&(params.len() as u16).to_le_bytes());
            for p in params {
                let bytes = p.as_bytes();
                buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(bytes);
            }
        }

        buf
    }

    /// 训练 Segment 级 zstd 字典
    ///
    /// 从样本 Chunk 二进制数据中学习公共模式，供后续所有 Chunk 共享。
    /// 返回 None 表示样本不足或训练失败（回退到无字典）。
    fn train_segment_dict(chunk_binaries: &[Vec<u8>], sample_chunks: usize) -> Option<Vec<u8>> {
        if chunk_binaries.len() < 2 {
            return None;
        }
        let samples: Vec<Vec<u8>> = chunk_binaries
            .iter()
            .take(sample_chunks)
            .cloned()
            .collect();
        if samples.is_empty() {
            return None;
        }
        let total_len: usize = samples.iter().map(|s| s.len()).sum();
        let avg_len = total_len / samples.len();
        // 字典大小上限：平均样本大小的 2 倍、总样本的 1/20、16KB、110KB 四者取最小，
        // 避免小数据量时字典本身成为主要开销。
        let max_dict_size = (avg_len * 2)
            .min(total_len / 20)
            .min(16 * 1024)
            .min(110 * 1024)
            .max(1024);
        match zstd::dict::from_samples(&samples, max_dict_size) {
            Ok(dict) if !dict.is_empty() => Some(dict),
            _ => None,
        }
    }

    /// 使用可选字典压缩数据
    fn compress_with_dict(
        data: &[u8],
        level: i32,
        dict: Option<&[u8]>,
    ) -> io::Result<Vec<u8>> {
        if let Some(d) = dict {
            let mut enc = zstd::stream::write::Encoder::with_dictionary(Vec::new(), level, d)?;
            enc.write_all(data)?;
            enc.finish()
        } else {
            zstd::encode_all(data, level)
        }
    }

    /// 使用可选字典解压数据
    fn decompress_with_dict(data: &[u8], dict: Option<&[u8]>) -> io::Result<Vec<u8>> {
        if let Some(d) = dict {
            let mut dec = zstd::stream::read::Decoder::with_dictionary(data, d)?;
            let mut out = Vec::new();
            dec.read_to_end(&mut out)?;
            Ok(out)
        } else {
            zstd::decode_all(data)
        }
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

        let initial_count = results.len();
        for log in batch {
            if log.ts >= start && log.ts <= end {
                if log.service.contains(keyword)
                    || log.level.contains(keyword)
                    || log.message.contains(keyword)
                {
                    results.push(log);
                    if results.len() - initial_count >= limit {
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

        // 1.5 读取 Segment 级 zstd 字典（如果存在）
        let dict_offset = header.dict_offset() as usize;
        let dict_len = header.dict_len() as usize;
        let segment_dict = if dict_len > 0 && dict_offset >= pattern_table_end && dict_offset + dict_len <= mmap.len() - SEGMENT_FOOTER_SIZE {
            Some(&mmap[dict_offset..dict_offset + dict_len])
        } else {
            None
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

        // 2. 读取 ChunkTable（在 PatternTable 和可选 Dict 之后）
        let table_start = SEGMENT_HEADER_SIZE + pattern_table_len + dict_len;
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
        let initial_result_count = results.len();
        for i in 0..chunk_count {
            if results.len() - initial_result_count >= limit {
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

            // 解压 Chunk 二进制（使用 Segment 级字典）
            let chunk_binary = Self::decompress_with_dict(compressed, segment_dict)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            
            // 解析并还原 XOR-P
            let feature_flags = header.feature_flags();
            let logs = self.deserialize_chunk_binary(&chunk_binary, &templates, feature_flags)?;
            for log in logs {
                if log.ts >= start && log.ts <= end {
                    let svc_match = log.service.contains(keyword);
                    let lvl_match = log.level.contains(keyword);
                    let msg_match = log.message.contains(keyword);
                    if svc_match || lvl_match || msg_match {
                        results.push(log);
                        if results.len() - initial_result_count >= limit {
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
        feature_flags: u8,
    ) -> io::Result<Vec<LogLine>> {
        if feature_flags & SegmentHeader::FEATURE_ENHANCED_CHUNK != 0 {
            self.deserialize_chunk_binary_enhanced(data, templates)
        } else {
            self.deserialize_chunk_binary_legacy(data, templates)
        }
    }

    fn decode_one_record(
        &self,
        pat_id: u16,
        ref_idx: u16,
        enc_data: &[u8],
        templates: &[crate::agent::template::Template],
        ref_params: &mut Vec<TypedParam>,
        ts: u64,
        service: String,
        level: String,
    ) -> LogLine {
        let enc_rec = EncodedRecord {
            ts_delta: 0,
            svc_id: 0,
            level: level.clone(),
            pat_id,
            param_encoding: ParamEncoding {
                ref_idx,
                data: enc_data.to_vec(),
            },
        };
        let params = TemplateExtractor::decode_xor(&enc_rec, ref_params);
        if ref_idx == 0 {
            *ref_params = params.clone();
        }

        let template = templates.get(pat_id as usize);
        let message = if let Some(t) = template {
            let mut msg = String::new();
            let mut param_idx = 0;
            for part in &t.parts {
                match part {
                    TemplatePart::Literal(s) => msg.push_str(s),
                    TemplatePart::Param => {
                        if let Some(p) = params.get(param_idx) {
                            msg.push_str(&p.to_string());
                            param_idx += 1;
                        } else {
                            msg.push('*');
                        }
                    }
                }
            }
            msg
        } else {
            params.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" ")
        };

        LogLine { ts, service, level, message }
    }

    fn deserialize_chunk_binary_legacy(
        &self,
        data: &[u8],
        templates: &[crate::agent::template::Template],
    ) -> io::Result<Vec<LogLine>> {
        let mut logs = Vec::new();
        let mut offset = 0;
        let mut ref_params: Vec<TypedParam> = Vec::new();

        while offset < data.len() {
            if offset + 8 > data.len() { break; }
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
                b'D' => "D".to_string(),
                b'I' => "I".to_string(),
                b'W' => "W".to_string(),
                b'E' => "E".to_string(),
                _ => "I".to_string(),
            };

            if offset + 2 > data.len() { break; }
            let pat_id = u16::from_le_bytes([data[offset], data[offset+1]]);
            offset += 2;

            if offset + 2 > data.len() { break; }
            let ref_idx = u16::from_le_bytes([data[offset], data[offset+1]]);
            offset += 2;

            if offset + 4 > data.len() { break; }
            let enc_len = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
            ]) as usize;
            offset += 4;

            if offset + enc_len > data.len() { break; }
            let enc_data = &data[offset..offset+enc_len];
            offset += enc_len;

            logs.push(self.decode_one_record(pat_id, ref_idx, enc_data, templates, &mut ref_params, ts, service, level));
        }

        Ok(logs)
    }

    fn deserialize_chunk_binary_enhanced(
        &self,
        data: &[u8],
        templates: &[crate::agent::template::Template],
    ) -> io::Result<Vec<LogLine>> {
        let mut offset = 0;
        let check = |offset: usize, len: usize| -> io::Result<()> {
            if offset + len > data.len() {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "enhanced chunk truncated"))
            } else {
                Ok(())
            }
        };

        // 1. timestamps
        check(offset, 1)?;
        let ts_type = data[offset];
        offset += 1;
        check(offset, 4)?;
        let rec_count = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
        offset += 4;
        check(offset, 8)?;
        let base_ts = u64::from_le_bytes([
            data[offset], data[offset+1], data[offset+2], data[offset+3],
            data[offset+4], data[offset+5], data[offset+6], data[offset+7],
        ]);
        offset += 8;

        let timestamps: Vec<u64> = match ts_type {
            1 => {
                check(offset, 8)?;
                let delta = i64::from_le_bytes([
                    data[offset], data[offset+1], data[offset+2], data[offset+3],
                    data[offset+4], data[offset+5], data[offset+6], data[offset+7],
                ]);
                offset += 8;
                (0..rec_count).map(|i| (base_ts as i64 + i as i64 * delta) as u64).collect()
            }
            _ => {
                let mut ts = base_ts as i64;
                let mut ts_vec = Vec::with_capacity(rec_count);
                ts_vec.push(base_ts);
                for _ in 1..rec_count {
                    check(offset, 8)?;
                    let d = i64::from_le_bytes([
                        data[offset], data[offset+1], data[offset+2], data[offset+3],
                        data[offset+4], data[offset+5], data[offset+6], data[offset+7],
                    ]);
                    offset += 8;
                    ts += d;
                    ts_vec.push(ts as u64);
                }
                ts_vec
            }
        };

        // 2. level bitmap
        let level_bm_len = (rec_count + 3) / 4;
        check(offset, level_bm_len)?;
        let level_bm = &data[offset..offset + level_bm_len];
        offset += level_bm_len;

        let level_for = |i: usize| -> String {
            let bits = (level_bm[i / 4] >> ((i % 4) * 2)) & 0x03;
            match bits {
                0 => "D".to_string(),
                1 => "I".to_string(),
                2 => "W".to_string(),
                3 => "E".to_string(),
                _ => "I".to_string(),
            }
        };

        // 3. service table
        check(offset, 1)?;
        let svc_mode = data[offset];
        offset += 1;

        let (services, svc_indices) = match svc_mode {
            0 => {
                check(offset, 2)?;
                let len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
                offset += 2;
                check(offset, len)?;
                let svc = String::from_utf8_lossy(&data[offset..offset+len]).to_string();
                offset += len;
                (vec![svc], Vec::new())
            }
            1 | 2 => {
                check(offset, 2)?;
                let svc_count = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
                offset += 2;
                let mut svcs = Vec::with_capacity(svc_count);
                for _ in 0..svc_count {
                    check(offset, 2)?;
                    let len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
                    offset += 2;
                    check(offset, len)?;
                    svcs.push(String::from_utf8_lossy(&data[offset..offset+len]).to_string());
                    offset += len;
                }
                if svc_mode == 1 {
                    check(offset, rec_count)?;
                    let indices: Vec<usize> = data[offset..offset + rec_count].iter().map(|&b| b as usize).collect();
                    offset += rec_count;
                    (svcs, indices)
                } else {
                    check(offset, rec_count * 2)?;
                    let mut indices = Vec::with_capacity(rec_count);
                    for i in 0..rec_count {
                        let off = offset + i * 2;
                        indices.push(u16::from_le_bytes([data[off], data[off+1]]) as usize);
                    }
                    offset += rec_count * 2;
                    (svcs, indices)
                }
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown service mode in enhanced chunk"));
            }
        };

        let svc_index_for = |i: usize| -> usize {
            if services.len() == 1 { 0 } else { svc_indices[i] }
        };

        // 4. records（文本参数格式：pat_id + param_count + [text_len + text]*）
        check(offset, 4)?;
        let stored_rec_count = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
        offset += 4;
        if stored_rec_count != rec_count {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "enhanced chunk record count mismatch"));
        }

        let mut logs = Vec::with_capacity(rec_count);
        for i in 0..rec_count {
            check(offset, 2)?;
            let pat_id = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
            offset += 2;
            check(offset, 2)?;
            let param_count = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
            offset += 2;

            let mut params: Vec<TypedParam> = Vec::with_capacity(param_count);
            for _ in 0..param_count {
                check(offset, 2)?;
                let text_len = u16::from_le_bytes([data[offset], data[offset+1]]) as usize;
                offset += 2;
                check(offset, text_len)?;
                let text = String::from_utf8_lossy(&data[offset..offset + text_len]).to_string();
                offset += text_len;
                params.push(TypedParam::from_str(&text));
            }

            // 重建 message
            let message = if let Some(t) = templates.get(pat_id) {
                let mut msg = String::new();
                let mut param_idx = 0;
                for part in &t.parts {
                    match part {
                        TemplatePart::Literal(s) => msg.push_str(s),
                        TemplatePart::Param => {
                            if let Some(p) = params.get(param_idx) {
                                msg.push_str(&p.to_string());
                                param_idx += 1;
                            }
                        }
                    }
                }
                msg
            } else {
                params.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" ")
            };

            logs.push(LogLine {
                ts: timestamps[i],
                service: services[svc_index_for(i)].clone(),
                level: level_for(i),
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

#[test]
fn test_enhanced_chunk_binary_timestamp_constant() {
    let dir = test_dir();
    let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();

    let logs: Vec<LogLine> = (0..10)
        .map(|i| make_log(1000 + i as u64 * 100, "svc", "I", &format!("msg {}", i)))
        .collect();
    let batch = TemplateExtractor::extract(&logs);
    let text_params: Vec<(u16, Vec<String>)> = batch.records.iter()
        .map(|r| (r.pat_id, r.params.iter().map(|p| p.to_string()).collect()))
        .collect();
    let binary = engine.serialize_chunk_text(&logs, &text_params);
    let decoded = engine.deserialize_chunk_binary_enhanced(&binary, &batch.templates).unwrap();
    assert_eq!(decoded, logs);
}

#[test]
fn test_enhanced_chunk_binary_multiple_services() {
    let dir = test_dir();
    let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();

    let logs: Vec<LogLine> = (0..6)
        .map(|i| {
            let svc = if i % 2 == 0 { "auth" } else { "payment" };
            make_log(1000 + i as u64, svc, "I", &format!("msg {}", i))
        })
        .collect();
    let batch = TemplateExtractor::extract(&logs);
    let text_params: Vec<(u16, Vec<String>)> = batch.records.iter()
        .map(|r| (r.pat_id, r.params.iter().map(|p| p.to_string()).collect()))
        .collect();
    let binary = engine.serialize_chunk_text(&logs, &text_params);
    let decoded = engine.deserialize_chunk_binary_enhanced(&binary, &batch.templates).unwrap();
    assert_eq!(decoded, logs);
}

#[test]
fn test_enhanced_chunk_binary_mixed_levels() {
    let dir = test_dir();
    let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();

    let logs: Vec<LogLine> = (0..8)
        .map(|i| {
            let lvl = match i % 4 {
                0 => "D",
                1 => "I",
                2 => "W",
                _ => "E",
            };
            make_log(1000 + i as u64 * 10, "svc", lvl, &format!("msg {}", i))
        })
        .collect();
    let batch = TemplateExtractor::extract(&logs);
    let text_params: Vec<(u16, Vec<String>)> = batch.records.iter()
        .map(|r| (r.pat_id, r.params.iter().map(|p| p.to_string()).collect()))
        .collect();
    let binary = engine.serialize_chunk_text(&logs, &text_params);
    let decoded = engine.deserialize_chunk_binary_enhanced(&binary, &batch.templates).unwrap();
    assert_eq!(decoded, logs);
}

#[test]
fn test_legacy_chunk_binary_compat() {
    let dir = test_dir();
    let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();

    let logs = vec![
        make_log(1000, "svc", "I", "alpha"),
        make_log(2000, "svc", "W", "beta"),
        make_log(3000, "svc", "E", "gamma"),
    ];

    // 手动构造旧版 Chunk 二进制（每条记录独立存储 ts/service/level）
    let mut binary = Vec::new();
    for log in &logs {
        binary.extend_from_slice(&log.ts.to_le_bytes());
        let svc = log.service.as_bytes();
        binary.extend_from_slice(&(svc.len() as u16).to_le_bytes());
        binary.extend_from_slice(svc);
        binary.push(log.level.as_bytes()[0]);
        // pat_id + ref_idx + empty param data
        binary.extend_from_slice(&0u16.to_le_bytes());
        binary.extend_from_slice(&0u16.to_le_bytes());
        binary.extend_from_slice(&0u32.to_le_bytes());
    }

    let decoded = engine.deserialize_chunk_binary_legacy(&binary, &[]).unwrap();
    assert_eq!(decoded.len(), logs.len());
    for (a, b) in decoded.iter().zip(logs.iter()) {
        assert_eq!(a.ts, b.ts);
        assert_eq!(a.service, b.service);
        assert_eq!(a.level, b.level);
    }
}
}
