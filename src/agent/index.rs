//! mini-obs/agent/index.rs
//! 轻量级日志索引引擎 —— 内存常驻 + 磁盘 Manifest + Segment 级摘要
//!
//! 新增能力（LittleLog 启发）：
//! - SegmentSummary：从 ChunkSummaryTable 重建，常驻内存
//! - keyword_to_patterns：全局模板字典，启动时从 Segment 文件重建
//! - may_exist：真阴性保证的存在性查询
//! - count_at_least：激进下界的近似计数

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::agent::template::{TemplateBatch, TemplatePart};
use crate::shared::format::{
    parse_segment_name, segment_name, ChunkEntry, ChunkSummary, ManifestEntry, SegmentHeader,
    SegmentSummary, CHUNK_ENTRY_SIZE, CHUNK_SUMMARY_SIZE, FORMAT_VERSION_V2, MIDX_MAGIC,
    SEGMENT_FOOTER_SIZE, SEGMENT_HEADER_SIZE,
};

/// 索引统计信息
#[derive(Debug, Clone, Copy, Default)]
pub struct IndexStats {
    pub segment_count: usize,
    pub total_lines: u64,
    pub min_ts: Option<u64>,
    pub max_ts: Option<u64>,
}

/// 轻量级日志索引
///
/// 内存结构：
/// - segments: Vec<SegmentMeta>（按 segment_id 升序）
/// - keyword_to_patterns: HashMap<String, Vec<u16>>（全局模板关键词索引）
pub struct Index {
    data_dir: PathBuf,
    segments: RwLock<Vec<SegmentMeta>>,
    next_id: RwLock<u32>,
    /// 全局关键词 → 模板 ID 映射（从所有 Segment 的 PatternTable 重建）
    keyword_to_patterns: RwLock<HashMap<String, Vec<u16>>>,
}

/// 内部 Segment 元数据（扩展 ManifestEntry + 内存缓存）
#[derive(Debug, Clone)]
struct SegmentMeta {
    id: u32,
    min_ts: u64,
    max_ts: u64,
    line_count: u32,
    path: PathBuf,
    summary: SegmentSummary,
}

impl Index {
    // ==================== 生命周期 ====================

    pub fn open(data_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(data_dir.join("index"))?;
        fs::create_dir_all(data_dir.join("segments"))?;

        let mut segments: Vec<SegmentMeta> = Vec::new();
        let mut next_id: u32 = 1;
        let mut keyword_map: HashMap<String, Vec<u16>> = HashMap::new();

        let manifest_path = data_dir.join("index").join("manifest.midx");
        if manifest_path.exists() {
            match Self::load_manifest(&manifest_path, &mut segments, &mut next_id) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("[index] Manifest load failed ({}), rebuilding from segments...", e);
                    segments.clear();
                    next_id = 1;
                    segments = Self::scan_all_segments(data_dir, &mut segments, &mut next_id, &mut keyword_map)?;
                }
            }
        } else {
            segments = Self::scan_all_segments(data_dir, &mut segments, &mut next_id, &mut keyword_map)?;
        }

        // 若 manifest 加载成功但 keyword_map 为空（旧版 manifest 无模板信息），重建
        if keyword_map.is_empty() && !segments.is_empty() {
            Self::rebuild_keyword_map(data_dir, &segments, &mut keyword_map)?;
        }

        let idx = Self {
            data_dir: data_dir.to_path_buf(),
            segments: RwLock::new(segments),
            next_id: RwLock::new(next_id),
            keyword_to_patterns: RwLock::new(keyword_map),
        };

        if !idx.segments.read().unwrap().is_empty() && !manifest_path.exists() {
            idx.save()?;
        }

        Ok(idx)
    }

    // ==================== 公共 API：写入 ====================

    /// 注册新 Segment（旧版兼容，无摘要）
    pub fn add_segment(&self, id: u32, min_ts: u64, max_ts: u64, line_count: u32) -> io::Result<()> {
        self.add_segment_with_summary(id, min_ts, max_ts, line_count, SegmentSummary::default())
    }

    /// 注册新 Segment（带摘要）
    pub fn add_segment_with_summary(
        &self,
        id: u32,
        min_ts: u64,
        max_ts: u64,
        line_count: u32,
        summary: SegmentSummary,
    ) -> io::Result<()> {
        let path = self.data_dir.join("segments").join(segment_name(id));
        let _entry = ManifestEntry::new(id, min_ts, max_ts, line_count, &path.to_string_lossy())
            .with_summary(&summary);

        {
            let mut segments = self.segments.write().unwrap();
            segments.push(SegmentMeta {
                id,
                min_ts,
                max_ts,
                line_count,
                path: path.clone(),
                summary,
            });
            segments.sort_by_key(|s| s.id);
        }

        // 更新全局关键词映射（如果摘要有效）
        if summary.has_summary() {
            self.update_keyword_map_from_segment(&path)?;
        }

        self.save()?;
        Ok(())
    }

    // ==================== 公共 API：查询 ====================

    /// 时间范围查询：返回与 [start, end] 重叠的所有 Segment（按 max_ts 降序）
    pub fn query_range(&self, start: u64, end: u64) -> Vec<SegmentMetaView> {
        let segments = self.segments.read().unwrap();
        let mut result: Vec<SegmentMetaView> = segments
            .iter()
            .filter(|s| s.max_ts >= start && s.min_ts <= end)
            .map(|s| SegmentMetaView {
                segment_id: s.id,
                min_ts: s.min_ts,
                max_ts: s.max_ts,
                line_count: s.line_count,
                summary: s.summary,
            })
            .collect();
        result.sort_by_key(|s| std::cmp::Reverse(s.max_ts));
        result
    }

    /// 精确查询 Segment ID
    pub fn query_by_id(&self, id: u32) -> Option<SegmentMetaView> {
        let segments = self.segments.read().unwrap();
        segments
            .binary_search_by_key(&id, |s| s.id)
            .ok()
            .map(|idx| SegmentMetaView {
                segment_id: segments[idx].id,
                min_ts: segments[idx].min_ts,
                max_ts: segments[idx].max_ts,
                line_count: segments[idx].line_count,
                summary: segments[idx].summary,
            })
    }

    // ==================== 公共 API：免解压统计（LittleLog 启发）====================

    /// 判断某关键词在时间段内是否**可能存在**
    ///
    /// 返回 false → 确定不存在（100% 可靠，真阴性）
    /// 返回 true → 可能存在（需进一步查询 storage 确认）
    pub fn may_exist(&self, start: u64, end: u64, keyword: &str) -> bool {
        let entries = self.query_range(start, end);
        let keyword_upper = keyword.to_uppercase();

        for entry in entries {
            if !entry.summary.has_summary() {
                // 旧版 Segment 无摘要，保守返回 true
                return true;
            }

            // 层 1：级别精确匹配
            let level_bit = match keyword_upper.as_str() {
                "DEBUG" | "D" => Some(0),
                "INFO" | "I" => Some(1),
                "WARN" | "W" | "WARNING" => Some(2),
                "ERROR" | "E" | "ERR" => Some(3),
                _ => None,
            };
            if let Some(bit) = level_bit {
                if (entry.summary.level_mask >> bit) & 1 != 0 {
                    return true;
                }
            }

            // 层 2：模板固定文本匹配
            if self.keyword_hits_pattern_mask(keyword, entry.summary.pattern_mask) {
                return true;
            }

            // 层 3：Bloom 粗过滤
            if entry.summary.bloom_may_contain_param(keyword) {
                return true;
            }
        }

        false
    }

    /// 估计时间范围内**至少**有多少条匹配日志（下界，不误报）
    ///
    /// 保证：返回值 ≤ 真实匹配数量
    /// 激进策略：
    /// - 若 Segment 只有 1 个模板且匹配，贡献 line_count
    /// - 否则贡献匹配模板数量（每个匹配模板至少 1 条）
    pub fn count_at_least(&self, start: u64, end: u64, keyword: &str) -> u64 {
        let entries = self.query_range(start, end);
        let keyword_upper = keyword.to_uppercase();
        let keyword_pats = self.keyword_to_patterns.read().unwrap();
        let mut lower = 0u64;

        for entry in entries {
            if !entry.summary.has_summary() {
                continue; // 旧版 Segment，保守跳过
            }

            let mut definitely_has = false;
            let mut matched_pats = 0u32;

            // 条件 1：级别精确匹配
            let level_bit = match keyword_upper.as_str() {
                "DEBUG" | "D" => Some(0),
                "INFO" | "I" => Some(1),
                "WARN" | "W" | "WARNING" => Some(2),
                "ERROR" | "E" | "ERR" => Some(3),
                _ => None,
            };
            if let Some(bit) = level_bit {
                if (entry.summary.level_mask >> bit) & 1 != 0 {
                    definitely_has = true;
                }
            }

            // 条件 2：模板固定文本匹配
            if let Some(pats) = keyword_pats.get(keyword) {
                for &pat_id in pats {
                    if pat_id < 64 && (entry.summary.pattern_mask >> pat_id) & 1 != 0 {
                        matched_pats += 1;
                        definitely_has = true;
                    }
                }
            }

            if definitely_has {
                let total_pats = entry.summary.pattern_mask.count_ones();
                if total_pats == 1 && matched_pats == 1 {
                    lower += entry.line_count as u64;
                } else if matched_pats > 0 {
                    lower += matched_pats as u64;
                } else {
                    lower += 1; // level 匹配但无模板匹配，保守贡献 1
                }
            }
        }

        lower
    }

    // ==================== 公共 API：统计 ====================

    pub fn stats(&self) -> IndexStats {
        let segments = self.segments.read().unwrap();
        let total_lines = segments.iter().map(|s| s.line_count as u64).sum();

        let (min_ts, max_ts) = segments.iter().fold((None, None), |(min, max), s| {
            (
                Some(min.map_or(s.min_ts, |m: u64| m.min(s.min_ts))),
                Some(max.map_or(s.max_ts, |m: u64| m.max(s.max_ts))),
            )
        });

        IndexStats {
            segment_count: segments.len(),
            total_lines,
            min_ts,
            max_ts,
        }
    }

    pub fn next_segment_id(&self) -> u32 {
        let mut nid = self.next_id.write().unwrap();
        let id = *nid;
        *nid += 1;
        id
    }

    pub fn rebuild(&self) -> io::Result<()> {
        {
            let mut segments = self.segments.write().unwrap();
            let mut next_id = self.next_id.write().unwrap();
            let mut keyword_map = self.keyword_to_patterns.write().unwrap();

            let new_segments = Self::scan_all_segments(&self.data_dir, &mut segments, &mut next_id, &mut keyword_map)?;
            *segments = new_segments;
            *next_id = segments.last().map(|s| s.id + 1).unwrap_or(1);
        }

        self.save()?;
        Ok(())
    }

    // ==================== 私有方法 ====================

    fn keyword_hits_pattern_mask(&self, keyword: &str, pattern_mask: u64) -> bool {
        let keyword_pats = self.keyword_to_patterns.read().unwrap();
        if let Some(pats) = keyword_pats.get(keyword) {
            for &pat_id in pats {
                if pat_id < 64 && (pattern_mask >> pat_id) & 1 != 0 {
                    return true;
                }
            }
        }
        false
    }

    fn update_keyword_map_from_segment(&self, path: &Path) -> io::Result<()> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        if mmap.len() < SEGMENT_HEADER_SIZE {
            return Ok(());
        }

        let header = match SegmentHeader::from_bytes(&mmap[0..SEGMENT_HEADER_SIZE]) {
            Ok(h) => h,
            Err(_) => return Ok(()),
        };

        if header.version != FORMAT_VERSION_V2 || header.pattern_count() == 0 {
            return Ok(());
        }

        let pattern_table_len = header.pattern_table_len() as usize;
        if pattern_table_len == 0 {
            return Ok(());
        }

        let pt_data = &mmap[SEGMENT_HEADER_SIZE..SEGMENT_HEADER_SIZE + pattern_table_len];
        if let Ok(templates) = TemplateBatch::deserialize_pattern_table(pt_data) {
            let mut keyword_map = self.keyword_to_patterns.write().unwrap();
            for t in &templates {
                for part in &t.parts {
                    if let TemplatePart::Literal(s) = part {
                        // 对 Literal 分词，建立关键词 → pat_id 映射
                        for word in s.split_whitespace() {
                            let word = word.to_lowercase();
                            if word.len() < 3 {
                                continue; // 忽略短词，减少噪声
                            }
                            keyword_map
                                .entry(word)
                                .or_default()
                                .push(t.id);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn rebuild_keyword_map(
        data_dir: &Path,
        segments: &[SegmentMeta],
        keyword_map: &mut HashMap<String, Vec<u16>>,
    ) -> io::Result<()> {
        for seg in segments {
            if !seg.summary.has_summary() {
                continue;
            }
            let path = data_dir.join("segments").join(segment_name(seg.id));
            let _ = Self::scan_segment_keywords(&path, keyword_map);
        }
        Ok(())
    }

    fn scan_segment_keywords(
        path: &Path,
        keyword_map: &mut HashMap<String, Vec<u16>>,
    ) -> io::Result<()> {
        let file = File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        if mmap.len() < SEGMENT_HEADER_SIZE {
            return Ok(());
        }

        let header = match SegmentHeader::from_bytes(&mmap[0..SEGMENT_HEADER_SIZE]) {
            Ok(h) => h,
            Err(_) => return Ok(()),
        };

        if header.version != FORMAT_VERSION_V2 || header.pattern_count() == 0 {
            return Ok(());
        }

        let pattern_table_len = header.pattern_table_len() as usize;
        let pt_data = &mmap[SEGMENT_HEADER_SIZE..SEGMENT_HEADER_SIZE + pattern_table_len];
        if let Ok(templates) = TemplateBatch::deserialize_pattern_table(pt_data) {
            for t in &templates {
                for part in &t.parts {
                    if let TemplatePart::Literal(s) = part {
                        for word in s.split_whitespace() {
                            let word = word.to_lowercase();
                            if word.len() < 3 {
                                continue;
                            }
                            keyword_map
                                .entry(word)
                                .or_default()
                                .push(t.id);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn load_manifest(
        path: &Path,
        segments: &mut Vec<SegmentMeta>,
        next_id: &mut u32,
    ) -> io::Result<()> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != MIDX_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad manifest magic"));
        }
        let mut version = [0u8; 1];
        file.read_exact(&mut version)?;
        let mut encoded = Vec::new();
        file.read_to_end(&mut encoded)?;

        let disk: Vec<ManifestEntry> = bincode::deserialize(&encoded)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        for d in disk {
            segments.push(SegmentMeta {
                id: d.segment_id,
                min_ts: d.min_ts,
                max_ts: d.max_ts,
                line_count: d.line_count,
                path: PathBuf::from(format!(
                    "segments/segment-{:08}.mobs",
                    d.segment_id
                )),
                summary: d.segment_summary(),
            });
            if d.segment_id >= *next_id {
                *next_id = d.segment_id + 1;
            }
        }

        Ok(())
    }

    fn save(&self) -> io::Result<()> {
        let path = self.data_dir.join("index").join("manifest.midx");
        let segments = self.segments.read().unwrap();

        let disk: Vec<ManifestEntry> = segments
            .iter()
            .map(|s| {
                ManifestEntry::new(s.id, s.min_ts, s.max_ts, s.line_count, &s.path.to_string_lossy())
                    .with_summary(&s.summary)
            })
            .collect();

        let encoded = bincode::serialize(&disk)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut tmp = File::create(path.with_extension("tmp"))?;
        tmp.write_all(MIDX_MAGIC)?;
        tmp.write_all(&[1u8])?;
        tmp.write_all(&encoded)?;
        tmp.sync_all()?;
        fs::rename(path.with_extension("tmp"), path)?;
        Ok(())
    }

    fn scan_all_segments(
        data_dir: &Path,
        _segments: &mut Vec<SegmentMeta>,
        next_id: &mut u32,
        keyword_map: &mut HashMap<String, Vec<u16>>,
    ) -> io::Result<Vec<SegmentMeta>> {
        let seg_dir = data_dir.join("segments");
        let mut result = Vec::new();

        if !seg_dir.exists() {
            return Ok(result);
        }

        for entry in fs::read_dir(&seg_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let _id = match parse_segment_name(&name) {
                Some(v) => v,
                None => continue,
            };

            let path = entry.path();
            match Self::scan_segment_meta(&path, keyword_map) {
                Ok((fid, min_ts, max_ts, lines, summary)) => {
                    result.push(SegmentMeta {
                        id: fid,
                        min_ts,
                        max_ts,
                        line_count: lines,
                        path,
                        summary,
                    });
                    if fid >= *next_id {
                        *next_id = fid + 1;
                    }
                }
                Err(e) => {
                    eprintln!("[index] Skip corrupted segment {}: {}", name, e);
                }
            }
        }

        result.sort_by_key(|s| s.id);
        Ok(result)
    }

    fn scan_segment_meta(
        path: &Path,
        keyword_map: &mut HashMap<String, Vec<u16>>,
    ) -> io::Result<(u32, u64, u64, u32, SegmentSummary)> {
        let file = File::open(path)?;
        let mmap = unsafe { memmap2::Mmap::map(&file)? };

        if mmap.len() < SEGMENT_HEADER_SIZE + CHUNK_ENTRY_SIZE + SEGMENT_FOOTER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment file too short",
            ));
        }

        let header = SegmentHeader::from_bytes(&mmap[0..SEGMENT_HEADER_SIZE])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let table_start = SEGMENT_HEADER_SIZE + header.pattern_table_len() as usize;
        let chunk = ChunkEntry::from_bytes(&mmap[table_start..table_start + CHUNK_ENTRY_SIZE])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut summary = SegmentSummary::default();

        // v2：从 ChunkSummaryTable 重建摘要
        if header.version == FORMAT_VERSION_V2 && header.chunk_count > 0 {
            let summary_offset = header.summary_offset() as usize;

            for i in 0..header.chunk_count {
                let off = summary_offset + (i as usize) * CHUNK_SUMMARY_SIZE;
                if off + CHUNK_SUMMARY_SIZE > mmap.len() - SEGMENT_FOOTER_SIZE {
                    break;
                }
                if let Ok(cs) = ChunkSummary::from_bytes(&mmap[off..off + CHUNK_SUMMARY_SIZE]) {
                    summary.pattern_mask |= cs.pattern_mask;
                    summary.level_mask |= cs.level_mask;
                    // 压缩 bloom：64-byte chunk bloom → 12-byte segment bloom
                    for j in 0..64 {
                        summary.param_bloom[j % 12] |= cs.param_bloom[j];
                    }
                }
            }

            summary.flags = SegmentSummary::HAS_SUMMARY;

            // 重建关键词映射
            let pattern_table_len = header.pattern_table_len() as usize;
            if pattern_table_len > 0 {
                let pt_end = SEGMENT_HEADER_SIZE + pattern_table_len;
                if pt_end <= mmap.len() {
                    let pt_data = &mmap[SEGMENT_HEADER_SIZE..pt_end];
                    if let Ok(templates) = TemplateBatch::deserialize_pattern_table(pt_data) {
                        for t in &templates {
                            for part in &t.parts {
                                if let TemplatePart::Literal(s) = part {
                                    for word in s.split_whitespace() {
                                        let word = word.to_lowercase();
                                        if word.len() < 3 {
                                            continue;
                                        }
                                        keyword_map
                                            .entry(word)
                                            .or_default()
                                            .push(t.id);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut total_lines = chunk.line_count;
        for i in 1..header.chunk_count {
            let off = table_start + (i as usize) * CHUNK_ENTRY_SIZE;
            if off + CHUNK_ENTRY_SIZE <= mmap.len() - SEGMENT_FOOTER_SIZE {
                if let Ok(c) = ChunkEntry::from_bytes(&mmap[off..off + CHUNK_ENTRY_SIZE]) {
                    total_lines += c.line_count;
                }
            }
        }

        Ok((header.segment_id, chunk.min_ts, chunk.max_ts, total_lines, summary))
    }
}

/// Segment 元数据的只读视图（避免暴露内部路径）
#[derive(Debug, Clone, Copy)]
pub struct SegmentMetaView {
    pub segment_id: u32,
    pub min_ts: u64,
    pub max_ts: u64,
    pub line_count: u32,
    pub summary: SegmentSummary,
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::temp_dir;

    #[test]
    fn test_may_exist_level_exact() {
        let dir = temp_dir("index-may-exist");
        fs::create_dir_all(dir.join("segments")).unwrap();
        fs::create_dir_all(dir.join("index")).unwrap();

        // 构造一个含摘要的 Segment
        let mut summary = SegmentSummary::default();
        summary.level_mask = 0b0100; // 含 W
        summary.flags = SegmentSummary::HAS_SUMMARY;

        let idx = Index::open(&dir).unwrap();
        idx.add_segment_with_summary(1, 1000, 2000, 100, summary).unwrap();

        assert!(idx.may_exist(0, u64::MAX, "WARN"));
        assert!(idx.may_exist(0, u64::MAX, "W"));
        assert!(!idx.may_exist(0, u64::MAX, "ERROR")); // 确定不存在
        assert!(!idx.may_exist(0, u64::MAX, "E"));
    }

    #[test]
    fn test_count_at_least_single_template() {
        let dir = temp_dir("index-count");
        fs::create_dir_all(dir.join("segments")).unwrap();
        fs::create_dir_all(dir.join("index")).unwrap();

        let mut summary = SegmentSummary::default();
        summary.pattern_mask = 0b1; // 只有模板 0
        summary.flags = SegmentSummary::HAS_SUMMARY;

        let idx = Index::open(&dir).unwrap();
        idx.add_segment_with_summary(1, 1000, 2000, 256, summary).unwrap();

        // 若 keyword 命中模板 0 的 Literal，应贡献 256
        // 但由于无全局字典，keyword 未注册，返回 0
        let count = idx.count_at_least(0, u64::MAX, "UNKNOWN");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_count_at_least_level_only() {
        let dir = temp_dir("index-count-level");
        fs::create_dir_all(dir.join("segments")).unwrap();
        fs::create_dir_all(dir.join("index")).unwrap();

        let mut summary = SegmentSummary::default();
        summary.level_mask = 0b1000; // 含 E
        summary.flags = SegmentSummary::HAS_SUMMARY;

        let idx = Index::open(&dir).unwrap();
        idx.add_segment_with_summary(1, 1000, 2000, 100, summary).unwrap();

        let count = idx.count_at_least(0, u64::MAX, "ERROR");
        assert_eq!(count, 1); 
    }

    #[test]
    fn test_old_segment_compat() {
        let dir = temp_dir("index-old");
        fs::create_dir_all(dir.join("segments")).unwrap();
        fs::create_dir_all(dir.join("index")).unwrap();

        let idx = Index::open(&dir).unwrap();
        idx.add_segment(1, 1000, 2000, 100).unwrap();

        // 旧版 Segment 无摘要，may_exist 保守返回 true
        assert!(idx.may_exist(0, u64::MAX, "ANYTHING"));
        // count_at_least 保守返回 0
        assert_eq!(idx.count_at_least(0, u64::MAX, "ANYTHING"), 0);
    }
// 将以下内容追加到 src/agent/index.rs 的 #[cfg(test)] mod tests 中

#[test]
fn test_query_range_empty() {
    let dir = temp_dir("index-empty-range");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let idx = Index::open(&dir).unwrap();
    let result = idx.query_range(0, u64::MAX);
    assert!(result.is_empty());
}

#[test]
fn test_query_range_single_segment() {
    let dir = temp_dir("index-single");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let idx = Index::open(&dir).unwrap();
    idx.add_segment(1, 1000, 2000, 100).unwrap();

    let all = idx.query_range(0, u64::MAX);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].segment_id, 1);

    let hit = idx.query_range(1500, 2500);
    assert_eq!(hit.len(), 1);

    let miss = idx.query_range(3000, 4000);
    assert!(miss.is_empty());
}

#[test]
fn test_query_range_multiple_segments_sorted() {
    let dir = temp_dir("index-multi");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let idx = Index::open(&dir).unwrap();
    idx.add_segment(1, 1000, 2000, 100).unwrap();
    idx.add_segment(2, 1500, 2500, 200).unwrap();
    idx.add_segment(3, 3000, 4000, 150).unwrap();

    let result = idx.query_range(1200, 3500);
    assert_eq!(result.len(), 3);
    // 应按 max_ts 降序：seg3(4000) > seg2(2500) > seg1(2000)
    assert_eq!(result[0].segment_id, 3);
    assert_eq!(result[1].segment_id, 2);
    assert_eq!(result[2].segment_id, 1);
}

#[test]
fn test_query_by_id_found() {
    let dir = temp_dir("index-by-id");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let idx = Index::open(&dir).unwrap();
    idx.add_segment(42, 1000, 2000, 100).unwrap();

    let found = idx.query_by_id(42);
    assert!(found.is_some());
    assert_eq!(found.unwrap().segment_id, 42);
}

#[test]
fn test_query_by_id_not_found() {
    let dir = temp_dir("index-by-id-miss");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let idx = Index::open(&dir).unwrap();
    idx.add_segment(1, 1000, 2000, 100).unwrap();

    assert!(idx.query_by_id(99).is_none());
}

#[test]
fn test_manifest_persistence_roundtrip() {
    let dir = temp_dir("index-persist");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    {
        let idx = Index::open(&dir).unwrap();
        idx.add_segment(1, 1000, 2000, 100).unwrap();
        idx.add_segment(2, 2500, 3500, 200).unwrap();
        // drop 时会自动 save
    }

    // 重新打开，应能加载之前的 manifest
    let idx2 = Index::open(&dir).unwrap();
    let stats = idx2.stats();
    assert_eq!(stats.segment_count, 2);
    assert_eq!(stats.total_lines, 300);

    let all = idx2.query_range(0, u64::MAX);
    assert_eq!(all.len(), 2);
}

#[test]
fn test_manifest_corruption_rebuild() {
    let dir = temp_dir("index-rebuild");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    {
        let idx = Index::open(&dir).unwrap();
        idx.add_segment(1, 1000, 2000, 100).unwrap();
    }

    // 破坏 manifest 文件
    let manifest_path = dir.join("index").join("manifest.midx");
    fs::write(&manifest_path, b"CORRUPTED DATA").unwrap();

    // 重新打开应触发重建（从 segments 目录扫描）
    let idx = Index::open(&dir).unwrap();
    let stats = idx.stats();
    // 注意：由于 scan_all_segments 需要实际 segment 文件，
    // 若之前只有 manifest 而无 segment 文件，重建后可能为空
    // 此测试主要用于验证不 panic
}

#[test]
fn test_next_segment_id_monotonic() {
    let dir = temp_dir("index-id");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let idx = Index::open(&dir).unwrap();
    let id1 = idx.next_segment_id();
    let id2 = idx.next_segment_id();
    let id3 = idx.next_segment_id();

    assert_eq!(id2, id1 + 1);
    assert_eq!(id3, id2 + 1);
}

#[test]
fn test_stats_calculation() {
    let dir = temp_dir("index-stats");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let idx = Index::open(&dir).unwrap();
    idx.add_segment(1, 1000, 2000, 100).unwrap();
    idx.add_segment(2, 500, 1500, 200).unwrap();
    idx.add_segment(3, 3000, 4000, 50).unwrap();

    let stats = idx.stats();
    assert_eq!(stats.segment_count, 3);
    assert_eq!(stats.total_lines, 350);
    assert_eq!(stats.min_ts, Some(500));
    assert_eq!(stats.max_ts, Some(4000));
}

#[test]
fn test_may_exist_pattern_match() {
    let dir = temp_dir("index-pattern");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let mut summary = SegmentSummary::default();
    summary.pattern_mask = 0b1; // 含模板 0
    summary.flags = SegmentSummary::HAS_SUMMARY;

    let idx = Index::open(&dir).unwrap();
    // 手动注入全局关键词映射（模拟 rebuild_keyword_map 效果）
    {
        let mut map = idx.keyword_to_patterns.write().unwrap();
        map.insert("logged".to_string(), vec![0]);
    }
    idx.add_segment_with_summary(1, 1000, 2000, 100, summary).unwrap();

    // 由于 keyword_to_patterns 中有 "logged" -> pat 0，且 summary.pattern_mask 含 pat 0
    assert!(idx.may_exist(0, u64::MAX, "logged"));
}

#[test]
fn test_count_at_least_multi_template() {
    let dir = temp_dir("index-multi-template");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let mut summary = SegmentSummary::default();
    summary.pattern_mask = 0b11; // 模板 0 和 1
    summary.level_mask = 0b0010; // 含 I
    summary.flags = SegmentSummary::HAS_SUMMARY;

    let idx = Index::open(&dir).unwrap();
    {
        let mut map = idx.keyword_to_patterns.write().unwrap();
        map.insert("login".to_string(), vec![0]);
        map.insert("query".to_string(), vec![1]);
    }
    idx.add_segment_with_summary(1, 1000, 2000, 256, summary).unwrap();

    // 两个模板都匹配，总模板数 > 1，贡献 matched_pats = 2
    let count_login = idx.count_at_least(0, u64::MAX, "login");
    let count_query = idx.count_at_least(0, u64::MAX, "query");
    assert_eq!(count_login, 1); // 仅模板 0 匹配，总模板数 >1，贡献 1
    assert_eq!(count_query, 1);  // 仅模板 1 匹配，总模板数 >1，贡献 1
}

#[test]
fn test_rebuild_function() {
    let dir = temp_dir("index-rebuild-fn");
    fs::create_dir_all(dir.join("segments")).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();

    let idx = Index::open(&dir).unwrap();
    idx.add_segment(1, 1000, 2000, 100).unwrap();
    idx.add_segment(2, 3000, 4000, 200).unwrap();

    // rebuild 从 segments 目录扫描重建；当前目录下无 segment 文件，
    // 因此重建后内存中的 segment 列表会被清空
    idx.rebuild().unwrap();

    let stats = idx.stats();
    assert_eq!(stats.segment_count, 0);
    assert_eq!(stats.total_lines, 0);
}

#[test]
fn test_manifest_entry_time_overlap_boundaries() {
    let e = ManifestEntry::new(1, 1000, 2000, 10, "path");
    // 精确边界
    assert!(e.overlaps(1000, 2000));
    assert!(e.overlaps(2000, 3000)); // max_ts=2000 与 start=2000 接触
    assert!(e.overlaps(0, 1000));     // min_ts=1000 与 end=1000 接触
}
}