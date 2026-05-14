//! mini-obs/agent/index.rs
//! 轻量级日志索引引擎 —— 内存常驻 + 磁盘 Manifest
//!
//! 设计约束：
//! - 内存占用 < 1MB/万 Segment（ManifestEntry 仅 64 bytes）
//! - 启动时全量加载到内存，运行时只追加
//! - Manifest 损坏时可通过扫描 segments 目录自愈重建
//! - 线程安全：读多写少，RwLock 保护

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::shared::format::{
    crc32, parse_segment_name, segment_name, ChunkEntry, FormatError,
    ManifestEntry, ManifestHeader, SegmentHeader, CHUNK_ENTRY_SIZE,
    MANIFEST_ENTRY_SIZE, SEGMENT_HEADER_SIZE,
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
/// 内存结构：Vec<ManifestEntry>（按 segment_id 升序），支持二分查找
/// 磁盘结构：manifest.midx = Header(9B) + Entry[](N×64B) + CRC32(4B)
pub struct Index {
    data_dir: PathBuf,
    entries: RwLock<Vec<ManifestEntry>>,
    next_id: RwLock<u32>,
}

impl Index {
    // ==================== 生命周期 ====================

    /// 打开或初始化索引目录
    ///
    /// 优先加载现有 manifest.midx；若损坏或不存在，扫描 segments/ 目录重建
    pub fn open(data_dir: impl AsRef<Path>) -> io::Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(data_dir.join("index"))?;
        fs::create_dir_all(data_dir.join("segments"))?;

        let (entries, next_id) = match Self::load(&data_dir) {
            Ok(entries) => {
                let next = entries.last().map(|e| e.segment_id + 1).unwrap_or(1);
                (entries, next)
            }
            Err(e) => {
                eprintln!("Manifest load failed ({}), rebuilding from segments...", e);
                let entries = Self::scan_all_segments(&data_dir)?;
                let next = entries.last().map(|e| e.segment_id + 1).unwrap_or(1);
                let idx = Self {
                    data_dir: data_dir.clone(),
                    entries: RwLock::new(entries.clone()),
                    next_id: RwLock::new(next),
                };
                idx.save()?; // 重建后立即持久化
                (entries, next)
            }
        };

        Ok(Self {
            data_dir,
            entries: RwLock::new(entries),
            next_id: RwLock::new(next_id),
        })
    }

    // ==================== 公共 API ====================

    /// 注册新 Segment 到索引（由 storage flush 后调用）
    pub fn add_segment(&self, id: u32, min_ts: u64, max_ts: u64, line_count: u32) -> io::Result<()> {
        let path = self.data_dir.join("segments").join(segment_name(id));
        let entry = ManifestEntry::new(id, min_ts, max_ts, line_count, &path.to_string_lossy());

        {
            let mut entries = self.entries.write().unwrap();
            entries.push(entry);
            entries.sort_by_key(|e| e.segment_id);
        }

        self.save()?;
        Ok(())
    }

    /// 分配下一个 Segment ID（原子递增）
    pub fn next_segment_id(&self) -> u32 {
        let mut nid = self.next_id.write().unwrap();
        let id = *nid;
        *nid += 1;
        id
    }

    /// 时间范围查询：返回与 [start, end] 重叠的所有 Segment（按 max_ts 降序，最新优先）
    pub fn query_range(&self, start: u64, end: u64) -> Vec<ManifestEntry> {
        let entries = self.entries.read().unwrap();
        let mut result: Vec<ManifestEntry> = entries
            .iter()
            .filter(|e| e.overlaps(start, end) && !e.is_deleted())
            .copied()
            .collect();
        // 最新优先（边缘场景下通常查近期日志）
        result.sort_by_key(|e| std::cmp::Reverse(e.max_ts));
        result
    }

    /// 精确查询 Segment ID（二分查找，O(log N)）
    pub fn query_by_id(&self, id: u32) -> Option<ManifestEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .binary_search_by_key(&id, |e| e.segment_id)
            .ok()
            .map(|idx| entries[idx])
    }

    /// 强制重建索引（扫描 segments 目录，从文件头解析元数据）
    pub fn rebuild(&self) -> io::Result<()> {
        let new_entries = Self::scan_all_segments(&self.data_dir)?;
        {
            let mut entries = self.entries.write().unwrap();
            *entries = new_entries;
        }
        self.save()?;
        Ok(())
    }

    /// 将内存索引原子写入磁盘（tmp -> rename）
    pub fn save(&self) -> io::Result<()> {
        let entries = self.entries.read().unwrap();
        let index_dir = self.data_dir.join("index");
        fs::create_dir_all(&index_dir)?;

        let tmp_path = index_dir.join("manifest.midx.tmp");
        let final_path = index_dir.join("manifest.midx");

        let mut file = File::create(&tmp_path)?;

        // 1. Header
        let header = ManifestHeader::new(entries.len() as u32);
        file.write_all(&header.to_bytes())?;

        // 2. Entries（边序列化边累加 CRC）
        let mut entry_bytes = Vec::with_capacity(entries.len() * MANIFEST_ENTRY_SIZE);
        for entry in entries.iter() {
            entry_bytes.extend_from_slice(&entry.to_bytes());
        }
        file.write_all(&entry_bytes)?;

        // 3. CRC32（覆盖全部 Entry 区域）
        file.write_all(&crc32(&entry_bytes).to_le_bytes())?;

        file.sync_all()?;
        drop(file);

        fs::rename(tmp_path, final_path)?;
        Ok(())
    }

    /// 获取索引统计
    pub fn stats(&self) -> IndexStats {
        let entries = self.entries.read().unwrap();
        let total_lines = entries.iter().map(|e| e.line_count as u64).sum();

        let (min_ts, max_ts) = entries.iter().fold((None, None), |(min, max), e| {
            (
                Some(min.map_or(e.min_ts, |m: u64| m.min(e.min_ts))),
                Some(max.map_or(e.max_ts, |m: u64| m.max(e.max_ts))),
            )
        });

        IndexStats {
            segment_count: entries.len(),
            total_lines,
            min_ts,
            max_ts,
        }
    }

    // ==================== 私有方法 ====================

    /// 从磁盘加载 manifest.midx
    fn load(data_dir: &Path) -> io::Result<Vec<ManifestEntry>> {
        let path = data_dir.join("index").join("manifest.midx");
        let mut file = File::open(&path)?;

        // Header
        let mut header_buf = [0u8; 9];
        file.read_exact(&mut header_buf)?;
        let header = ManifestHeader::from_bytes(&header_buf)
            .map_err(|e: FormatError| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if header.entry_count == 0 {
            return Ok(Vec::new());
        }

        // Entries
        let count = header.entry_count as usize;
        let mut entries = Vec::with_capacity(count);
        let mut entry_bytes = Vec::with_capacity(count * MANIFEST_ENTRY_SIZE);

        for _ in 0..count {
            let mut buf = [0u8; MANIFEST_ENTRY_SIZE];
            file.read_exact(&mut buf)?;
            let entry = ManifestEntry::from_bytes(&buf)
                .map_err(|e: FormatError| io::Error::new(io::ErrorKind::InvalidData, e))?;
            entries.push(entry);
            entry_bytes.extend_from_slice(&buf);
        }

        // CRC validation
        let mut crc_buf = [0u8; 4];
        file.read_exact(&mut crc_buf)?;
        let stored_crc = u32::from_le_bytes(crc_buf);
        let computed_crc = crc32(&entry_bytes);
        if computed_crc != stored_crc {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "manifest CRC mismatch"));
        }

        Ok(entries)
    }

    /// 扫描 segments 目录，从每个 .mobs 文件头解析元数据
    fn scan_all_segments(data_dir: &Path) -> io::Result<Vec<ManifestEntry>> {
        let seg_dir = data_dir.join("segments");
        let mut entries = Vec::new();

        if !seg_dir.exists() {
            return Ok(entries);
        }

        for dir_entry in fs::read_dir(&seg_dir)? {
            let dir_entry = dir_entry?;
            let name = dir_entry.file_name();
            let name_str = name.to_string_lossy();

            let id = match parse_segment_name(&name_str) {
                Some(id) => id,
                None => continue,
            };

            let (fid, min_ts, max_ts, lines) = match Self::scan_segment_meta(&dir_entry.path()) {
                Ok(meta) => meta,
                Err(e) => {
                    eprintln!("Skip corrupted segment {}: {}", name_str, e);
                    continue;
                }
            };

            if fid != id {
                eprintln!(
                    "Warning: segment {} header ID {} mismatches filename, using filename ID",
                    name_str, fid
                );
            }

            let entry = ManifestEntry::new(id, min_ts, max_ts, lines, &dir_entry.path().to_string_lossy());
            entries.push(entry);
        }

        entries.sort_by_key(|e| e.segment_id);
        Ok(entries)
    }

    /// 读取单个 Segment 文件的 Header + ChunkEntries，提取时间范围和行数
    fn scan_segment_meta(path: &Path) -> io::Result<(u32, u64, u64, u32)> {
        let file = File::open(path)?;
        let mut reader = io::BufReader::new(file);

        // Header
        let mut header_buf = [0u8; SEGMENT_HEADER_SIZE];
        reader.read_exact(&mut header_buf)?;
        let header = SegmentHeader::from_bytes(&header_buf)
            .map_err(|e: FormatError| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Aggregate all chunks
        let mut min_ts = u64::MAX;
        let mut max_ts = u64::MIN;
        let mut total_lines = 0u32;

        for _ in 0..header.chunk_count {
            let mut entry_buf = [0u8; CHUNK_ENTRY_SIZE];
            reader.read_exact(&mut entry_buf)?;
            let chunk = ChunkEntry::from_bytes(&entry_buf)
                .map_err(|e: FormatError| io::Error::new(io::ErrorKind::InvalidData, e))?;
            min_ts = min_ts.min(chunk.min_ts);
            max_ts = max_ts.max(chunk.max_ts);
            total_lines += chunk.line_count;
        }

        // Edge case: empty segment
        if header.chunk_count == 0 {
            min_ts = header.created_at;
            max_ts = header.created_at;
        }

        Ok((header.segment_id, min_ts, max_ts, total_lines))
    }
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::format::{align_up, SegmentFooter, ALIGNMENT};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("mini-obs-index-test-{}-{}", ts, n));
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("segments")).unwrap();
        fs::create_dir_all(dir.join("index")).unwrap();
        dir
    }

    /// 构造一个最小合法的假 Segment 文件（仅用于重建测试）
    fn create_fake_segment(path: &Path, id: u32, min_ts: u64, max_ts: u64, lines: u32) -> io::Result<()> {
        let header = SegmentHeader::new(id, 1);
        let data_offset = align_up(SEGMENT_HEADER_SIZE + CHUNK_ENTRY_SIZE, ALIGNMENT) as u32;
        let chunk = ChunkEntry::new(data_offset, 10, 100, lines, min_ts, max_ts);

        let mut content = Vec::new();
        content.extend_from_slice(&header.to_bytes());
        content.extend_from_slice(&chunk.to_bytes());

        // 填充到对齐边界 + 假压缩数据
        let target_len = (data_offset as usize) + 10;
        content.resize(target_len, 0);

        let mut footer = SegmentFooter::new(SEGMENT_HEADER_SIZE as u32);
        footer.crc32 = crc32(&content);
        content.extend_from_slice(&footer.to_bytes());

        fs::write(path, content)
    }

    #[test]
    fn test_open_empty_and_allocate_id() {
        let dir = temp_dir();
        let idx = Index::open(&dir).unwrap();

        assert_eq!(idx.stats().segment_count, 0);
        assert_eq!(idx.next_segment_id(), 1);
        assert_eq!(idx.next_segment_id(), 2);
    }

    #[test]
    fn test_add_and_query_range() {
        let dir = temp_dir();
        let idx = Index::open(&dir).unwrap();

        // 注册 5 个 Segment，时间交错
        idx.add_segment(1, 1000, 2000, 100).unwrap();
        idx.add_segment(2, 1500, 2500, 200).unwrap();
        idx.add_segment(3, 3000, 4000, 150).unwrap();
        idx.add_segment(4, 500, 1200, 50).unwrap();
        idx.add_segment(5, 2200, 3200, 80).unwrap();

        // 查询与 [1600, 2800] 重叠的 Segment
        let hits = idx.query_range(1600, 2800);
        let ids: Vec<u32> = hits.iter().map(|e| e.segment_id).collect();
        // 应命中: 2(1500-2500), 5(2200-3200), 1(1000-2000 不重叠1600-2800? 等等，1000-2000 与 1600-2800 重叠于 1600-2000，是重叠的)
        // 1: 1000-2000 与 1600-2800 重叠 (1600-2000) -> 命中
        // 2: 1500-2500 与 1600-2800 重叠 (1600-2500) -> 命中
        // 3: 3000-4000 不重叠 -> 不命中
        // 4: 500-1200 不重叠 -> 不命中
        // 5: 2200-3200 与 1600-2800 重叠 (2200-2800) -> 命中
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
        assert!(ids.contains(&5));
        assert!(!ids.contains(&3));
        assert!(!ids.contains(&4));

        // 验证按 max_ts 降序
        assert_eq!(hits[0].segment_id, 5); // max_ts=3200 最大
    }

    #[test]
    fn test_query_by_id() {
        let dir = temp_dir();
        let idx = Index::open(&dir).unwrap();
        idx.add_segment(42, 1000, 2000, 10).unwrap();

        assert!(idx.query_by_id(42).is_some());
        assert!(idx.query_by_id(99).is_none());
    }

    #[test]
    fn test_persistence_and_reload() {
        let dir = temp_dir();
        {
            let idx = Index::open(&dir).unwrap();
            idx.add_segment(1, 1000, 2000, 100).unwrap();
            idx.add_segment(2, 3000, 4000, 200).unwrap();
        }

        // 重新打开，验证从磁盘恢复
        let idx2 = Index::open(&dir).unwrap();
        let stats = idx2.stats();
        assert_eq!(stats.segment_count, 2);
        assert_eq!(stats.total_lines, 300);

        let hit = idx2.query_by_id(2).unwrap();
        assert_eq!(hit.max_ts, 4000);
    }

    #[test]
    fn test_manifest_corruption_rebuild() {
        let dir = temp_dir();
        let seg_dir = dir.join("segments");

        // 先创建假 Segment 文件并注册到索引
        {
            let idx = Index::open(&dir).unwrap();
            create_fake_segment(&seg_dir.join("segment-00000001.mobs"), 1, 1000, 2000, 50).unwrap();
            idx.add_segment(1, 1000, 2000, 50).unwrap();
        }

        // 破坏 manifest
        let manifest_path = dir.join("index").join("manifest.midx");
        fs::write(&manifest_path, b"CORRUPTED").unwrap();

        // 重新打开应触发重建（从 segments 目录扫描）
        let idx = Index::open(&dir).unwrap();
        assert_eq!(idx.stats().segment_count, 1);
        assert_eq!(idx.query_by_id(1).unwrap().line_count, 50);
    }

    #[test]
    fn test_rebuild_from_segments() {
        let dir = temp_dir();
        let seg_dir = dir.join("segments");

        // 直接创建 3 个假 Segment 文件，无 manifest
        create_fake_segment(&seg_dir.join("segment-00000007.mobs"), 7, 1000, 2000, 50).unwrap();
        create_fake_segment(&seg_dir.join("segment-00000003.mobs"), 3, 500, 800, 30).unwrap();
        create_fake_segment(&seg_dir.join("segment-00000012.mobs"), 12, 3000, 4000, 100).unwrap();

        let idx = Index::open(&dir).unwrap();
        let stats = idx.stats();
        assert_eq!(stats.segment_count, 3);
        assert_eq!(stats.total_lines, 180); // 50+30+100

        // 验证排序（按 segment_id）
        let all = idx.query_range(0, u64::MAX);
        assert_eq!(all[0].segment_id, 12); // 最新优先（max_ts 最大）
        assert_eq!(all[2].segment_id, 3);
    }

    #[test]
    fn test_stats_accuracy() {
        let dir = temp_dir();
        let idx = Index::open(&dir).unwrap();

        idx.add_segment(1, 1000, 2000, 10).unwrap();
        idx.add_segment(2, 500, 1500, 20).unwrap();
        idx.add_segment(3, 3000, 4000, 30).unwrap();

        let s = idx.stats();
        assert_eq!(s.segment_count, 3);
        assert_eq!(s.total_lines, 60);
        assert_eq!(s.min_ts, Some(500));
        assert_eq!(s.max_ts, Some(4000));
    }

    #[test]
    fn test_next_id_monotonic() {
        let dir = temp_dir();
        let seg_dir = dir.join("segments");
        let idx = Index::open(&dir).unwrap();

        assert_eq!(idx.next_segment_id(), 1);
        assert_eq!(idx.next_segment_id(), 2);
        create_fake_segment(&seg_dir.join("segment-00000002.mobs"), 2, 100, 200, 5).unwrap();
        idx.add_segment(2, 100, 200, 5).unwrap();
        assert_eq!(idx.next_segment_id(), 3);
    }
}