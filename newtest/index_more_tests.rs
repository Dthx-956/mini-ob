
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

    idx.rebuild().unwrap();

    let stats = idx.stats();
    assert_eq!(stats.segment_count, 2);
    assert_eq!(stats.total_lines, 300);
}

#[test]
fn test_manifest_entry_time_overlap_boundaries() {
    let e = ManifestEntry::new(1, 1000, 2000, 10, "path");
    // 精确边界
    assert!(e.overlaps(1000, 2000));
    assert!(e.overlaps(2000, 3000)); // max_ts=2000 与 start=2000 接触
    assert!(e.overlaps(0, 1000));     // min_ts=1000 与 end=1000 接触
}
