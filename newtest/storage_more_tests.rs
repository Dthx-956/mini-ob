
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
    assert_eq!(stats.total_lines, 23);
    // 23 / 5 = 4 个完整 flush + 3 条在缓冲
    assert_eq!(stats.segment_count, 4);
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
