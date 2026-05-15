// tests/integration_tests.rs
// Mini-OBS 集成测试：端到端验证 Agent/Storage/Index/Compressor 协作

use mini_obs::agent::*;
use mini_obs::shared::format::*;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

fn temp_dir(prefix: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let dir = std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), ts));
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

// ==================== 端到端写入-查询 ====================

#[test]
fn test_end_to_end_write_query() {
    let dir = temp_dir("e2e-write-query");
    let cfg = StorageConfig {
        max_buffer_lines: 10,
        chunk_size: 5,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    // 写入 50 条混合日志
    for i in 0..50 {
        let lvl = match i % 4 {
            0 => "D",
            1 => "I",
            2 => "W",
            _ => "E",
        };
        let msg = if i % 5 == 0 {
            format!("ERROR: critical failure in module {}", i)
        } else {
            format!("Request {} processed successfully", i)
        };
        engine.append(make_log(1000 + i as u64 * 100, "app", lvl, &msg)).unwrap();
    }

    // 全量查询
    let all = engine.query(0, u64::MAX, "", 1000).unwrap();
    assert_eq!(all.len(), 50);

    // 关键词查询
    let errors = engine.query(0, u64::MAX, "critical", 1000).unwrap();
    assert_eq!(errors.len(), 10); // i % 5 == 0 共 10 条
    for log in &errors {
        assert!(log.message.contains("critical"));
    }

    // 时间范围查询
    let mid = engine.query(2000, 3000, "", 1000).unwrap();
    assert_eq!(mid.len(), 11); // ts 2000..3000 含边界

    // limit 测试
    let limited = engine.query(0, u64::MAX, "", 5).unwrap();
    assert_eq!(limited.len(), 5);
}

#[test]
fn test_end_to_end_compression_ratio() {
    let dir = temp_dir("e2e-compression");
    let cfg = StorageConfig {
        max_buffer_lines: 100,
        chunk_size: 50,
        compression_level: 3,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    // 高重复度模板日志
    for i in 0..1000 {
        let msg = format!(
            "User {} performed action LOGIN on resource {} at 2026-05-15T09:24:00Z from {}.{}.{}.{}",
            i,
            i % 100,
            192,
            168,
            i % 256,
            (i / 256) % 256
        );
        engine.append(make_log(1000 + i as u64 * 1000, "auth", "I", &msg)).unwrap();
    }

    let stats = engine.stats();
    let ratio = stats.compression_ratio();
    println!("End-to-end compression ratio: {:.2}x", ratio);
    assert!(ratio > 3.0, "Expected >3x compression, got {:.2}x", ratio);
}

// ==================== Collector + Storage 集成 ====================

#[test]
fn test_collector_to_storage_pipeline() {
    let dir = temp_dir("e2e-collector-storage");
    let cfg = StorageConfig {
        max_buffer_lines: 50,
        chunk_size: 25,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    let (collector, rx) = Collector::start(CollectorConfig {
        source: SourceType::Mock {
            rate_per_sec: 100,
            duration_sec: 1,
        },
        poll_interval: Duration::from_millis(10),
        service_name: "integration".to_string(),
    }).unwrap();

    // 消费 channel 并写入 storage
    let engine_clone = std::sync::Arc::new(engine);
    let engine_writer = engine_clone.clone();
    let handle = std::thread::spawn(move || {
        while let Ok(log) = rx.recv_timeout(Duration::from_secs(2)) {
            engine_writer.append(log).unwrap();
        }
    });

    handle.join().unwrap();
    collector.stop();

    let stats = engine_clone.stats();
    assert!(stats.total_lines >= 50, "Expected >=50 lines, got {}", stats.total_lines);

    let all = engine_clone.query(0, u64::MAX, "", 10000).unwrap();
    assert!(!all.is_empty());
}

// ==================== 崩溃恢复集成 ====================

#[test]
fn test_crash_recovery_integrity() {
    let dir = temp_dir("e2e-crash");
    let cfg = StorageConfig {
        max_buffer_lines: 100,
        chunk_size: 50,
        ..Default::default()
    };

    // Phase 1: 写入但不 flush（模拟崩溃）
    {
        let engine = StorageEngine::open(&dir, cfg.clone()).unwrap();
        for i in 0..77 {
            engine.append(make_log(
                1000 + i as u64 * 100,
                "svc",
                if i % 7 == 0 { "E" } else { "I" },
                &format!("crash test message {}", i),
            )).unwrap();
        }
        // 不 flush，直接 drop
    }

    // Phase 2: 重新打开，验证 WAL 恢复
    let engine = StorageEngine::open(&dir, cfg).unwrap();
    let stats = engine.stats();
    assert_eq!(stats.total_lines, 77);

    let all = engine.query(0, u64::MAX, "", 1000).unwrap();
    assert_eq!(all.len(), 77);

    // 验证数据完整性
    for i in 0..77 {
        let expected_msg = format!("crash test message {}", i);
        assert!(all.iter().any(|l| l.message == expected_msg));
    }
}

// ==================== 并发压力测试 ====================

#[test]
fn test_concurrent_append() {
    let dir = temp_dir("e2e-concurrent");
    let cfg = StorageConfig {
        max_buffer_lines: 1000,
        chunk_size: 500,
        ..Default::default()
    };
    let engine = std::sync::Arc::new(StorageEngine::open(&dir, cfg).unwrap());

    let mut handles = vec![];
    for t in 0..4 {
        let eng = engine.clone();
        let handle = std::thread::spawn(move || {
            for i in 0..250 {
                eng.append(make_log(
                    1000 + t as u64 * 10000 + i as u64 * 10,
                    &format!("svc{}", t),
                    "I",
                    &format!("thread {} msg {}", t, i),
                )).unwrap();
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    let stats = engine.stats();
    assert_eq!(stats.total_lines, 1000);

    let all = engine.query(0, u64::MAX, "", 10000).unwrap();
    assert_eq!(all.len(), 1000);
}

// ==================== 查询精确性测试 ====================

#[test]
fn test_query_accuracy_with_multiple_segments() {
    let dir = temp_dir("e2e-accuracy");
    let cfg = StorageConfig {
        max_buffer_lines: 10,
        chunk_size: 5,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    // 写入跨多个 segment 的数据
    for batch in 0..5 {
        for i in 0..10 {
            let ts = batch * 10000 + i as u64 * 100;
            let msg = if i == 5 {
                format!("BATCH{} SPECIAL MARKER", batch)
            } else {
                format!("batch {} regular {}", batch, i)
            };
            engine.append(make_log(ts, "app", "I", &msg)).unwrap();
        }
    }

    // 查询特定 marker
    let markers = engine.query(0, u64::MAX, "SPECIAL MARKER", 1000).unwrap();
    assert_eq!(markers.len(), 5);
    for (i, log) in markers.iter().enumerate() {
        assert!(log.message.contains(&format!("BATCH{} SPECIAL MARKER", 4 - i))); // 降序
    }

    // 查询特定 batch 时间范围
    let batch2 = engine.query(20000, 29999, "", 1000).unwrap();
    assert_eq!(batch2.len(), 10);
}

// ==================== Index 自愈集成 ====================

#[test]
fn test_index_rebuild_from_segments() {
    let dir = temp_dir("e2e-index-rebuild");
    let cfg = StorageConfig {
        max_buffer_lines: 10,
        chunk_size: 10,
        ..Default::default()
    };

    // 创建数据
    {
        let engine = StorageEngine::open(&dir, cfg.clone()).unwrap();
        for i in 0..30 {
            engine.append(make_log(1000 + i as u64 * 100, "svc", "I", &format!("msg {}", i))).unwrap();
        }
    }

    // 删除 manifest
    let manifest_path = dir.join("index").join("manifest.midx");
    assert!(manifest_path.exists());
    fs::remove_file(&manifest_path).unwrap();

    // 重新打开应自动重建索引
    let engine = StorageEngine::open(&dir, cfg).unwrap();
    let stats = engine.stats();
    assert_eq!(stats.total_lines, 30);
    assert_eq!(stats.segment_count, 3);

    let all = engine.query(0, u64::MAX, "", 1000).unwrap();
    assert_eq!(all.len(), 30);
}

// ==================== 边界与异常测试 ====================

#[test]
fn test_empty_query_no_panic() {
    let dir = temp_dir("e2e-empty");
    let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();

    let empty = engine.query(0, u64::MAX, "", 100).unwrap();
    assert!(empty.is_empty());

    let no_match = engine.query(0, u64::MAX, "impossible", 100).unwrap();
    assert!(no_match.is_empty());
}

#[test]
fn test_very_large_message_integrity() {
    let dir = temp_dir("e2e-large-msg");
    let cfg = StorageConfig {
        max_buffer_lines: 2,
        chunk_size: 2,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    let big = "X".repeat(5 * 1024 * 1024); // 5MB
    engine.append(make_log(1000, "svc", "E", &big)).unwrap();
    engine.append(make_log(2000, "svc", "E", "small")).unwrap();

    let all = engine.query(0, u64::MAX, "", 100).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].message.len(), 5 * 1024 * 1024);
    assert_eq!(all[1].message, "small");
}

#[test]
fn test_unicode_message_roundtrip() {
    let dir = temp_dir("e2e-unicode");
    let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();

    let msgs = vec![
        "中文测试消息",
        "日本語テストメッセージ",
        "한국어 테스트 메시지",
        "🎉🎊🎁 Emoji party! 🌍🌎🌏",
        "Arabic: مرحبا بالعالم",
        "Russian: Привет мир",
    ];

    for (i, msg) in msgs.iter().enumerate() {
        engine.append(make_log(1000 + i as u64 * 100, "svc", "I", msg)).unwrap();
    }

    let all = engine.query(0, u64::MAX, "", 100).unwrap();
    assert_eq!(all.len(), 6);
    for (expected, actual) in msgs.iter().zip(all.iter().rev()) {
        assert_eq!(actual.message, *expected);
    }
}

// ==================== 性能基准（非严格，仅防退化）====================

#[test]
fn test_bulk_write_performance() {
    let dir = temp_dir("e2e-perf");
    let cfg = StorageConfig {
        max_buffer_lines: 10000,
        chunk_size: 5000,
        ..Default::default()
    };
    let engine = StorageEngine::open(&dir, cfg).unwrap();

    let start = std::time::Instant::now();
    for i in 0..10000 {
        engine.append(make_log(
            1000 + i as u64,
            "perf",
            "I",
            &format!("Performance test log entry number {} with some padding", i),
        )).unwrap();
    }
    let elapsed = start.elapsed();

    let stats = engine.stats();
    assert_eq!(stats.total_lines, 10000);

    // 宽松阈值：10k 条应在 5 秒内完成（Debug 模式）
    println!("Bulk write 10k logs: {:?}", elapsed);
    assert!(elapsed < Duration::from_secs(5), "Too slow: {:?}", elapsed);
}
