//! 端到端集成测试：验证完整 write -> flush -> query 链路

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use mini_obs::agent::{StorageConfig, StorageEngine};
use mini_obs::shared::format::LogLine;

#[test]
fn test_end_to_end_write_flush_query() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let dir = format!("/tmp/mini-obs-integ-{}", ts);
    fs::create_dir_all(&dir).unwrap();

    let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();

    // 写入 500 条日志，触发多次 flush
    for i in 0..500 {
        let level = if i % 10 == 0 { "E" } else { "I" };
        engine
            .append(LogLine {
                ts: 1000000 + i as u64 * 1000,
                service: "nginx".into(),
                level: level.into(),
                message: format!("request {} handled", i),
            })
            .unwrap();
    }

    // 强制刷盘确保落段
    engine.flush().unwrap();

    // 查询 ERROR 级别
    let errors = engine.query(0, u64::MAX, "E", 100).unwrap();
    assert_eq!(errors.len(), 50); // i=0,10,20...490

    // 时间范围查询
    let mid = engine.query(2000000, 3000000, "", 100).unwrap();
    assert_eq!(mid.len(), 1); // 仅 ts=2000000 那条

    // 统计验证
    let stats = engine.stats();
    assert_eq!(stats.total_lines, 500);
    assert_eq!(stats.buffered_lines, 0); // 已 flush
    assert!(stats.compression_ratio() > 1.0);

    // 清理
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_crash_recovery_simulation() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let dir = format!("/tmp/mini-obs-crash-{}", ts);
    fs::create_dir_all(&dir).unwrap();

    // 第一次打开，写入但不 flush
    {
        let engine = StorageEngine::open(
            &dir,
            StorageConfig {
                max_buffer_lines: 10000, // 很大，避免自动 flush
                ..Default::default()
            },
        )
        .unwrap();
        for i in 0..42 {
            engine
                .append(LogLine {
                    ts: i as u64 * 100,
                    service: "svc".into(),
                    level: "I".into(),
                    message: format!("crash test {}", i),
                })
                .unwrap();
        }
        // 故意 drop，模拟崩溃
    }

    // 重新打开，应自动恢复 WAL 并 flush
    let engine = StorageEngine::open(&dir, StorageConfig::default()).unwrap();
    let stats = engine.stats();
    assert_eq!(stats.total_lines, 42);
    assert_eq!(stats.buffered_lines, 0);

    let all = engine.query(0, u64::MAX, "crash", 100).unwrap();
    assert_eq!(all.len(), 42);

    let _ = fs::remove_dir_all(&dir);
}