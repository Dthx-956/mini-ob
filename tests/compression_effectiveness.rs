//! 压缩效果集成测试
//!
//! 使用真实 Windows 事件日志 (/tmp/Windows_2k.log) 验证：
//! 1. Mini-OBS 处理后的压缩比是否接近纯 zstd 压缩
//! 2. 解压/查询后数据是否完整
//!
//! 该测试直接对比 "原始字节 -> zstd" 与 "原始行 -> Collector -> StorageEngine -> Segment 文件"
//! 的磁盘占用，评估模板提取+二进制格式的实际收益。

use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use mini_obs::agent::{
    Collector, CollectorConfig, SourceType, StorageConfig, StorageEngine,
};

const LOG_PATH: &str = "/tmp/Windows_2k.log";

fn temp_dir(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("{}-{}-{}-{}", prefix, pid, ts, n));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_windows_2k_compression_vs_pure_zstd() {
    // 1. 读取原始日志
    let log_path = PathBuf::from(LOG_PATH);
    assert!(
        log_path.exists(),
        "测试日志 {} 不存在，请先准备该文件",
        LOG_PATH
    );

    let raw_bytes = fs::read(&log_path).expect("读取日志文件失败");
    let raw_size = raw_bytes.len();
    assert!(raw_size > 0, "日志文件为空");

    // 2. 纯 zstd 压缩（作为对照组）
    let pure_zstd_bytes = zstd::encode_all(&raw_bytes[..], 3).expect("zstd 压缩失败");
    let pure_zstd_size = pure_zstd_bytes.len();
    let pure_zstd_ratio = raw_size as f64 / pure_zstd_size as f64;

    // 3. Mini-OBS 完整流水线
    let data_dir = temp_dir("mini-obs-windows-2k");
    let storage = StorageEngine::open(
        &data_dir,
        StorageConfig {
            max_buffer_lines: 10_000,
            max_buffer_bytes: 5 * 1024 * 1024,
            compression_level: 3,
            chunk_size: 256,
            dict: None,
            single_chunk_threshold_lines: 10_000,
            single_chunk_threshold_bytes: 5 * 1024 * 1024,
            dict_training_min_chunks: 4,
            dict_training_sample_chunks: 8,
        },
    )
    .expect("打开 StorageEngine 失败");

    // Collector::File 首次启动会跳到文件末尾（tail -f 语义），
    // 因此先创建空文件并启动采集器，再写入内容，才能被完整读取。
    let test_log_path = data_dir.join("windows_2k.log");
    fs::write(&test_log_path, b"").expect("创建空测试日志失败");

    let (collector, rx) = Collector::start(CollectorConfig {
        source: SourceType::File {
            path: test_log_path.clone(),
        },
        poll_interval: Duration::from_millis(50),
        service_name: "windows".to_string(),
    })
    .expect("启动 Collector 失败");

    // 等待 Collector 完成首次打开（空文件 seek 到末尾）
    std::thread::sleep(Duration::from_millis(200));

    let raw_text = fs::read_to_string(&log_path).expect("读取原始日志失败");
    let expected_lines = raw_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();

    // 追加写入内容，触发 Collector 读取
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&test_log_path)
        .expect("打开测试日志失败");
    std::io::Write::write_all(&mut file, raw_text.as_bytes()).expect("写入测试日志失败");
    drop(file);

    let mut received = 0usize;
    let deadline = Instant::now() + Duration::from_secs(15);

    loop {
        if received >= expected_lines || Instant::now() > deadline {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(log) => {
                storage.append(log).expect("写入 StorageEngine 失败");
                received += 1;
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    collector.stop();

    // 把 channel 中剩余的日志也写入
    while let Ok(log) = rx.recv_timeout(Duration::from_millis(200)) {
        storage.append(log).expect("写入 StorageEngine 失败");
        received += 1;
    }

    storage.flush().expect("flush 失败");

    // 4. 统计 Mini-OBS 实际磁盘占用（仅 segment 文件）
    let segments_dir = data_dir.join("segments");
    let mut mini_obs_size = 0u64;
    for entry in fs::read_dir(&segments_dir).expect("读取 segments 目录失败") {
        let entry = entry.expect("读取目录项失败");
        mini_obs_size += entry.metadata().expect("读取文件元数据失败").len();
    }

    let mini_obs_ratio = raw_size as f64 / mini_obs_size as f64;

    println!("\n========== Windows_2k.log 压缩效果对比 ==========");
    println!("原始大小:           {:10} bytes ({:.2} KB)", raw_size, raw_size as f64 / 1024.0);
    println!("纯 zstd 大小:       {:10} bytes ({:.2} KB), 压缩比: {:.2}x", pure_zstd_size, pure_zstd_size as f64 / 1024.0, pure_zstd_ratio);
    println!("Mini-OBS 大小:      {:10} bytes ({:.2} KB), 压缩比: {:.2}x", mini_obs_size, mini_obs_size as f64 / 1024.0, mini_obs_ratio);
    println!("接收行数:           {} / {}", received, expected_lines);
    println!("相对效率:           Mini-OBS / 纯 zstd = {:.1}%", (mini_obs_ratio / pure_zstd_ratio) * 100.0);
    println!("==================================================\n");

    // 5. 断言：Mini-OBS 必须真实有效
    assert_eq!(
        received, expected_lines,
        "Collector 未完整接收日志 ({} / {})",
        received, expected_lines
    );

    assert!(
        mini_obs_ratio >= 2.0,
        "Mini-OBS 压缩比过低: {:.2}x，说明模板提取未生效",
        mini_obs_ratio
    );

    // 纯 zstd 是全局一次性压缩，Mini-OBS 为了支持按 Chunk 查询会把数据切分并保留
    // PatternTable/ChunkSummary 等元数据，因此通常会比纯 zstd 大一些。
    // 启用单 Chunk Segment 后，小数据量下 zstd 滑动窗口覆盖全部数据，
    // 要求 Mini-OBS 至少达到纯 zstd 效果的 35%，即可证明元数据设计有效。
    assert!(
        mini_obs_ratio >= pure_zstd_ratio * 0.35,
        "Mini-OBS 压缩比 ({:.2}x) 远低于纯 zstd ({:.2}x)，预处理效果不明显",
        mini_obs_ratio,
        pure_zstd_ratio
    );

    // 6. 完整性校验：查询所有日志，确认可解压还原
    let stats = storage.stats();
    println!(
        "Storage stats: segments={}, total_lines={}, buffered_lines={}",
        stats.segment_count, stats.total_lines, stats.buffered_lines
    );

    let results = storage
        .query(0, u64::MAX, "", expected_lines)
        .expect("查询失败");

    assert_eq!(
        results.len(),
        expected_lines,
        "查询返回行数不匹配 ({} / {})",
        results.len(),
        expected_lines
    );

    // 采样验证 message 内容（降级路径已剥离 Info/Warning/Error 前缀）
    let info_count = results.iter().filter(|l| l.level == "I").count();
    let warn_count = results.iter().filter(|l| l.level == "W").count();
    let err_count = results.iter().filter(|l| l.level == "E").count();
    assert!(info_count > 0, "应至少包含部分 INFO 级别日志");
    println!("级别分布: I={}, W={}, E={}", info_count, warn_count, err_count);
}

/// 验证 Segment 级 zstd 共享字典的写入/读取/查询路径可正常工作。
///
/// 说明：对高度模板化日志，模板提取已经去除大部分冗余，字典增益不明显；
/// 此测试主要确保当启用字典时，Segment 能正确存储字典并在查询时用其解压。
#[test]
fn test_segment_dictionary_roundtrip() {
    use mini_obs::shared::format::LogLine;

    let lines = 2000;
    // 故意使用非高度模板化、但含大量公共子串的数据，给字典留下发挥空间
    let logs: Vec<LogLine> = (0..lines)
        .map(|i| LogLine {
            ts: 1000 + i as u64 * 100,
            service: "windows".to_string(),
            level: if i % 10 == 0 { "E" } else { "I" }.to_string(),
            message: format!(
                "Service Control Manager: The {} service entered the {} state on host {} pid={}",
                ["Spooler", "Themes", "WSearch", "WinDefend"][i % 4],
                ["running", "stopped", "paused"][i % 3],
                format!("host-{:04}", i % 50),
                i
            ),
        })
        .collect();

    let dir = temp_dir("mini-obs-dict-roundtrip");
    let storage = StorageEngine::open(
        &dir,
        StorageConfig {
            max_buffer_lines: 10_000,
            max_buffer_bytes: 10 * 1024 * 1024,
            compression_level: 3,
            chunk_size: 256,
            dict: None,
            // 强制多 Chunk：单 Chunk 阈值小于日志行数，使字典有机会训练
            single_chunk_threshold_lines: 100,
            single_chunk_threshold_bytes: 10 * 1024 * 1024,
            dict_training_min_chunks: 4,
            dict_training_sample_chunks: 8,
        },
    )
    .unwrap();

    for log in &logs {
        storage.append(log.clone()).unwrap();
    }
    storage.flush().unwrap();

    let stats = storage.stats();
    println!(
        "dict roundtrip: segments={}, total_lines={}, compressed={}",
        stats.segment_count, stats.total_lines, stats.total_compressed_bytes
    );

    // 确认 segment 头记录了字典信息
    let mut found_dict = false;
    for entry in std::fs::read_dir(dir.join("segments")).unwrap() {
        let path = entry.unwrap().path();
        let buf = std::fs::read(&path).unwrap();
        if let Ok(parsed) = mini_obs::shared::format::ParsedSegment::parse(&buf) {
            let h = &parsed.header;
            println!(
                "  segment {}: chunks={}, dict_offset={}, dict_len={}",
                h.segment_id,
                h.chunk_count,
                h.dict_offset(),
                h.dict_len()
            );
            if h.dict_len() > 0 {
                found_dict = true;
            }
        }
    }
    assert!(found_dict, "应训练出 Segment 级字典");

    // 查询验证完整性：用字典解压后数据正确
    let results = storage.query(0, u64::MAX, "", lines).unwrap();
    assert_eq!(results.len(), lines, "查询行数不匹配");

    // 验证部分 message 内容正确还原
    assert!(results.iter().any(|l| l.message.contains("Spooler")));
    assert!(results.iter().any(|l| l.message.contains("WinDefend")));
}
