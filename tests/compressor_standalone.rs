//! Compressor 独立压缩效果测试
//!
//! 目的：
//! 1. 测量 **Compressor 单独输出**（未经过 Segment 打包）的大小。
//! 2. 验证模板提取 + XOR-P 编码是否真正降低了输入熵，从而让 zstd 发挥效果。
//! 3. 与 "原始字节 -> zstd" 以及 "JSON Lines -> zstd" 做对照。

use std::fs;
use std::path::PathBuf;

use mini_obs::agent::collector::parse_line;
use mini_obs::agent::compressor::{Compressor, CompressorConfig};
use mini_obs::shared::format::LogLine;

const WINDOWS_LOG_PATH: &str = "/tmp/Windows_2k.log";
const HDFS_LOG_PATH: &str = "tmp/HDFS_2k.log";

#[test]
fn test_compressor_standalone_compression_effectiveness_windows() {
    run_standalone_test(
        WINDOWS_LOG_PATH,
        "windows",
        "Windows_2k.log",
    );
}

#[test]
fn test_compressor_standalone_compression_effectiveness_hdfs() {
    run_standalone_test(
        HDFS_LOG_PATH,
        "hdfs",
        "HDFS_2k.log",
    );
}

fn run_standalone_test(path: &str, service: &str, label: &str) {
    // 1. 读取真实日志并解析为 LogLine
    let log_path = PathBuf::from(path);
    assert!(
        log_path.exists(),
        "测试日志 {} 不存在，请先准备该文件",
        path
    );

    let raw_text = fs::read_to_string(&log_path).expect("读取日志文件失败");
    let raw_bytes = raw_text.as_bytes();
    let raw_size = raw_bytes.len();

    let logs: Vec<LogLine> = raw_text
        .lines()
        .filter_map(|line| parse_line(line, service))
        .collect();

    assert!(
        !logs.is_empty(),
        "未能从 {} 解析出任何日志行",
        path
    );

    // 2. 计算各种“原始表示”的字节数
    let json_lines: Vec<String> = logs
        .iter()
        .map(|l| serde_json::to_string(l).unwrap())
        .collect();
    let json_lines_size: usize = json_lines.iter().map(|s| s.len() + 1).sum(); // +1 for '\n'

    let compact_json_lines: Vec<String> = logs
        .iter()
        .map(|l| {
            format!(
                "{{\"t\":{},\"s\":\"{}\",\"l\":\"{}\",\"m\":\"{}\"}}",
                l.ts,
                l.service,
                l.level,
                l.message.replace('\\', "\\\\").replace('"', "\\\"")
            )
        })
        .collect();
    let compact_json_size: usize = compact_json_lines.iter().map(|s| s.len() + 1).sum();

    // 3. 纯 zstd 对照组
    let pure_zstd_raw = zstd::encode_all(raw_bytes, 3).expect("zstd 压缩原始字节失败");
    let pure_zstd_json = zstd::encode_all(compact_json_lines.join("\n").as_bytes(), 3)
        .expect("zstd 压缩 JSON Lines 失败");

    // 4. Compressor：模板提取路径（默认）
    let compressor_template = Compressor::new(CompressorConfig::default());
    let compressed_template = compressor_template
        .compress_batch(&logs)
        .expect("Compressor 模板路径压缩失败");
    let decompressed_template = compressor_template
        .decompress_batch(&compressed_template)
        .expect("Compressor 模板路径解压失败");

    // 5. Compressor：JSON fallback 路径（禁用模板）
    let compressor_json = Compressor::new(CompressorConfig {
        enable_template: false,
        ..Default::default()
    });
    let compressed_json = compressor_json
        .compress_batch(&logs)
        .expect("Compressor JSON fallback 压缩失败");
    let decompressed_json = compressor_json
        .decompress_batch(&compressed_json)
        .expect("Compressor JSON fallback 解压失败");

    // 6. 计算压缩比
    let ratio_template = json_lines_size as f64 / compressed_template.len() as f64;
    let ratio_json_fallback = json_lines_size as f64 / compressed_json.len() as f64;
    let ratio_pure_zstd_raw = raw_size as f64 / pure_zstd_raw.len() as f64;
    let ratio_pure_zstd_json = compact_json_size as f64 / pure_zstd_json.len() as f64;

    // 7. 打印报告
    println!("\n========== Compressor 独立压缩效果报告 [{}] ==========", label);
    println!("日志行数:           {}", logs.len());
    println!(
        "原始文件大小:       {:10} bytes ({:.2} KB)",
        raw_size,
        raw_size as f64 / 1024.0
    );
    println!(
        "JSON Lines 表示:    {:10} bytes ({:.2} KB)",
        json_lines_size,
        json_lines_size as f64 / 1024.0
    );
    println!(
        "紧凑 JSON 表示:     {:10} bytes ({:.2} KB)",
        compact_json_size,
        compact_json_size as f64 / 1024.0
    );
    println!();
    println!(
        "纯 zstd(原始字节):  {:10} bytes ({:.2} KB), 压缩比: {:.2}x",
        pure_zstd_raw.len(),
        pure_zstd_raw.len() as f64 / 1024.0,
        ratio_pure_zstd_raw
    );
    println!(
        "纯 zstd(紧凑 JSON): {:10} bytes ({:.2} KB), 压缩比: {:.2}x",
        pure_zstd_json.len(),
        pure_zstd_json.len() as f64 / 1024.0,
        ratio_pure_zstd_json
    );
    println!(
        "Compressor(JSON):   {:10} bytes ({:.2} KB), 压缩比: {:.2}x",
        compressed_json.len(),
        compressed_json.len() as f64 / 1024.0,
        ratio_json_fallback
    );
    println!(
        "Compressor(模板):   {:10} bytes ({:.2} KB), 压缩比: {:.2}x",
        compressed_template.len(),
        compressed_template.len() as f64 / 1024.0,
        ratio_template
    );
    println!();
    println!(
        "模板 / JSON fallback 大小比: {:.1}%",
        (compressed_template.len() as f64 / compressed_json.len() as f64) * 100.0
    );
    println!(
        "Compressor(模板) / 纯 zstd(原始字节): {:.1}%",
        (compressed_template.len() as f64 / pure_zstd_raw.len() as f64) * 100.0
    );
    println!(
        "Compressor(模板) / 纯 zstd(紧凑 JSON): {:.1}%",
        (compressed_template.len() as f64 / pure_zstd_json.len() as f64) * 100.0
    );
    println!("==================================================\n");

    // 8. 断言：正确性
    assert_eq!(
        decompressed_template.len(),
        logs.len(),
        "模板路径解压后行数不匹配"
    );
    assert_eq!(
        decompressed_json.len(),
        logs.len(),
        "JSON fallback 解压后行数不匹配"
    );

    for (idx, (a, b)) in logs.iter().zip(decompressed_template.iter()).enumerate() {
        assert_eq!(a.ts, b.ts, "模板路径 ts 不匹配，索引 {}", idx);
        assert_eq!(a.level, b.level, "模板路径 level 不匹配，索引 {}", idx);
        assert_eq!(a.message, b.message, "模板路径 message 不匹配，索引 {}", idx);
    }

    for (idx, (a, b)) in logs.iter().zip(decompressed_json.iter()).enumerate() {
        assert_eq!(a.ts, b.ts, "JSON fallback ts 不匹配，索引 {}", idx);
        assert_eq!(a.level, b.level, "JSON fallback level 不匹配，索引 {}", idx);
        assert_eq!(a.message, b.message, "JSON fallback message 不匹配，索引 {}", idx);
    }

    // 9. 断言：压缩确实生效
    assert!(
        compressed_template.len() < raw_size,
        "Compressor 模板路径输出应小于原始文件大小"
    );
    assert!(
        compressed_json.len() < raw_size,
        "Compressor JSON fallback 输出应小于原始文件大小"
    );

    // 10. 断言：Compressor 独立输出应显著优于带 Segment 元数据的完整文件
    assert!(
        ratio_template >= 5.0,
        "模板路径压缩比应 >= 5x，实际 {:.2}x",
        ratio_template
    );
}

/// 使用高度模板化的合成日志，验证模板提取路径确实比 JSON fallback 更优。
#[test]
fn test_compressor_template_path_wins_on_templated_logs() {
    let template = "User {id} performed {action} on {resource} at {time} from {ip}";
    let logs: Vec<LogLine> = (0..2000)
        .map(|i| LogLine {
            ts: 1_000_000 + i as u64 * 1000,
            service: "auth".to_string(),
            level: if i % 10 == 0 { "E".to_string() } else { "I".to_string() },
            message: template
                .replace("{id}", &format!("user_{:05}", i))
                .replace("{action}", "LOGIN")
                .replace("{resource}", &format!("res_{:03}", i % 100))
                .replace("{time}", "2026-05-15T09:24:00Z")
                .replace("{ip}", &format!("192.168.{}.{}", i % 256, (i / 256) % 256)),
        })
        .collect();

    let compressor_template = Compressor::new(CompressorConfig::default());
    let compressed_template = compressor_template.compress_batch(&logs).unwrap();
    let decompressed_template = compressor_template.decompress_batch(&compressed_template).unwrap();

    let compressor_json = Compressor::new(CompressorConfig {
        enable_template: false,
        ..Default::default()
    });
    let compressed_json = compressor_json.compress_batch(&logs).unwrap();
    let decompressed_json = compressor_json.decompress_batch(&compressed_json).unwrap();

    assert_eq!(decompressed_template.len(), logs.len());
    assert_eq!(decompressed_json.len(), logs.len());

    for (a, b) in logs.iter().zip(decompressed_template.iter()) {
        assert_eq!(a.message, b.message);
    }

    println!("\n========== 高模板化日志 Compressor 对比 ==========");
    println!("模板路径大小:     {} bytes", compressed_template.len());
    println!("JSON fallback 大小: {} bytes", compressed_json.len());
    println!(
        "模板 / JSON fallback: {:.1}%",
        (compressed_template.len() as f64 / compressed_json.len() as f64) * 100.0
    );
    println!("==================================================\n");

    assert!(
        compressed_template.len() < compressed_json.len(),
        "高模板化日志中，模板路径应明显小于 JSON fallback"
    );
}
