
// 将以下内容追加到 src/agent/compressor.rs 的 #[cfg(test)] mod tests 中

#[test]
fn test_compressor_empty_batch() {
    let comp = Compressor::new(CompressorConfig::default());
    let empty: Vec<LogLine> = vec![];
    let compressed = comp.compress_batch(&empty).unwrap();
    assert!(compressed.is_empty());
    let decompressed = comp.decompress_batch(&compressed).unwrap();
    assert!(decompressed.is_empty());
}

#[test]
fn test_compressor_json_fallback_roundtrip() {
    let comp = Compressor::new(CompressorConfig {
        enable_template: false,
        ..Default::default()
    });
    let logs = vec![
        make_log(1000, "svc", "I", "plain json fallback test"),
        make_log(2000, "svc", "W", "unicode 中文测试 🎉"),
    ];
    let compressed = comp.compress_batch(&logs).unwrap();
    let decompressed = comp.decompress_batch(&compressed).unwrap();
    assert_eq!(decompressed.len(), 2);
    assert_eq!(decompressed[0].message, "plain json fallback test");
    assert_eq!(decompressed[1].message, "unicode 中文测试 🎉");
}

#[test]
fn test_compressor_mixed_content() {
    let comp = Compressor::new(CompressorConfig::default());
    // 模板化日志 + 非模板化日志混合
    let logs = vec![
        make_log(1000, "svc", "I", "User 12345 logged in"),
        make_log(1100, "svc", "I", "User 67890 logged in"),
        make_log(1200, "svc", "E", "Completely unique and non-templatable error message xyz"),
        make_log(1300, "svc", "I", "User 11111 logged in"),
    ];
    let compressed = comp.compress_batch(&logs).unwrap();
    let decompressed = comp.decompress_batch(&compressed).unwrap();
    assert_eq!(decompressed.len(), 4);
    for (a, b) in logs.iter().zip(decompressed.iter()) {
        assert_eq!(a.ts, b.ts, "ts mismatch");
        assert_eq!(a.message, b.message, "message mismatch");
    }
}

#[test]
fn test_compressor_large_batch() {
    let comp = Compressor::new(CompressorConfig::default());
    let logs: Vec<LogLine> = (0..2000)
        .map(|i| make_log(
            1000 + i as u64 * 100,
            "svc",
            if i % 10 == 0 { "E" } else { "I" },
            &format!("Request {} processed in {}ms", i, i % 100),
        ))
        .collect();

    let compressed = comp.compress_batch(&logs).unwrap();
    let decompressed = comp.decompress_batch(&compressed).unwrap();
    assert_eq!(decompressed.len(), 2000);

    // 验证压缩比（模板化日志应显著压缩）
    let original_size: usize = logs.iter()
        .map(|l| serde_json::to_string(l).unwrap().len())
        .sum();
    let ratio = original_size as f64 / compressed.len() as f64;
    println!("Large batch compression ratio: {:.2}x", ratio);
    assert!(ratio > 2.0, "Expected compression ratio > 2x, got {:.2}x", ratio);
}

#[test]
fn test_compressor_compression_ratio_target() {
    // 模拟高重复度模板日志，验证能否达到 >10x
    let comp = Compressor::new(CompressorConfig::default());
    let template_msg = "User {id} performed action {action} on resource {resource} at {time} from {ip}";
    let logs: Vec<LogLine> = (0..5000)
        .map(|i| make_log(
            1000 + i as u64 * 1000,
            "auth",
            "I",
            &template_msg
                .replace("{id}", &format!("user_{:05}", i))
                .replace("{action}", "LOGIN")
                .replace("{resource}", &format!("res_{:03}", i % 100))
                .replace("{time}", "2026-05-15T09:24:00Z")
                .replace("{ip}", &format!("192.168.{}.{}", i % 256, (i / 256) % 256)),
        ))
        .collect();

    let compressed = comp.compress_batch(&logs).unwrap();
    let original_size: usize = logs.iter()
        .map(|l| serde_json::to_string(l).unwrap().len())
        .sum();
    let ratio = original_size as f64 / compressed.len() as f64;
    println!("Template-heavy compression ratio: {:.2}x", ratio);
    assert!(ratio > 5.0, "Expected compression ratio > 5x for templated logs, got {:.2}x", ratio);
}

#[test]
fn test_compressor_corrupted_data() {
    let comp = Compressor::new(CompressorConfig::default());
    let corrupted = vec![0xFFu8; 100]; // 非 Zstd 数据
    let result = comp.decompress_batch(&corrupted);
    assert!(result.is_err());
}

#[test]
fn test_compressor_with_dictionary() {
    // 训练一个简单的 Zstd 字典
    let samples: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            let log = make_log(1000 + i as u64 * 100, "svc", "I", &format!("Template log entry number {}", i));
            serde_json::to_vec(&log).unwrap()
        })
        .collect();

    let dict = zstd::dict::from_samples(&samples, 100_000).unwrap();
    let comp = Compressor::new(CompressorConfig {
        zstd_level: 3,
        dict: Some(dict),
        ..Default::default()
    });

    let test_logs = vec![
        make_log(5000, "svc", "I", "Template log entry number 9999"),
        make_log(5100, "svc", "I", "Template log entry number 10000"),
    ];

    let compressed = comp.compress_batch(&test_logs).unwrap();
    let decompressed = comp.decompress_batch(&compressed).unwrap();
    assert_eq!(decompressed.len(), 2);
    assert_eq!(decompressed[0].message, "Template log entry number 9999");
}

#[test]
fn test_compressor_single_log() {
    let comp = Compressor::new(CompressorConfig::default());
    let logs = vec![make_log(1000, "svc", "E", "single error")];
    let compressed = comp.compress_batch(&logs).unwrap();
    let decompressed = comp.decompress_batch(&compressed).unwrap();
    assert_eq!(decompressed.len(), 1);
    assert_eq!(decompressed[0].message, "single error");
}

#[test]
fn test_compressor_unicode_and_special_chars() {
    let comp = Compressor::new(CompressorConfig::default());
    let logs = vec![
        make_log(1000, "svc", "I", "Hello 世界 🌍"),
        make_log(1100, "svc", "I", "Path: C:\Users\Admin\file.txt"),
        make_log(1200, "svc", "E", "JSON: {"key": "value with \"quotes\"}"),
    ];
    let compressed = comp.compress_batch(&logs).unwrap();
    let decompressed = comp.decompress_batch(&compressed).unwrap();
    assert_eq!(decompressed.len(), 3);
    assert_eq!(decompressed[0].message, "Hello 世界 🌍");
    assert_eq!(decompressed[1].message, "Path: C:\Users\Admin\file.txt");
    assert_eq!(decompressed[2].message, "JSON: {"key": "value with \"quotes\"}");
}
