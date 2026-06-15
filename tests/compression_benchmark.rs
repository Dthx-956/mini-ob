//! 多日志源压缩率基准测试 —— 三层对比
//!
//! 对 tmp/ 目录下的三类日志（Android, OpenSSH, OpenStack）分别执行三组测试：
//!
//! ① 纯 zstd（对照组）：           原始字节 → zstd::encode_all
//! ② 项目压缩逻辑（无 Segment 开销）：原始行 → Collector 解析 → Compressor::compress_batch
//! ③ 完整流水线（含 Segment 格式）：原始行 → Collector → StorageEngine → Segment 文件大小
//!
//! 通过 ①→② 对比验证预处理是否真正降低熵值；
//! 通过 ②→③ 对比量化 Segment 格式（Header/PatternTable/ChunkTable/Footer）的开销。

use std::fs;
use std::path::PathBuf;

use mini_obs::agent::{Compressor, CompressorConfig, StorageConfig, StorageEngine};
use mini_obs::shared::format::LogLine;

/// 被测日志文件列表（相对于项目根目录）
const LOG_FILES: &[(&str, &str)] = &[
    ("Android", "tmp/Android_2k.log"),
    ("OpenSSH", "tmp/OpenSSH_2k.log"),
    ("OpenStack", "tmp/OpenStack_2k.log"),
];

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

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

// ==================== 日志解析：模拟 Collector 的解析逻辑 ====================

/// 将原始文本行解析为 LogLine（使用与 Collector 相同的解析策略）
fn parse_log_line(line: &str, service: &str, default_ts: u64) -> Option<LogLine> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // 1. 尝试 JSON 解析（紧凑或标准字段）
    if line.starts_with('{') {
        if let Ok(log) = serde_json::from_str::<LogLine>(line) {
            return Some(log);
        }
        // 尝试标准字段名
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "lowercase")]
        struct StandardLog {
            timestamp: Option<u64>,
            service: Option<String>,
            level: Option<String>,
            message: Option<String>,
            ts: Option<u64>,
            s: Option<String>,
            l: Option<String>,
            m: Option<String>,
        }
        if let Ok(sl) = serde_json::from_str::<StandardLog>(line) {
            return Some(LogLine {
                ts: sl.ts.or(sl.timestamp).unwrap_or(default_ts),
                service: sl.s.or(sl.service).unwrap_or_else(|| service.to_string()),
                level: sl.l.or(sl.level).unwrap_or_else(|| "I".to_string()),
                message: sl.m.or(sl.message).unwrap_or_else(|| line.to_string()),
            });
        }
    }

    // 2. Nginx 启发式
    if line.contains("HTTP/") {
        return Some(LogLine {
            ts: default_ts,
            service: "nginx".to_string(),
            level: "I".to_string(),
            message: line.to_string(),
        });
    }

    // 3. 降级：关键词推断级别
    let level = if line.contains("ERROR") || line.contains("Error") || line.contains("error") {
        "E"
    } else if line.contains("WARN") || line.contains("Warn") || line.contains("warn") {
        "W"
    } else if line.contains("DEBUG") || line.contains("Debug") {
        "D"
    } else {
        "I"
    };

    Some(LogLine {
        ts: default_ts,
        service: service.to_string(),
        level: level.to_string(),
        message: line.to_string(),
    })
}

/// 对单个日志文件执行三层压缩对比测试
fn run_full_benchmark(name: &str, log_path: PathBuf) -> FullBenchmarkResult {
    // ── 1. 读取原始日志 ──
    let raw_bytes = fs::read(&log_path).expect(&format!("读取 {} 失败", log_path.display()));
    let raw_size = raw_bytes.len();
    assert!(raw_size > 0, "{} 日志为空", name);

    let raw_text = String::from_utf8_lossy(&raw_bytes).to_string();
    let all_lines: Vec<&str> = raw_text.lines().filter(|l| !l.trim().is_empty()).collect();
    let line_count = all_lines.len();

    // ── 2. 解析所有日志行为 LogLine ──
    // 模拟 Collector 的时间戳递增（没有真实时间戳的文件逐行 +1ms）
    let base_ts = 1_000_000u64;
    let logs: Vec<LogLine> = all_lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| parse_log_line(line, &name.to_lowercase(), base_ts + i as u64))
        .collect();
    let parsed_count = logs.len();
    assert!(parsed_count > 0, "{} 解析后日志为空", name);

    // ── 3. ① 纯 zstd 压缩（对照组）──
    let pure_zstd_bytes = zstd::encode_all(&raw_bytes[..], 3).expect("纯 zstd 压缩失败");
    let pure_zstd_size = pure_zstd_bytes.len();
    let pure_zstd_ratio = raw_size as f64 / pure_zstd_size as f64;

    // ── 4. ② 项目压缩逻辑（Compressor::compress_batch，无 Segment 开销）──
    // 这测量的是：模板提取 + XOR-P + 二进制序列化 + Zstd 的实际效果
    let compressor = Compressor::new(CompressorConfig {
        zstd_level: 3,
        enable_template: true,
        xor_ref_reset: 16,
        dict: None,
    });
    let preprocess_zstd_bytes = compressor
        .compress_batch(&logs)
        .expect("项目压缩逻辑失败");
    let preprocess_zstd_size = preprocess_zstd_bytes.len();
    let preprocess_zstd_ratio = raw_size as f64 / preprocess_zstd_size as f64;
    // 预处理效率：预处理后体积 vs 纯 zstd 体积
    // >100% = 预处理比纯 zstd 更好（不太可能，但意味着模板提取极有效）
    // <100% = 预处理在 zstd 之上有额外开销
    let preprocess_efficiency = (preprocess_zstd_ratio / pure_zstd_ratio) * 100.0;

    // 验证可完整解压
    let decompressed = compressor
        .decompress_batch(&preprocess_zstd_bytes)
        .expect("项目压缩解压失败");
    let preprocess_roundtrip_ok = decompressed.len() == parsed_count;

    // ── 5. ③ 完整流水线（StorageEngine → Segment 文件）──
    let data_dir = temp_dir(&format!("mini-obs-full-{}", name.to_lowercase()));
    let storage = StorageEngine::open(
        &data_dir,
        StorageConfig {
            max_buffer_lines: 10_000,
            max_buffer_bytes: 5 * 1024 * 1024,
            compression_level: 3,
            chunk_size: 256,
            dict: None,
            single_chunk_threshold_lines: 1_000,
            single_chunk_threshold_bytes: 1 * 1024 * 1024,
            dict_training_min_chunks: 4,
            dict_training_sample_chunks: 8,
        },
    )
    .expect("打开 StorageEngine 失败");

    // 直接将 LogLine 写入 storage（跳过 Collector，避免 tail -f 的复杂性）
    for log in &logs {
        storage.append(log.clone()).expect("Storage append 失败");
    }
    storage.flush().expect("flush 失败");

    // 统计 Segment 文件大小
    let segments_dir = data_dir.join("segments");
    let mut segment_size = 0u64;
    let mut segment_count = 0u32;
    if segments_dir.exists() {
        for entry in fs::read_dir(&segments_dir).expect("读取 segments 目录失败") {
            let entry = entry.expect("读取目录项失败");
            segment_size += entry.metadata().expect("读取文件元数据失败").len();
            segment_count += 1;
        }
    }

    // 统计元数据（index 目录）
    let index_dir = data_dir.join("index");
    let mut metadata_size = 0u64;
    if index_dir.exists() {
        for entry in fs::read_dir(&index_dir).expect("读取 index 目录失败") {
            let entry = entry.expect("读取目录项失败");
            metadata_size += entry.metadata().expect("读取文件元数据失败").len();
        }
    }

    let total_pipeline_size = segment_size + metadata_size;
    let pipeline_ratio = raw_size as f64 / segment_size as f64;
    let pipeline_total_ratio = raw_size as f64 / total_pipeline_size as f64;
    let pipeline_efficiency = (pipeline_ratio / pure_zstd_ratio) * 100.0;
    // Segment 格式开销：完整流水线比纯压缩逻辑多出的体积占比
    let segment_overhead_pct = if preprocess_zstd_size > 0 {
        ((segment_size as f64 - preprocess_zstd_size as f64) / preprocess_zstd_size as f64) * 100.0
    } else {
        0.0
    };

    // ── 6. 查询完整性 ──
    let stats = storage.stats();
    let results = storage
        .query(0, u64::MAX, "", line_count + 100)
        .expect("查询失败");
    let query_ok = results.len() == line_count;

    // ── 7. 日志级别分布 ──
    let info_count = results.iter().filter(|l| l.level == "I").count();
    let warn_count = results.iter().filter(|l| l.level == "W").count();
    let err_count = results.iter().filter(|l| l.level == "E").count();
    let debug_count = results.iter().filter(|l| l.level == "D").count();

    // ── 8. 分解：仅 JSON Lines + zstd（不使用模板）──
    let compressor_no_tpl = Compressor::new(CompressorConfig {
        zstd_level: 3,
        enable_template: false,
        xor_ref_reset: 16,
        dict: None,
    });
    let json_zstd_bytes = compressor_no_tpl
        .compress_batch(&logs)
        .expect("JSON+zstd 压缩失败");
    let json_zstd_size = json_zstd_bytes.len();
    let json_zstd_ratio = raw_size as f64 / json_zstd_size as f64;

    FullBenchmarkResult {
        name: name.to_string(),
        raw_size,
        raw_size_kb: raw_size as f64 / 1024.0,
        line_count,
        parsed_count,
        // ① 纯 zstd
        pure_zstd_size,
        pure_zstd_ratio,
        // ② 项目压缩逻辑（模板 + XOR-P + zstd）
        preprocess_zstd_size,
        preprocess_zstd_ratio,
        preprocess_efficiency,
        preprocess_roundtrip_ok,
        // ②-b 仅 JSON Lines + zstd（无模板，作为对比）
        json_zstd_size,
        json_zstd_ratio,
        // ③ 完整流水线
        segment_size,
        metadata_size,
        total_pipeline_size,
        pipeline_ratio,
        pipeline_total_ratio,
        pipeline_efficiency,
        segment_count,
        segment_overhead_pct,
        // 统计
        stats_total_lines: stats.total_lines,
        query_returned: results.len(),
        query_ok,
        level_distribution: LevelDist {
            debug: debug_count,
            info: info_count,
            warn: warn_count,
            error: err_count,
        },
    }
}

#[derive(Debug)]
struct LevelDist {
    debug: usize,
    info: usize,
    warn: usize,
    error: usize,
}

#[derive(Debug)]
struct FullBenchmarkResult {
    name: String,
    raw_size: usize,
    raw_size_kb: f64,
    line_count: usize,
    parsed_count: usize,
    // ①
    pure_zstd_size: usize,
    pure_zstd_ratio: f64,
    // ②
    preprocess_zstd_size: usize,
    preprocess_zstd_ratio: f64,
    preprocess_efficiency: f64,
    preprocess_roundtrip_ok: bool,
    // ②-b
    json_zstd_size: usize,
    json_zstd_ratio: f64,
    // ③
    segment_size: u64,
    metadata_size: u64,
    total_pipeline_size: u64,
    pipeline_ratio: f64,
    pipeline_total_ratio: f64,
    pipeline_efficiency: f64,
    segment_count: u32,
    segment_overhead_pct: f64,
    // stats
    stats_total_lines: u64,
    query_returned: usize,
    query_ok: bool,
    level_distribution: LevelDist,
}

// ==================== 打印函数 ====================

fn print_detailed_report(r: &FullBenchmarkResult) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════╗");
    println!("║                    📁 {} 压缩率详细分析报告                              ║", r.name);
    println!("╠══════════════════════════════════════════════════════════════════════════╣");
    println!("║  输入统计                                                                ║");
    println!("║    原始大小:     {:>10} bytes ({:>8.2} KB)                               ║", r.raw_size, r.raw_size_kb);
    println!("║    文件行数:     {:>10}                                                  ║", r.line_count);
    println!("║    解析行数:     {:>10}                                                  ║", r.parsed_count);
    println!("╠══════════════════════════════════════════════════════════════════════════╣");
    println!("║  ① 纯 zstd（基线）                                                       ║");
    println!("║    压缩后:       {:>10} bytes ({:>8.2} KB)                               ║", r.pure_zstd_size, r.pure_zstd_size as f64 / 1024.0);
    println!("║    压缩比:       {:>10.2}x  ◀── 理论上界                                 ║", r.pure_zstd_ratio);
    println!("╠══════════════════════════════════════════════════════════════════════════╣");
    println!("║  ②-b 仅 JSON Lines + zstd（无模板，回退路径）                              ║");
    println!("║    压缩后:       {:>10} bytes ({:>8.2} KB)                               ║", r.json_zstd_size, r.json_zstd_size as f64 / 1024.0);
    println!("║    压缩比:       {:>10.2}x                                               ║", r.json_zstd_ratio);
    println!("╠══════════════════════════════════════════════════════════════════════════╣");
    println!("║  ② 项目压缩逻辑（模板提取 + XOR-P + zstd，无 Segment 开销）               ║");
    println!("║    压缩后:       {:>10} bytes ({:>8.2} KB)                               ║", r.preprocess_zstd_size, r.preprocess_zstd_size as f64 / 1024.0);
    println!("║    压缩比:       {:>10.2}x                                               ║", r.preprocess_zstd_ratio);
    println!("║    vs 纯 zstd:   {:>10.1}%  ◀── 预处理有效性                             ║", r.preprocess_efficiency);
    println!("║    解压完整性:   {:>10}                                                  ║", if r.preprocess_roundtrip_ok { "✅ 通过" } else { "❌ 失败" });
    println!("╠══════════════════════════════════════════════════════════════════════════╣");
    println!("║  ③ 完整流水线（含 Segment 格式：Header + PatternTable + ChunkTable + Footer）");
    println!("║    Segment 文件: {:>10} bytes ({:>8.2} KB)                               ║", r.segment_size, r.segment_size as f64 / 1024.0);
    println!("║    元数据:       {:>10} bytes ({:>8.2} KB)                               ║", r.metadata_size, r.metadata_size as f64 / 1024.0);
    println!("║    总占用:       {:>10} bytes ({:>8.2} KB)                               ║", r.total_pipeline_size, r.total_pipeline_size as f64 / 1024.0);
    println!("║    压缩比:       {:>10.2}x (segment) / {:>5.2}x (含元数据)               ║", r.pipeline_ratio, r.pipeline_total_ratio);
    println!("║    vs 纯 zstd:   {:>10.1}%  ◀── 端到端效率                               ║", r.pipeline_efficiency);
    println!("║    Segment 数:   {:>10}                                                  ║", r.segment_count);
    println!("║    Segment 开销: {:>10.1}% (相比纯压缩逻辑额外体积)                       ║", r.segment_overhead_pct);
    println!("╠══════════════════════════════════════════════════════════════════════════╣");
    println!("║  查询验证                                                                ║");
    println!("║    查询返回:     {:>10} / {}  {}", r.query_returned, r.line_count,
        if r.query_ok { "✅" } else { "❌" });
    println!("║    级别分布:     D={} I={} W={} E={}                                      ║",
        r.level_distribution.debug, r.level_distribution.info,
        r.level_distribution.warn, r.level_distribution.error);
    println!("╚══════════════════════════════════════════════════════════════════════════╝");
}

// ==================== 测试用例 ====================

#[test]
fn test_android_2k_compression() {
    let path = project_root().join("tmp/Android_2k.log");
    assert!(path.exists(), "Android 日志文件不存在: {}", path.display());
    let result = run_full_benchmark("Android", path);
    print_detailed_report(&result);

    assert!(result.preprocess_roundtrip_ok, "Android: 压缩逻辑解压失败");
    assert!(result.query_ok, "Android: 查询完整性检查失败");
    assert!(result.pipeline_ratio >= 1.5, "Android: 完整流水线压缩比过低 {:.2}x", result.pipeline_ratio);
    // 预处理有效性：模板提取不应让压缩比降到纯 zstd 的 15% 以下
    assert!(result.preprocess_efficiency >= 15.0,
        "Android: 预处理效率过低 {:.1}%", result.preprocess_efficiency);
}

#[test]
fn test_openssh_2k_compression() {
    let path = project_root().join("tmp/OpenSSH_2k.log");
    assert!(path.exists(), "OpenSSH 日志文件不存在: {}", path.display());
    let result = run_full_benchmark("OpenSSH", path);
    print_detailed_report(&result);

    assert!(result.preprocess_roundtrip_ok, "OpenSSH: 压缩逻辑解压失败");
    assert!(result.query_ok, "OpenSSH: 查询完整性检查失败");
    assert!(result.pipeline_ratio >= 1.5, "OpenSSH: 完整流水线压缩比过低 {:.2}x", result.pipeline_ratio);
    assert!(result.preprocess_efficiency >= 15.0,
        "OpenSSH: 预处理效率过低 {:.1}%", result.preprocess_efficiency);
}

#[test]
fn test_openstack_2k_compression() {
    let path = project_root().join("tmp/OpenStack_2k.log");
    assert!(path.exists(), "OpenStack 日志文件不存在: {}", path.display());
    let result = run_full_benchmark("OpenStack", path);
    print_detailed_report(&result);

    assert!(result.preprocess_roundtrip_ok, "OpenStack: 压缩逻辑解压失败");
    assert!(result.query_ok, "OpenStack: 查询完整性检查失败");
    assert!(result.pipeline_ratio >= 1.5, "OpenStack: 完整流水线压缩比过低 {:.2}x", result.pipeline_ratio);
    assert!(result.preprocess_efficiency >= 15.0,
        "OpenStack: 预处理效率过低 {:.1}%", result.preprocess_efficiency);
}

#[test]
fn test_all_three_logs_summary() {
    let mut results = Vec::new();

    for (name, rel_path) in LOG_FILES {
        let path = project_root().join(rel_path);
        if !path.exists() {
            println!("[SKIP] {}: 文件不存在 {}", name, path.display());
            continue;
        }
        let result = run_full_benchmark(name, path);
        print_detailed_report(&result);
        results.push(result);
    }

    assert_eq!(results.len(), 3, "应有 3 个日志文件的测试结果");

    // ═══════════════════════════════════════════════════════════════════
    // 汇总对比表：三层拆解
    // ═══════════════════════════════════════════════════════════════════
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                                          📊 三日志三层压缩对比汇总                                          ║");
    println!("╠═══════════╦══════════╦════════════╦══════════════╦══════════════╦══════════════╦══════════════╦═══════════════╣");
    println!("║           ║          ║   ① 纯zstd ║ ②-b JSON+zstd║ ② 模板+zstd  ║ ③ 完整流水线║ 预处理效率   ║ Segment开销   ║");
    println!("║  日志源   ║ 原始(KB) ║   压缩比    ║   压缩比      ║   压缩比      ║  Seg压缩比   ║  vs纯zstd    ║  vs纯压缩逻辑 ║");
    println!("╠═══════════╬══════════╬════════════╬══════════════╬══════════════╬══════════════╬══════════════╬═══════════════╣");
    for r in &results {
        println!(
            "║ {:9} ║ {:6.1} KB ║  {:5.2}x     ║  {:5.2}x      ║  {:5.2}x      ║  {:5.2}x      ║  {:5.1}%      ║  {:5.1}%      ║",
            r.name,
            r.raw_size_kb,
            r.pure_zstd_ratio,
            r.json_zstd_ratio,
            r.preprocess_zstd_ratio,
            r.pipeline_ratio,
            r.preprocess_efficiency,
            r.segment_overhead_pct,
        );
    }
    println!("╚═══════════╩══════════╩════════════╩══════════════╩══════════════╩══════════════╩══════════════╩═══════════════╝");

    // 关键指标
    let avg_preprocess_eff: f64 =
        results.iter().map(|r| r.preprocess_efficiency).sum::<f64>() / results.len() as f64;
    let avg_segment_overhead: f64 =
        results.iter().map(|r| r.segment_overhead_pct).sum::<f64>() / results.len() as f64;
    let avg_json_vs_template: f64 = results
        .iter()
        .map(|r| {
            if r.json_zstd_size > 0 {
                (1.0 - r.preprocess_zstd_size as f64 / r.json_zstd_size as f64) * 100.0
            } else {
                0.0
            }
        })
        .sum::<f64>()
        / results.len() as f64;

    println!();
    println!("  ┌─────────────────────────────────────────────────────────────┐");
    println!("  │  关键指标汇总                                               │");
    println!("  ├─────────────────────────────────────────────────────────────┤");
    println!("  │  平均预处理效率 (② vs ①):     {:>6.1}%                       │", avg_preprocess_eff);
    println!("  │  平均 Segment 格式开销:        {:>6.1}%                       │", avg_segment_overhead);
    println!("  │  模板 vs 纯 JSON+zstd 收益:    {:>6.1}% (模板减少的体积)     │", avg_json_vs_template);
    println!("  └─────────────────────────────────────────────────────────────┘");

    // 如果 ② < ②-b（即模板反而变大了），说明模板对这类日志无效
    if avg_json_vs_template < 0.0 {
        println!("  ⚠️  模板提取未能进一步压缩，JSON Lines + zstd 回退路径反而更优");
    } else {
        println!("  ✅ 模板提取在 zstd 基础上进一步压缩了 {:.1}% 体积", avg_json_vs_template);
    }

    // 如果 ① > ②（即纯净 zstd 比模板预处理更好），说明日志模板化程度不够
    if avg_preprocess_eff < 50.0 {
        println!(
            "  📝 预处理效率 {:.1}% < 50%：日志模板化程度有限，预处理+二进制格式引入额外开销",
            avg_preprocess_eff
        );
    }

    assert!(avg_preprocess_eff >= 10.0, "预处理效率过低: {:.1}%", avg_preprocess_eff);
    assert!(avg_segment_overhead < 200.0, "Segment 格式开销过大: {:.1}%", avg_segment_overhead);
}
