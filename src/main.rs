//! mini-obs 命令行入口 (v2 格式)
//!
//! 子命令：
//!   agent   <data-dir> <service> <log-file>        启动采集代理（前台运行）
//!   query   <data-dir> <start> <end> [keyword] [limit] 查询存储的日志
//!   generate <count> <output> [service]            生成测试日志文件
//!   stats   <data-dir>                             显示存储统计

use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mini_obs::agent::{
    Collector, CollectorConfig, SourceType, StorageConfig, StorageEngine,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_usage() {
    eprintln!("Mini-OBS Edge Log Agent  v{}", VERSION);
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  mini-obs agent   <data-dir> <service-name> <log-file>      Run agent (tail mode)");
    eprintln!("  mini-obs query   <data-dir> <start-ts> <end-ts> [keyword] [limit]  Query logs");
    eprintln!("  mini-obs generate <count> <output-file> [service-name]     Generate test logs");
    eprintln!("  mini-obs stats   <data-dir>                                Show storage stats");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  mini-obs agent /data/mini-obs nginx /var/log/nginx/access.log");
    eprintln!("  mini-obs query /data/mini-obs 0 9999999999999 ERROR 50");
    eprintln!("  mini-obs generate 10000 /tmp/test.log my-service");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "agent" => cmd_agent(&args),
        "query" => cmd_query(&args),
        "generate" => cmd_generate(&args),
        "stats" => cmd_stats(&args),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

/// 启动采集代理：tail 日志文件 -> 压缩 -> 存储
fn cmd_agent(args: &[String]) -> io::Result<()> {
    if args.len() < 5 {
        eprintln!("Usage: mini-obs agent <data-dir> <service-name> <log-file>");
        process::exit(1);
    }

    let data_dir = &args[2];
    let service = &args[3];
    let source_file = &args[4];

    println!(
        "[mini-obs] Starting agent: dir={}, service={}, source={}",
        data_dir, service, source_file
    );

    let storage = StorageEngine::open(
        data_dir,
        StorageConfig {
            max_buffer_lines: 1000,
            max_buffer_bytes: 64 * 1024,
            compression_level: 3,
            chunk_size: 256,
            dict: None,
        },
    )?;

    let (collector, rx) = Collector::start(CollectorConfig {
        source: SourceType::File {
            path: Path::new(source_file).to_path_buf(),
        },
        poll_interval: Duration::from_millis(100),
        service_name: service.clone(),
    })?;

    println!("[mini-obs] Agent running. Press Ctrl+C to stop.");

    // 桥接：从 collector 接收，写入 storage
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(log) => {
                if let Err(e) = storage.append(log) {
                    eprintln!("[mini-obs] Storage error: {}", e);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    println!("[mini-obs] Collector disconnected, shutting down.");
    collector.stop();
    Ok(())
}

/// 查询已存储的日志
fn cmd_query(args: &[String]) -> io::Result<()> {
    if args.len() < 5 {
        eprintln!("Usage: mini-obs query <data-dir> <start-ts> <end-ts> [keyword] [limit]");
        process::exit(1);
    }

    let data_dir = &args[2];
    let start: u64 = args[3]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid start timestamp"))?;
    let end: u64 = args[4]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid end timestamp"))?;
    let keyword = args.get(5).map(|s| s.as_str()).unwrap_or("");
    let limit: usize = args
        .get(6)
        .map(|s| {
            s.parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid limit"))
        })
        .transpose()?
        .unwrap_or(100);

    let engine = StorageEngine::open(data_dir, StorageConfig::default())?;
    let results = engine.query(start, end, keyword, limit)?;

    println!("[mini-obs] Query returned {} results:", results.len());
    for log in results {
        println!(
            "[{}] [{}] {}: {}",
            format_ts(log.ts),
            log.service,
            log.level,
            log.message
        );
    }

    Ok(())
}

/// 生成测试日志文件（JSON Lines 格式）
fn cmd_generate(args: &[String]) -> io::Result<()> {
    if args.len() < 4 {
        eprintln!("Usage: mini-obs generate <count> <output-file> [service-name]");
        process::exit(1);
    }

    let count: usize = args[2]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid count"))?;
    let output = &args[3];
    let service = args.get(4).map(|s| s.as_str()).unwrap_or("app");

    let mut file = std::fs::File::create(output)?;
    let messages = [
        "User login successful",
        "Connection timeout after 3000ms",
        "Query executed in 45ms",
        "Cache miss for key user:12345",
        "Payment processed: $99.99",
        "Health check passed",
        "ERROR: null pointer exception at line 42",
        "WARN: retry attempt 3/3",
        "Config reloaded successfully",
    ];

    let base_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    for i in 0..count {
        let ts = base_ts + i as u64 * 100;
        let msg = messages[i % messages.len()];
        let lvl = if msg.contains("ERROR") {
            "E"
        } else if msg.contains("WARN") {
            "W"
        } else {
            "I"
        };
        let line = format!(
            r#"{{"t":{},"s":"{}","l":"{}","m":"{} [seq={}]"}}"#,
            ts, service, lvl, msg, i
        );
        writeln!(file, "{}", line)?;
    }

    println!("[mini-obs] Generated {} lines to {}", count, output);
    Ok(())
}

/// 显示存储统计
fn cmd_stats(args: &[String]) -> io::Result<()> {
    if args.len() < 3 {
        eprintln!("Usage: mini-obs stats <data-dir>");
        process::exit(1);
    }

    let data_dir = &args[2];
    let engine = StorageEngine::open(data_dir, StorageConfig::default())?;
    let stats = engine.stats();

    println!("[mini-obs] Storage Statistics:");
    println!("  Segments:      {}", stats.segment_count);
    println!("  Total lines:   {}", stats.total_lines);
    println!(
        "  Buffered:      {} lines ({} bytes)",
        stats.buffered_lines, stats.buffered_bytes
    );
    println!("  Original:      {} bytes", stats.total_original_bytes);
    println!("  Compressed:    {} bytes", stats.total_compressed_bytes);
    if stats.total_compressed_bytes > 0 {
        println!(
            "  Ratio:         {:.2}x",
            stats.total_original_bytes as f64 / stats.total_compressed_bytes as f64
        );
    }

    Ok(())
}

/// 格式化时间戳（Unix millis -> 可读字符串）
fn format_ts(ts: u64) -> String {
    let secs = ts / 1000;
    let ms = ts % 1000;
    // 简化输出：秒.毫秒，课程项目无需完整日期解析
    format!("{}.{}", secs, ms)
}
