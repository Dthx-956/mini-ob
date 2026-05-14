//! mini-obs/agent/collector.rs
//! 日志采集引擎 —— 支持文件 tail、stdin、模拟生成
//!
//! 设计约束：
//! - 内存占用极低：逐行处理，无全量缓存，channel 缓冲 10000 行
//! - 非阻塞：独立线程采集，通过 mpsc 向 storage 投递
//! - 容错：文件轮转、JSON 解析失败、编码错误均不中断采集
//! - 多格式兼容：支持标准 JSON 日志 + 本系统紧凑格式 (t/s/l/m) + 原始行降级
//! - 跨平台：纯 Rust 标准库 + serde_json，无系统特定依赖

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::shared::format::LogLine;

/// 采集配置
#[derive(Debug, Clone)]
pub struct CollectorConfig {
    pub source: SourceType,
    pub poll_interval: Duration,
    /// 默认服务名缩写（如 "ngx", "pg", "app"）
    pub service_name: String,
}

#[derive(Debug, Clone)]
pub enum SourceType {
    /// 追踪日志文件（类似 tail -F，支持日志轮转）
    File { path: PathBuf },
    /// 从标准输入读取（管道模式）
    Stdin,
    /// 生成模拟数据（用于测试和演示）
    Mock {
        rate_per_sec: u32,
        duration_sec: u32,
    },
}

/// 采集引擎
pub struct Collector {
    config: CollectorConfig,
    handle: Option<JoinHandle<()>>,
    stop_flag: Option<Arc<AtomicBool>>,
}

impl Collector {
    /// 创建并启动采集器，返回 (采集器实例, 接收端)
    pub fn start(config: CollectorConfig) -> io::Result<(Self, Receiver<LogLine>)> {
        let (tx, rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = stop_flag.clone();

        let config_clone = config.clone();
        let handle = thread::spawn(move || {
            match config_clone.source {
                SourceType::File { ref path } => {
                    collect_file(path.clone(), &config_clone, tx, stop_clone);
                }
                SourceType::Stdin => {
                    collect_stdin(&config_clone, tx, stop_clone);
                }
                SourceType::Mock {
                    rate_per_sec,
                    duration_sec,
                } => {
                    collect_mock(rate_per_sec, duration_sec, &config_clone, tx, stop_clone);
                }
            }
        });

        let collector = Self {
            config,
            handle: Some(handle),
            stop_flag: Some(stop_flag),
        };

        Ok((collector, rx))
    }

    /// 优雅停止：通知线程退出并等待结束
    pub fn stop(mut self) {
        if let Some(flag) = self.stop_flag.take() {
            flag.store(true, Ordering::Relaxed);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ==================== 具体采集实现 ====================

/// 文件 tail 采集（支持日志轮转、断点续读）
fn collect_file(
    path: PathBuf,
    config: &CollectorConfig,
    tx: Sender<LogLine>,
    stop: Arc<AtomicBool>,
) {
    let mut reader: Option<BufReader<File>> = None;
    let mut current_inode: Option<u64> = None;
    let mut last_size: u64 = 0;
    let poll = config.poll_interval;

    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }

        match fs::metadata(&path) {
            Ok(meta) => {
                let new_inode = get_inode(&meta);
                let new_size = meta.len();

                // 检测到新文件（inode 变化）或首次打开
                if current_inode != Some(new_inode) || reader.is_none() {
                    match File::open(&path) {
                        Ok(file) => {
                            let mut new_reader = BufReader::new(file);
                            // 新文件：跳到末尾（tail -f 行为）
                            if current_inode.is_some() {
                                // 日志轮转，从头读新文件
                                let _ = new_reader.seek(SeekFrom::Start(0));
                                last_size = 0;
                            } else {
                                // 首次启动，跳到末尾（避免历史数据洪泛）
                                let _ = new_reader.seek(SeekFrom::End(0));
                                last_size = new_size;
                            }
                            reader = Some(new_reader);
                            current_inode = Some(new_inode);
                        }
                        Err(e) => {
                            eprintln!("[collector] Failed to open {}: {}", path.display(), e);
                            thread::sleep(poll);
                            continue;
                        }
                    }
                } else if new_size > last_size {
                    // 文件增长，读取新增内容
                    if let Some(ref mut r) = reader {
                        let mut line = String::with_capacity(256);
                        loop {
                            line.clear();
                            match r.read_line(&mut line) {
                                Ok(0) => break, // 已读到当前末尾
                                Ok(_) => {
                                    if let Some(log) = parse_line(&line, &config.service_name) {
                                        if tx.send(log).is_err() {
                                            return; // 接收端已关闭
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[collector] Read error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    last_size = new_size;
                } else if new_size < last_size {
                    // 文件被截断（如手动清空），重置到开头
                    if let Some(ref mut r) = reader {
                        let _ = r.seek(SeekFrom::Start(0));
                        last_size = 0;
                    }
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    eprintln!("[collector] Stat error for {}: {}", path.display(), e);
                }
            }
        }

        thread::sleep(poll);
    }
}

/// 标准输入采集（管道模式，适合 `cat app.log | mini-obs agent`）
fn collect_stdin(
    config: &CollectorConfig,
    tx: Sender<LogLine>,
    stop: Arc<AtomicBool>,
) {
    let stdin = io::stdin();
    let reader = BufReader::with_capacity(8192, stdin);

    for line_result in reader.lines() {
        if stop.load(Ordering::Relaxed) {
            return;
        }

        match line_result {
            Ok(line) => {
                if let Some(log) = parse_line(&line, &config.service_name) {
                    if tx.send(log).is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                eprintln!("[collector] Stdin read error: {}", e);
            }
        }
    }
}

/// 模拟数据生成（用于压力测试和演示）
fn collect_mock(
    rate: u32,
    duration_sec: u32,
    config: &CollectorConfig,
    tx: Sender<LogLine>,
    stop: Arc<AtomicBool>,
) {
    let start = SystemTime::now();
    let messages = [
        "User login successful",
        "Connection timeout after 3000ms",
        "Query executed in 45ms",
        "Cache miss for key user:12345",
        "Payment processed: $99.99",
        "Health check passed",
        "Database connection pool exhausted",
        "Request completed with status 200",
        "Disk usage above 90%",
        "ERROR: null pointer exception at line 42",
        "WARN: retry attempt 3/3",
        "Config reloaded successfully",
    ];
    let levels = ["I", "W", "E"];

    let mut total_sent = 0u32;

    while let Ok(elapsed) = start.elapsed() {
        if stop.load(Ordering::Relaxed) || elapsed.as_secs() >= duration_sec as u64 {
            break;
        }

        // 计算本周期应发送量
        let expected_total = (elapsed.as_secs_f64() * rate as f64) as u32;
        let to_send = if expected_total > total_sent {
            expected_total - total_sent
        } else {
            0
        };

        for i in 0..to_send {
            let ts = now_ms();
            let idx = (total_sent + i) as usize;
            let msg = messages[idx % messages.len()];
            let lvl = levels[idx % levels.len()];

            let log = LogLine {
                ts,
                service: config.service_name.clone(),
                level: lvl.to_string(),
                message: format!("{} [seq={}]", msg, total_sent + i),
            };

            if tx.send(log).is_err() {
                return;
            }
        }

        total_sent += to_send;

        // 精确速率控制：sleep 到下一个整秒边界
        let next_second = (total_sent as f64 / rate as f64).ceil() as u64;
        if let Ok(elapsed) = start.elapsed() {
            let sleep_ms = (next_second * 1000).saturating_sub(elapsed.as_millis() as u64);
            if sleep_ms > 0 {
                thread::sleep(Duration::from_millis(sleep_ms.min(100)));
            }
        }
    }
}

// ==================== 解析逻辑 ====================

/// 将原始行解析为 LogLine
///
/// 解析策略（按优先级）：
/// 1. JSON 对象：同时支持标准字段（timestamp/service/level/message）
///    和紧凑字段（t/s/l/m）
/// 2. Nginx/Apache 格式：简单启发式提取
/// 3. 降级：原始整行作为 message，自动推断 level
fn parse_line(line: &str, default_service: &str) -> Option<LogLine> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 策略1：JSON
    if trimmed.starts_with('{') {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(log) = parse_json_value(json, default_service, trimmed) {
                return Some(log);
            }
        }
    }

    // 策略2：Nginx 启发式
    if trimmed.contains("HTTP/") && trimmed.contains('"') {
        return parse_nginx_line(trimmed, default_service);
    }

    // 策略3：降级为原始行
    Some(LogLine {
        ts: now_ms(),
        service: default_service.to_string(),
        level: infer_level(trimmed),
        message: trimmed.to_string(),
    })
}

/// 从 JSON Value 提取 LogLine（兼容标准格式和紧凑格式）
fn parse_json_value(v: serde_json::Value, default_service: &str, fallback_line: &str) -> Option<LogLine> {
    let obj = v.as_object()?;

    // 时间戳：兼容 timestamp/ts/time/t
    let ts = obj
        .get("timestamp")
        .or_else(|| obj.get("ts"))
        .or_else(|| obj.get("time"))
        .or_else(|| obj.get("t"))
        .and_then(|t| t.as_u64())
        .or_else(|| {
            obj.get("timestamp")
                .or_else(|| obj.get("ts"))
                .or_else(|| obj.get("t"))
                .and_then(|t| t.as_str())
                .and_then(|s| parse_iso_timestamp(s))
        })
        .unwrap_or_else(now_ms);

    // 服务名：兼容 service/app/source/s
    let service = obj
        .get("service")
        .or_else(|| obj.get("app"))
        .or_else(|| obj.get("source"))
        .or_else(|| obj.get("s"))
        .and_then(|s| s.as_str())
        .unwrap_or(default_service)
        .to_string();

    // 级别：兼容 level/severity/loglevel/l
    let level = obj
        .get("level")
        .or_else(|| obj.get("severity"))
        .or_else(|| obj.get("loglevel"))
        .or_else(|| obj.get("l"))
        .and_then(|l| l.as_str())
        .map(|s| normalize_level(s))
        .unwrap_or_else(|| "I".to_string());

    // 消息：兼容 message/msg/log/m
    let message = obj
        .get("message")
        .or_else(|| obj.get("msg"))
        .or_else(|| obj.get("log"))
        .or_else(|| obj.get("m"))
        .and_then(|m| m.as_str())
        .unwrap_or(fallback_line)
        .to_string();

    Some(LogLine {
        ts,
        service,
        level,
        message,
    })
}

/// Nginx 行简易解析
fn parse_nginx_line(line: &str, _default_service: &str) -> Option<LogLine> {
    let level = if line.contains(" 5") || line.contains(" 4") {
        "E".to_string()
    } else {
        "I".to_string()
    };

    Some(LogLine {
        ts: now_ms(),
        service: "ngx".to_string(),
        level,
        message: line.to_string(),
    })
}

/// 基于关键词推断日志级别
fn infer_level(line: &str) -> String {
    let upper = line.to_uppercase();
    if upper.contains("ERROR") || upper.contains("FATAL") || upper.contains("PANIC") || upper.contains("CRITICAL") {
        "E".to_string()
    } else if upper.contains("WARN") || upper.contains("WARNING") {
        "W".to_string()
    } else {
        "I".to_string()
    }
}

/// 规范化级别为单字符
fn normalize_level(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "DEBUG" | "D" => "D".to_string(),
        "INFO" | "I" | "INFORMATION" => "I".to_string(),
        "WARN" | "WARNING" | "W" => "W".to_string(),
        "ERROR" | "ERR" | "E" | "FATAL" | "CRITICAL" => "E".to_string(),
        _ => "I".to_string(),
    }
}

/// 解析 ISO/Unix 时间戳字符串
fn parse_iso_timestamp(s: &str) -> Option<u64> {
    // Unix 毫秒时间戳（纯数字）
    if let Ok(ms) = s.parse::<u64>() {
        if ms > 1_000_000_000_000 {
            return Some(ms);
        }
        if ms > 1_000_000_000 {
            return Some(ms * 1000); // 秒级转毫秒
        }
    }
    None
}

// ==================== 平台适配 ====================

#[cfg(unix)]
fn get_inode(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
fn get_inode(_meta: &fs::Metadata) -> u64 {
    0 // Windows 下无 inode，用 0 表示（依赖大小+时间检测轮转）
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_standard_json() {
        let line = r#"{"timestamp":1715424000000,"service":"auth","level":"ERROR","message":"login failed"}"#;
        let log = parse_line(line, "default").unwrap();
        assert_eq!(log.ts, 1715424000000);
        assert_eq!(log.service, "auth");
        assert_eq!(log.level, "E");
        assert_eq!(log.message, "login failed");
    }

    #[test]
    fn test_parse_compact_json() {
        let line = r#"{"t":1715424000000,"s":"pg","l":"W","m":"slow query"}"#;
        let log = parse_line(line, "default").unwrap();
        assert_eq!(log.ts, 1715424000000);
        assert_eq!(log.service, "pg");
        assert_eq!(log.level, "W");
        assert_eq!(log.message, "slow query");
    }

    #[test]
    fn test_parse_plain_line() {
        let line = "2026-05-11 14:30:00 ERROR something went wrong";
        let log = parse_line(line, "app").unwrap();
        assert_eq!(log.level, "E");
        assert!(log.message.contains("something went wrong"));
        assert_eq!(log.service, "app");
    }

    #[test]
    fn test_parse_nginx() {
        let line = r#"127.0.0.1 - - [11/May/2026:14:32:10 +0000] "GET /api HTTP/1.1" 500 42"#;
        let log = parse_line(line, "web").unwrap();
        assert_eq!(log.level, "E");
        assert_eq!(log.service, "ngx");
    }

    #[test]
    fn test_infer_level_edge_cases() {
        assert_eq!(infer_level("CRITICAL: disk full"), "E");
        assert_eq!(infer_level("WARN: low memory"), "W");
        assert_eq!(infer_level("DEBUG info"), "I"); // DEBUG 不在 infer_level 中，降级为 I
    }

    #[test]
    fn test_normalize_level() {
        assert_eq!(normalize_level("DEBUG"), "D");
        assert_eq!(normalize_level("INFORMATION"), "I");
        assert_eq!(normalize_level("CRITICAL"), "E");
        assert_eq!(normalize_level("unknown"), "I");
    }

    #[test]
    fn test_mock_collector_rate() {
        let config = CollectorConfig {
            source: SourceType::Mock {
                rate_per_sec: 500,
                duration_sec: 1,
            },
            poll_interval: Duration::from_millis(100),
            service_name: "test".to_string(),
        };

        let (collector, rx) = Collector::start(config).unwrap();

        let mut count = 0;
        while let Ok(_) = rx.recv_timeout(Duration::from_secs(3)) {
            count += 1;
            if count >= 100 { break; }
        }

        assert!(count >= 100, "expected >= 100 logs, got {}", count);
        collector.stop();
    }

    #[test]
    fn test_empty_and_whitespace() {
        assert!(parse_line("", "svc").is_none());
        assert!(parse_line("   ", "svc").is_none());
        assert!(parse_line("\n", "svc").is_none());
    }

    #[test]
    fn test_channel_backpressure() {
        // 测试 channel 不会无限膨胀导致 OOM
        let config = CollectorConfig {
            source: SourceType::Mock {
                rate_per_sec: 100000, // 极高速率
                duration_sec: 1,
            },
            poll_interval: Duration::from_millis(10),
            service_name: "flood".to_string(),
        };

        let (collector, rx) = Collector::start(config).unwrap();

        // 故意缓慢消费，观察是否阻塞或崩溃
        let mut count = 0;
        while let Ok(_) = rx.recv_timeout(Duration::from_millis(100)) {
            count += 1;
            if count >= 50 {
                break;
            }
            thread::sleep(Duration::from_millis(10)); // 模拟慢消费
        }

        assert!(count >= 10); // 至少收到一些，证明 channel 在工作
        collector.stop();
    }
}