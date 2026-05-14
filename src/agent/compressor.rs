//! mini-obs/agent/compressor.rs
//! 日志压缩引擎 —— 预处理降熵 + Zstd 字典压缩
//!
//! 设计策略（专利安全）：
//! - 不直接实现 rANS/tANS（规避微软 US11234023B）
//! - 采用"预处理降熵 + 标准 Zstd 库"双层架构，Zstd 内部封装 ANS/FSE
//! - 预处理降低输入熵，使 Zstd 的熵编码器更接近理论极限
//!
//! 预处理流水线：
//!   1. Delta 编码：时间戳转为与上一行的差值（边缘日志通常间隔固定，delta 很小）
//!   2. 行间 RLE：相邻行 message 完全相同时，用 "*" 引用，降低模板日志冗余
//!   3. 服务名缓存：batch 内首次出现的服务名存全称，后续用 "$n" 引用
//!
//! 输出格式（解压后文本，再送 Zstd）：
//!   第1行: {"t":1715424000000,"s":"nginx","l":"E","m":"timeout"}
//!   第2行: {"d":1000,"s":"$0","l":"I","m":"ok"}   // delta=1000, 服务名引用第0个
//!   第3行: {"d":1000,"m":"*"}                     // message 与上一行相同

use std::collections::HashMap;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::shared::format::LogLine;

// ==================== 配置 ====================

#[derive(Debug, Clone)]
pub struct CompressorConfig {
    /// Zstd 压缩级别 1-22（默认 3，平衡速度与压缩比）
    pub zstd_level: i32,
    /// 启用 Delta 时间戳编码
    pub enable_delta: bool,
    /// 启用行间 Message 重复引用（RLE 简化）
    pub enable_rle: bool,
    /// 启用服务名批量引用（batch 内去重）
    pub enable_service_ref: bool,
    /// 字典（可选，训练后传入可提升 20-40% 压缩比）
    pub dict: Option<Vec<u8>>,
}

impl Default for CompressorConfig {
    fn default() -> Self {
        Self {
            zstd_level: 3,
            enable_delta: true,
            enable_rle: true,
            enable_service_ref: true,
            dict: None,
        }
    }
}

// ==================== 内部预处理格式 ====================

/// 预处理后的单行表示（紧凑 JSON，字段可省略默认值）
#[derive(Serialize, Deserialize, Debug)]
struct CompactLine {
    /// 绝对时间戳（仅首行）或差值（后续行）
    #[serde(rename = "t", skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
    #[serde(rename = "d", skip_serializing_if = "Option::is_none")]
    pub delta: Option<i64>,
    /// 服务名（或引用标记 "$n"）
    #[serde(rename = "s")]
    pub service: String,
    /// 级别
    #[serde(rename = "l")]
    pub level: String,
    /// 消息（或 "*" 表示与上一行相同）
    #[serde(rename = "m")]
    pub message: String,
}

// ==================== 压缩引擎 ====================

pub struct Compressor {
    config: CompressorConfig,
}

impl Compressor {
    pub fn new(config: CompressorConfig) -> Self {
        Self { config }
    }

    /// 使用预训练字典创建压缩器（针对固定格式日志，如 nginx/postgres）
    pub fn with_dict(zstd_level: i32, dict: Vec<u8>) -> Self {
        Self {
            config: CompressorConfig {
                zstd_level,
                enable_delta: true,
                enable_rle: true,
                enable_service_ref: true,
                dict: Some(dict),
            },
        }
    }

    // ---------- 压缩入口 ----------

    /// 将一批日志压缩为字节流（对应 storage.rs 中 Segment 的数据区）
    pub fn compress_batch(&self, logs: &[LogLine]) -> io::Result<Vec<u8>> {
        if logs.is_empty() {
            return Ok(Vec::new());
        }

        // 1. 预处理降熵
        let preprocessed = self.preprocess(logs);

        // 2. 序列化为紧凑 JSON Lines
        let text = self.serialize_batch(&preprocessed);

        // 3. Zstd 压缩（带字典或不带字典）
        let compressed = self.zstd_compress(text.as_bytes())?;

        Ok(compressed)
    }

    /// 解压字节流还原为日志行（对应 storage.rs 查询时的流式解压）
    pub fn decompress_batch(&self, data: &[u8]) -> io::Result<Vec<LogLine>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // 1. Zstd 解压
        let text = self.zstd_decompress(data)?;

        // 2. 解析紧凑 JSON Lines
        let compact = self.deserialize_batch(&text)?;

        // 3. 后处理还原
        let logs = self.postprocess(&compact);

        Ok(logs)
    }

    // ---------- 预处理（降熵）----------

    fn preprocess(&self, logs: &[LogLine]) -> Vec<CompactLine> {
        let mut result = Vec::with_capacity(logs.len());
        let mut prev_ts: u64 = 0;
        let mut prev_msg: String = String::new();
        let mut service_table: Vec<String> = Vec::new();
        let mut service_map: HashMap<String, usize> = HashMap::new();

        for (i, log) in logs.iter().enumerate() {
            let mut line = CompactLine {
                ts: None,
                delta: None,
                service: log.service.clone(),
                level: log.level.clone(),
                message: log.message.clone(),
            };

            // Delta 时间戳编码
            if self.config.enable_delta {
                if i == 0 {
                    line.ts = Some(log.ts);
                    prev_ts = log.ts;
                } else {
                    let delta = log.ts as i64 - prev_ts as i64;
                    line.delta = Some(delta);
                    prev_ts = log.ts;
                }
            } else {
                line.ts = Some(log.ts);
            }

            // 服务名引用编码（batch 内首次出现存全称，后续用 "$n"）
            if self.config.enable_service_ref && i > 0 {
                if let Some(&idx) = service_map.get(&log.service) {
                    line.service = format!("${}", idx);
                } else {
                    let idx = service_table.len();
                    service_table.push(log.service.clone());
                    service_map.insert(log.service.clone(), idx);
                    // 首次出现仍用原名，但后续用引用
                }
            } else if i == 0 && self.config.enable_service_ref {
                service_map.insert(log.service.clone(), 0);
                service_table.push(log.service.clone());
            }

            // 行间 Message RLE（相邻行 message 相同则标记 "*"）
            if self.config.enable_rle && i > 0 && log.message == prev_msg {
                line.message = "*".to_string();
            } else {
                prev_msg = log.message.clone();
            }

            result.push(line);
        }

        result
    }

    // ---------- 后处理（还原）----------

    fn postprocess(&self, compact: &[CompactLine]) -> Vec<LogLine> {
        let mut result = Vec::with_capacity(compact.len());
        let mut prev_ts: u64 = 0;
        let mut service_table: Vec<String> = Vec::new();
        let mut prev_msg: String = String::new();

        for (i, line) in compact.iter().enumerate() {
            // 还原时间戳
            let ts = if let Some(t) = line.ts {
                prev_ts = t;
                t
            } else if let Some(d) = line.delta {
                let t = (prev_ts as i64 + d) as u64;
                prev_ts = t;
                t
            } else {
                prev_ts // 兜底
            };

            // 还原服务名（解析 "$n" 引用）
            let service = if line.service.starts_with('$') {
                let idx: usize = line.service[1..].parse().unwrap_or(0);
                service_table.get(idx).cloned().unwrap_or_else(|| line.service.clone())
            } else {
                if i == 0 || !service_table.contains(&line.service) {
                    service_table.push(line.service.clone());
                }
                line.service.clone()
            };

            // 还原 message（"*" 引用上一行）
            let message = if line.message == "*" {
                prev_msg.clone()
            } else {
                prev_msg = line.message.clone();
                line.message.clone()
            };

            result.push(LogLine {
                ts,
                service,
                level: line.level.clone(),
                message,
            });
        }

        result
    }

    // ---------- 序列化 ----------

    fn serialize_batch(&self, lines: &[CompactLine]) -> String {
        let mut buf = String::with_capacity(lines.len() * 128);
        for line in lines {
            // 使用紧凑 JSON，无空格
            let json = serde_json::to_string(line)
                .unwrap_or_else(|_| r#"{"m":"serialize_error"}"#.to_string());
            buf.push_str(&json);
            buf.push('\n');
        }
        buf
    }

    fn deserialize_batch(&self, text: &str) -> io::Result<Vec<CompactLine>> {
        let mut result = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let compact: CompactLine = serde_json::from_str(line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            result.push(compact);
        }
        Ok(result)
    }

    // ---------- Zstd 压缩/解压 ----------

    fn zstd_compress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(ref dict) = self.config.dict {
            // 使用字典压缩（针对模板化日志效率最高）
            let mut encoder = zstd::stream::write::Encoder::with_dictionary(
                Vec::new(),
                self.config.zstd_level,
                dict,
            )?;
            encoder.write_all(data)?;
            encoder.finish()
        } else {
            // 标准压缩
            zstd::encode_all(data, self.config.zstd_level)
        }
    }

    fn zstd_decompress(&self, data: &[u8]) -> io::Result<String> {
        let raw = if let Some(ref dict) = self.config.dict {
            let mut decoder = zstd::stream::read::Decoder::with_dictionary(data, dict)?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            out
        } else {
            zstd::decode_all(data)?
        };

        String::from_utf8(raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

// ==================== 字典训练 ====================

/// 字典训练器（针对固定格式日志预训练，提升边缘场景压缩比）
pub struct DictTrainer {
    samples: Vec<Vec<u8>>,
    max_size: usize,
}

impl DictTrainer {
    pub fn new(max_size: usize) -> Self {
        Self {
            samples: Vec::new(),
            max_size,
        }
    }

    /// 添加训练样本（原始文本，未压缩）
    pub fn add_sample(&mut self, text: &str) {
        self.samples.push(text.as_bytes().to_vec());
    }

    /// 从 LogLine 批次添加样本
    pub fn add_logs(&mut self, logs: &[LogLine]) {
        let text = logs
            .iter()
            .map(|l| {
                format!(
                    r#"{{"t":{},"s":"{}","l":"{}","m":"{}"}}"#,
                    l.ts, l.service, l.level, l.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        self.add_sample(&text);
    }

    /// 训练并返回字典（失败返回 None）
    pub fn train(&self) -> Option<Vec<u8>> {
        if self.samples.is_empty() {
            return None;
        }
        // 合并所有样本为连续字节流
        let total_len: usize = self.samples.iter().map(|s| s.len()).sum();
        let mut continuous = Vec::with_capacity(total_len);
        let mut lengths = Vec::with_capacity(self.samples.len());
        for s in &self.samples {
            continuous.extend_from_slice(s);
            lengths.push(s.len());
        }

        match zstd::dict::from_continuous(&continuous, &lengths, self.max_size) {
            Ok(dict) => Some(dict),
            Err(e) => {
                eprintln!("[dict] Training failed: {}", e);
                None
            }
        }
    }
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(ts: u64, svc: &str, lvl: &str, msg: &str) -> LogLine {
        LogLine {
            ts,
            service: svc.to_string(),
            level: lvl.to_string(),
            message: msg.to_string(),
        }
    }

    #[test]
    fn test_roundtrip_simple() {
        let comp = Compressor::new(CompressorConfig::default());
        let logs = vec![
            make_log(1715424000000, "nginx", "E", "timeout"),
            make_log(1715424001000, "nginx", "E", "timeout"),
            make_log(1715424002000, "nginx", "I", "ok"),
        ];

        let compressed = comp.compress_batch(&logs).unwrap();
        let decompressed = comp.decompress_batch(&compressed).unwrap();

        assert_eq!(decompressed.len(), 3);
        assert_eq!(decompressed[0].ts, 1715424000000);
        assert_eq!(decompressed[1].ts, 1715424001000);
        assert_eq!(decompressed[2].message, "ok");
    }

    #[test]
    fn test_delta_encoding_reduces_size() {
        // 对比：enable_delta vs disable_delta
        let logs: Vec<LogLine> = (0..1000)
            .map(|i| make_log(1715424000000 + i * 1000, "app", "I", "heartbeat"))
            .collect();

        let with_delta = Compressor::new(CompressorConfig {
            enable_delta: true,
            enable_rle: false,
            enable_service_ref: false,
            ..Default::default()
        });
        let without_delta = Compressor::new(CompressorConfig {
            enable_delta: false,
            enable_rle: false,
            enable_service_ref: false,
            ..Default::default()
        });

        let c1 = with_delta.compress_batch(&logs).unwrap();
        let c2 = without_delta.compress_batch(&logs).unwrap();

        println!("With delta: {} bytes, Without: {} bytes", c1.len(), c2.len());
        assert!(c1.len() < c2.len(), "delta encoding should reduce size");
    }

    #[test]
    fn test_rle_encoding() {
        let logs = vec![
            make_log(1000, "svc", "I", "same message"),
            make_log(2000, "svc", "I", "same message"),
            make_log(3000, "svc", "I", "same message"),
            make_log(4000, "svc", "I", "different"),
        ];

        let comp = Compressor::new(CompressorConfig::default());
        let compressed = comp.compress_batch(&logs).unwrap();
        let decompressed = comp.decompress_batch(&compressed).unwrap();

        assert_eq!(decompressed.len(), 4);
        assert_eq!(decompressed[0].message, "same message");
        assert_eq!(decompressed[1].message, "same message");
        assert_eq!(decompressed[2].message, "same message");
        assert_eq!(decompressed[3].message, "different");
    }

    #[test]
    fn test_service_ref_encoding() {
        let logs = vec![
            make_log(1000, "nginx", "I", "a"),
            make_log(2000, "nginx", "I", "b"),
            make_log(3000, "nginx", "I", "c"),
            make_log(4000, "postgres", "I", "d"),
            make_log(5000, "postgres", "I", "e"),
        ];

        let comp = Compressor::new(CompressorConfig::default());
        let compressed = comp.compress_batch(&logs).unwrap();
        let decompressed = comp.decompress_batch(&compressed).unwrap();

        assert_eq!(decompressed[0].service, "nginx");
        assert_eq!(decompressed[3].service, "postgres");
    }

    #[test]
    fn test_compression_ratio_high_entropy_logs() {
        // 模拟高重复性边缘日志（如传感器数据）
        let template = "Sensor reading: temperature=25.3, humidity=60%, status=OK, device_id=DEV-12345, location=FLOOR-3-ROOM-7";
        let logs: Vec<LogLine> = (0..1000)
            .map(|i| make_log(1715424000000 + i * 100, "iot", "I", template))
            .collect();

        let comp = Compressor::new(CompressorConfig::default());
        let compressed = comp.compress_batch(&logs).unwrap();

        let original_size: usize = logs.iter().map(|l| l.message.len() + 50).sum();
        let ratio = original_size as f64 / compressed.len() as f64;

        println!("Original: {} bytes, Compressed: {} bytes, Ratio: {:.2}x", original_size, compressed.len(), ratio);
        assert!(ratio > 5.0, "expected >5x compression for repetitive logs, got {:.2}x", ratio);
    }

    #[test]
    fn test_dict_compression_improvement() {
        // 1. 训练字典
        let mut trainer = DictTrainer::new(100 * 1024); // 100KB 字典
        for _ in 0..10 {
            let sample: Vec<LogLine> = (0..100)
                .map(|i| make_log(1000 + i * 100, "nginx", "I", "GET /api/v1/users HTTP/1.1 200"))
                .collect();
            trainer.add_logs(&sample);
        }
        let dict = trainer.train().expect("dict training failed");

        // 2. 对比
        let logs: Vec<LogLine> = (0..500)
            .map(|i| make_log(2000 + i * 100, "nginx", "I", "GET /api/v1/users HTTP/1.1 200"))
            .collect();

        let with_dict = Compressor::with_dict(3, dict);
        let without_dict = Compressor::new(CompressorConfig::default());

        let c1 = with_dict.compress_batch(&logs).unwrap();
        let c2 = without_dict.compress_batch(&logs).unwrap();

        println!("With dict: {} bytes, Without: {} bytes", c1.len(), c2.len());
        // 字典通常能提升 10-30%
        assert!(c1.len() <= c2.len(), "dict should not worsen compression");
    }

    #[test]
    fn test_empty_batch() {
        let comp = Compressor::new(CompressorConfig::default());
        let compressed = comp.compress_batch(&[]).unwrap();
        assert!(compressed.is_empty());
        let decompressed = comp.decompress_batch(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_large_batch_stability() {
        let logs: Vec<LogLine> = (0..10000)
            .map(|i| make_log(i * 1000, "svc", "I", &format!("message number {}", i)))
            .collect();

        let comp = Compressor::new(CompressorConfig::default());
        let compressed = comp.compress_batch(&logs).unwrap();
        let decompressed = comp.decompress_batch(&compressed).unwrap();

        assert_eq!(decompressed.len(), 10000);
        assert_eq!(decompressed[9999].ts, 9999 * 1000);
    }
}