//! mini-obs/agent/compressor.rs
//! 日志压缩引擎 —— 预处理降熵 + Zstd 字典压缩
//!
//!
//! 设计策略（专利安全）：
//! - 不直接实现 rANS/tANS（规避微软 US11234023B）
//! - 采用"预处理降熵 + 标准 Zstd 库"双层架构

//! mini-obs/agent/compressor.rs
//! 压缩引擎 —— 模板降熵 + 64-bit XOR-P + Zstd

use std::io::{self, Read, Write};

use crate::agent::template::{EncodedRecord, TemplateExtractor};
use crate::shared::format::LogLine;

// ==================== 配置 ====================

#[derive(Debug, Clone)]
pub struct CompressorConfig {
    pub zstd_level: i32,
    pub enable_template: bool,
    pub xor_ref_reset: usize,
    pub dict: Option<Vec<u8>>,
}

impl Default for CompressorConfig {
    fn default() -> Self {
        Self {
            zstd_level: 3,
            enable_template: true,
            xor_ref_reset: 16,
            dict: None,
        }
    }
}

// ==================== 压缩引擎 ====================

pub struct Compressor {
    config: CompressorConfig,
}

impl Compressor {
    pub fn new(config: CompressorConfig) -> Self {
        Self { config }
    }

    /// 压缩一批日志
    ///
    /// 流程：
    /// 1. 模板提取（若启用）
    /// 2. XOR-P 编码
    /// 3. 序列化为紧凑二进制
    /// 4. Zstd 压缩
    pub fn compress_batch(&self, logs: &[LogLine]) -> io::Result<Vec<u8>> {
        if logs.is_empty() {
            return Ok(Vec::new());
        }

        let raw_bytes = if self.config.enable_template {
            let batch = TemplateExtractor::extract(logs);
            let encoded = TemplateExtractor::encode_xor(&batch, self.config.xor_ref_reset);
            Self::serialize_template(&batch.templates, &encoded)
        } else {
            // 回退：旧版 JSON Lines（保留兼容）
            Self::serialize_json_fallback(logs)
        };

        self.zstd_compress(&raw_bytes)
    }

    /// 解压
    pub fn decompress_batch(&self, data: &[u8]) -> io::Result<Vec<LogLine>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        let raw = self.zstd_decompress(data)?;
        
        // 尝试解析模板格式，失败则回退 JSON
        if let Ok(logs) = Self::deserialize_template(&raw) {
            return Ok(logs);
        }
        
        Self::deserialize_json_fallback(&raw)
    }

    // ---------- 序列化：模板二进制格式 ----------

    fn serialize_template(templates: &[crate::agent::template::Template], records: &[EncodedRecord]) -> Vec<u8> {
        let mut buf = Vec::new();

        // 1. 模板字典
        buf.extend_from_slice(&(templates.len() as u16).to_le_bytes());
        for t in templates {
            buf.extend_from_slice(&(t.parts.len() as u16).to_le_bytes());
            for part in &t.parts {
                match part {
                    crate::agent::template::TemplatePart::Literal(s) => {
                        buf.push(0x01);
                        let bytes = s.as_bytes();
                        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                        buf.extend_from_slice(bytes);
                    }
                    crate::agent::template::TemplatePart::Param => {
                        buf.push(0x02);
                    }
                }
            }
        }

        // 2. 记录
        buf.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for rec in records {
            buf.extend_from_slice(&rec.ts_delta.to_le_bytes());
            buf.push(rec.svc_id);
            buf.push(rec.level.as_bytes()[0]); // D/I/W/E
            buf.extend_from_slice(&rec.pat_id.to_le_bytes());
            buf.extend_from_slice(&rec.param_encoding.ref_idx.to_le_bytes());
            buf.extend_from_slice(&(rec.param_encoding.data.len() as u32).to_le_bytes());
            buf.extend_from_slice(&rec.param_encoding.data);
        }

        buf
    }

    fn deserialize_template(data: &[u8]) -> io::Result<Vec<LogLine>> {
        use crate::agent::template::{ParamEncoding, TemplateExtractor, TemplatePart};

        let mut offset = 0;
        let check = |offset, len| {
            if offset + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "template deserialize truncated"));
            }
            Ok(())
        };

        // 解析模板字典
        check(offset, 2)?;
        let tmpl_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let mut templates = Vec::with_capacity(tmpl_count);
        for _ in 0..tmpl_count {
            check(offset, 2)?;
            let part_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let mut parts = Vec::with_capacity(part_count);
            for _ in 0..part_count {
                check(offset, 1)?;
                let tag = data[offset];
                offset += 1;
                if tag == 0x01 {
                    check(offset, 4)?;
                    let len = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
                    offset += 4;
                    check(offset, len)?;
                    let s = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
                    offset += len;
                    parts.push(TemplatePart::Literal(s));
                } else {
                    parts.push(TemplatePart::Param);
                }
            }
            templates.push(crate::agent::template::Template { id: templates.len() as u16, parts });
        }

        // 解析记录
        check(offset, 4)?;
        let rec_count = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as usize;
        offset += 4;

        let mut logs = Vec::with_capacity(rec_count);
        let mut prev_ts: u64 = 0;
        let mut ref_params: Vec<String> = Vec::new();

        for rec_idx in 0..rec_count {
            check(offset, 8)?;
            let ts_delta = i64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ]);
            offset += 8;
            check(offset, 1)?;
            let svc_id = data[offset];
            offset += 1;
            check(offset, 1)?;
            let level = match data[offset] {
                b'D' => "D".to_string(),
                b'I' => "I".to_string(),
                b'W' => "W".to_string(),
                b'E' => "E".to_string(),
                _ => "I".to_string(),
            };
            offset += 1;
            check(offset, 2)?;
            let pat_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            check(offset, 2)?;
            let ref_idx = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            check(offset, 4)?;
            let enc_len = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            ]) as usize;
            offset += 4;
            check(offset, enc_len)?;
            let enc_data = &data[offset..offset + enc_len];
            offset += enc_len;

            // 时间戳重建
            let ts = if rec_idx == 0 {
                prev_ts = ts_delta as u64;
                ts_delta as u64
            } else {
                prev_ts = (prev_ts as i64 + ts_delta) as u64;
                prev_ts
            };

            // 参数解码
            let enc_rec = crate::agent::template::EncodedRecord {
                ts_delta,
                svc_id,
                level: level.clone(),
                pat_id,
                param_encoding: ParamEncoding {
                    ref_idx,
                    data: enc_data.to_vec(),
                },
            };

            let params = TemplateExtractor::decode_xor(&enc_rec, &ref_params);
            if ref_idx == 0 {
                ref_params = params.clone();
            }

            // 重建 message
            let template = &templates[pat_id as usize];
            let mut msg_parts = Vec::new();
            let mut param_iter = params.iter();
            for part in &template.parts {
                match part {
                    TemplatePart::Literal(s) => msg_parts.push(s.clone()),
                    TemplatePart::Param => {
                        if let Some(p) = param_iter.next() {
                            msg_parts.push(p.clone());
                        }
                    }
                }
            }
            let message = msg_parts.concat();

            logs.push(LogLine {
                ts,
                service: format!("svc{}", svc_id),
                level,
                message,
            });
        }

        Ok(logs)
    }

    // ---------- 回退：JSON Lines ----------

    fn serialize_json_fallback(logs: &[LogLine]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(logs.len() * 128);
        for log in logs {
            let json = serde_json::to_string(log).unwrap_or_default();
            buf.extend_from_slice(json.as_bytes());
            buf.push(b'\n');
        }
        buf
    }

    fn deserialize_json_fallback(data: &[u8]) -> io::Result<Vec<LogLine>> {
        let mut logs = Vec::new();
        for line in std::str::from_utf8(data).unwrap_or("").lines() {
            if line.trim().is_empty() { continue; }
            if let Ok(log) = serde_json::from_str::<LogLine>(line) {
                logs.push(log);
            }
        }
        Ok(logs)
    }

    // ---------- Zstd ----------

    fn zstd_compress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(ref dict) = self.config.dict {
            let mut enc = zstd::stream::write::Encoder::with_dictionary(Vec::new(), self.config.zstd_level, dict)?;
            enc.write_all(data)?;
            enc.finish()
        } else {
            zstd::encode_all(data, self.config.zstd_level)
        }
    }

    fn zstd_decompress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(ref dict) = self.config.dict {
            let mut dec = zstd::stream::read::Decoder::with_dictionary(data, dict)?;
            let mut out = Vec::new();
            dec.read_to_end(&mut out)?;
            Ok(out)
        } else {
            zstd::decode_all(data)
        }
    }
}

// ==================== 字典训练（保留） ====================

pub use crate::agent::template::TemplateExtractor as DictTrainerSource; // 别名，保持兼容


#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::format::LogLine;

    fn make_log(ts: u64, svc: &str, lvl: &str, msg: &str) -> LogLine {
        LogLine {
            ts,
            service: svc.to_string(),
            level: lvl.to_string(),
            message: msg.to_string(),
        }
    }

    #[test]
    fn test_compressor_roundtrip_template() {
        let comp = Compressor::new(CompressorConfig::default());
        let logs = vec![
            make_log(1000, "svc", "I", "alpha"),
            make_log(2000, "svc", "W", "beta"),
            make_log(3000, "svc", "E", "gamma"),
        ];

        let compressed = comp.compress_batch(&logs).unwrap();
        let decompressed = comp.decompress_batch(&compressed).unwrap();

        assert_eq!(decompressed.len(), 3);
        for (a, b) in logs.iter().zip(decompressed.iter()) {
            assert_eq!(a.ts, b.ts, "ts mismatch");
            assert_eq!(a.level, b.level, "level mismatch");
            assert_eq!(a.message, b.message, "message mismatch");
        }
    }

    #[test]
    fn test_compressor_template_with_reset() {
        let comp = Compressor::new(CompressorConfig {
            xor_ref_reset: 4,
            ..Default::default()
        });
        let logs: Vec<LogLine> = (0..20)
            .map(|i| make_log(1000 + i as u64 * 100, "svc", "I", &format!("msg-{}", i)))
            .collect();

        let compressed = comp.compress_batch(&logs).unwrap();
        let decompressed = comp.decompress_batch(&compressed).unwrap();

        assert_eq!(decompressed.len(), 20);
        for (a, b) in logs.iter().zip(decompressed.iter()) {
            assert_eq!(a.message, b.message, "message mismatch at idx");
        }
    }
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
    // 模拟高重复度模板日志，验证能否达到 >5x
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
        make_log(1100, "svc", "I", "Path: C:\\Users\\Admin\\file.txt"),
        make_log(1200, "svc", "E", "JSON: {\"key\": \"value with \\\"quotes\\\"}"),
    ];
    let compressed = comp.compress_batch(&logs).unwrap();
    let decompressed = comp.decompress_batch(&compressed).unwrap();
    assert_eq!(decompressed.len(), 3);
    assert_eq!(decompressed[0].message, "Hello 世界 🌍");
    assert_eq!(decompressed[1].message, "Path: C:\\Users\\Admin\\file.txt");
    assert_eq!(decompressed[2].message, "JSON: {\"key\": \"value with \\\"quotes\\\"}");
}
}
