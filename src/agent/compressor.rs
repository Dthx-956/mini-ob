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

use crate::agent::template::{EncodedRecord, TemplateBatch, TemplateExtractor};
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
                        buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
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

        // 解析模板字典
        let tmpl_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let mut templates = Vec::with_capacity(tmpl_count);
        for _ in 0..tmpl_count {
            let part_count = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let mut parts = Vec::with_capacity(part_count);
            for _ in 0..part_count {
                let tag = data[offset];
                offset += 1;
                if tag == 0x01 {
                    let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2;
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
        let rec_count = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as usize;
        offset += 4;

        let mut logs = Vec::with_capacity(rec_count);
        let mut prev_ts: u64 = 0;
        let mut ref_params: Vec<String> = Vec::new();

        for rec_idx in 0..rec_count {
            let ts_delta = i64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ]);
            offset += 8;
            let svc_id = data[offset];
            offset += 1;
            let level = match data[offset] {
                b'D' => "D".to_string(),
                b'I' => "I".to_string(),
                b'W' => "W".to_string(),
                b'E' => "E".to_string(),
                _ => "I".to_string(),
            };
            offset += 1;
            let pat_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            let ref_idx = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            let enc_len = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            ]) as usize;
            offset += 4;
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
}
