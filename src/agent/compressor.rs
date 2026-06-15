//! mini-obs/agent/compressor.rs
//! 压缩引擎 —— 模板提取 + 文本参数序列化 + Zstd
//!
//! 设计策略（专利安全）：
//! - 不直接实现 rANS/tANS（规避微软 US11234023B）
//! - 模板字典用二进制 TLV（精确重建结构）
//! - 记录参数保持文本格式（让 zstd LZ77 跨行匹配相似值）

use std::io::{self, Read, Write};

use crate::agent::template::{TemplateBatch, TemplateExtractor};
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
    /// 2. 序列化为"模板字典(二进制) + 记录(文本参数)"的混合格式
    /// 3. Zstd 压缩
    ///
    /// 参数保持文本形式而非 XOR-P 二进制编码，让 zstd 的 LZ77 能继续
    /// 在相邻行的参数值之间找到字节级相似性。
    pub fn compress_batch(&self, logs: &[LogLine]) -> io::Result<Vec<u8>> {
        if logs.is_empty() {
            return Ok(Vec::new());
        }

        let raw_bytes = if self.config.enable_template {
            let batch = TemplateExtractor::extract(logs);
            Self::serialize_template_v2(&batch)
        } else {
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

        // 尝试 v2 文本参数格式，失败则回退 JSON
        if let Ok(logs) = Self::deserialize_template_v2(&raw) {
            return Ok(logs);
        }

        Self::deserialize_json_fallback(&raw)
    }

    // ---------- v2 序列化：模板字典(二进制) + 记录(文本参数) ----------
    //
    // 格式设计原则：
    // - 模板字典保持二进制 TLV（体积小，需精确重建）
    // - 记录用 \0 分隔的文本格式，参数保持原始文本表示
    // - zstd 可以跨记录找到字节级模式（相同模板 → pat_id 重复，
    //   相邻参数值相似 → zstd LZ77 匹配）
    //
    // 整体布局：
    //   [template_count:u16][template_dict_TLV...]
    //   [record_count:u32]
    //   "{ts_delta}\0{svc_id}\0{level}\0{pat_id}\0{param_count}\0{p1}\0{p2}...\n"
    //   ...

    fn serialize_template_v2(
        batch: &crate::agent::template::TemplateBatch,
    ) -> Vec<u8> {
        let mut buf = Vec::new();

        // 1. 模板字典（二进制 TLV，与旧格式兼容）
        buf.extend_from_slice(&(batch.templates.len() as u16).to_le_bytes());
        for t in &batch.templates {
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

        // 2. 记录：文本格式，\0 分隔字段，\n 分隔记录
        buf.extend_from_slice(&(batch.records.len() as u32).to_le_bytes());
        // 二进制头与文本记录之间加换行，帮助 zstd 定位模式边界
        buf.push(b'\n');

        for rec in &batch.records {
            // ts_delta (十进制字符串，比 8 字节固定宽度二进制更 zstd 友好)
            write!(buf, "{}", rec.ts_delta).unwrap();
            buf.push(0u8);
            // svc_id
            write!(buf, "{}", rec.svc_id).unwrap();
            buf.push(0u8);
            // level
            buf.extend_from_slice(rec.level.as_bytes());
            buf.push(0u8);
            // pat_id
            write!(buf, "{}", rec.pat_id).unwrap();
            buf.push(0u8);
            // param_count
            write!(buf, "{}", rec.params.len()).unwrap();
            // 参数：每个参数用 TypedParam::to_string() 的文本表示
            for p in &rec.params {
                buf.push(0u8);
                buf.extend_from_slice(p.to_string().as_bytes());
            }
            buf.push(b'\n');
        }

        buf
    }

    fn deserialize_template_v2(data: &[u8]) -> io::Result<Vec<LogLine>> {
        use crate::agent::template::{TemplatePart, TypedParam};

        let mut offset = 0;
        let check = |offset: usize, len: usize| {
            if offset + len > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "template v2 deserialize truncated",
                ));
            }
            Ok(())
        };

        // ── 解析模板字典（二进制 TLV，与旧格式相同）──
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
                    let len = u32::from_le_bytes([
                        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                    ]) as usize;
                    offset += 4;
                    check(offset, len)?;
                    let s = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
                    offset += len;
                    parts.push(TemplatePart::Literal(s));
                } else {
                    parts.push(TemplatePart::Param);
                }
            }
            templates.push(crate::agent::template::Template {
                id: templates.len() as u16,
                parts,
            });
        }

        // ── 解析记录（文本格式）──
        check(offset, 4)?;
        let rec_count = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]) as usize;
        offset += 4;

        // 跳过分隔换行
        if offset < data.len() && data[offset] == b'\n' {
            offset += 1;
        }

        let mut logs = Vec::with_capacity(rec_count);
        let mut prev_ts: u64 = 0;

        for rec_idx in 0..rec_count {
            // 找到本条记录的结束位置（\n）
            let rec_end = match data[offset..].iter().position(|&b| b == b'\n') {
                Some(pos) => offset + pos,
                None => data.len(),
            };
            let rec_bytes = &data[offset..rec_end];
            offset = rec_end + 1; // 跳过 \n

            // 按 \0 分割字段
            let fields: Vec<&[u8]> = rec_bytes.split(|&b| b == 0u8).collect();
            if fields.len() < 5 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("record {} too few fields: {}", rec_idx, fields.len()),
                ));
            }

            let ts_delta: i64 = std::str::from_utf8(fields[0])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let svc_id: u8 = std::str::from_utf8(fields[1])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let level = String::from_utf8_lossy(fields[2]).to_string();
            let pat_id: u16 = std::str::from_utf8(fields[3])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let param_count: usize = std::str::from_utf8(fields[4])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // 剩余字段是参数文本
            let param_fields = &fields[5..];
            if param_fields.len() < param_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "record {} param count mismatch: expected {}, got {} fields",
                        rec_idx,
                        param_count,
                        param_fields.len()
                    ),
                ));
            }
            let params: Vec<TypedParam> = param_fields[..param_count]
                .iter()
                .map(|bytes| {
                    let s = String::from_utf8_lossy(bytes);
                    TypedParam::from_str(&s)
                })
                .collect();

            // 时间戳重建
            let ts = if rec_idx == 0 {
                prev_ts = ts_delta as u64;
                ts_delta as u64
            } else {
                prev_ts = (prev_ts as i64 + ts_delta) as u64;
                prev_ts
            };

            // 重建 message
            let template = &templates[pat_id as usize];
            let mut msg_parts = Vec::new();
            let mut param_iter = params.iter();
            for part in &template.parts {
                match part {
                    TemplatePart::Literal(s) => msg_parts.push(s.clone()),
                    TemplatePart::Param => {
                        if let Some(p) = param_iter.next() {
                            msg_parts.push(p.to_string());
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
