//! mini-obs/agent/template.rs
//! 模板提取与 64-bit XOR-P 参数编码
//!
//! 核心设计：
//! - Batch 级模板提取：按 token 长度分组，组内聚类公共模式
//! - 无匹配 → 自动创建新模板，保留原始字符
//! - XOR-P 按 ARM64 字长（64-bit / 8 bytes）对齐操作
//! - 编码格式：bitmap + literals，紧凑且 SIMD 友好

use std::collections::HashMap;
use std::io;

use crate::shared::format::LogLine;

// ==================== 数据模型 ====================

/// 模板片段：固定文本或参数占位符
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplatePart {
    Literal(String),
    Param,
}

/// 模板定义
#[derive(Debug, Clone)]
pub struct Template {
    pub id: u16,
    pub parts: Vec<TemplatePart>,
}

/// 模板化记录（逻辑表示，未编码）
#[derive(Debug, Clone)]
pub struct TemplateRecord {
    /// 原始 batch 索引（用于恢复顺序）
    pub original_idx: usize,
    pub ts_delta: i64,
    pub svc_id: u8,
    pub level: String,
    pub pat_id: u16,
    /// 参数值，与模板中的 Param 一一对应
    pub params: Vec<String>,
}

/// 一批日志的模板化结果
#[derive(Debug, Default)]
pub struct TemplateBatch {
    pub templates: Vec<Template>,
    pub records: Vec<TemplateRecord>,
}

/// XOR-P 编码后的单条记录
#[derive(Debug, Clone)]
pub struct EncodedRecord {
    pub ts_delta: i64,
    pub svc_id: u8,
    pub level: String,
    pub pat_id: u16,
    pub param_encoding: ParamEncoding,
}

/// 参数编码：参考行 + bitmap/literals
#[derive(Debug, Clone)]
pub struct ParamEncoding {
    /// Chunk 内参考行索引（0 = 本 Chunk 首行存原始值）
    pub ref_idx: u16,
    /// 编码后字节流：u16(num_chunks) + bitmap + [u64 literals...]
    pub data: Vec<u8>,
}

// ==================== 模板提取器 ====================

pub struct TemplateExtractor;

impl TemplateExtractor {
    /// 从一批日志中提取模板
    ///
    /// 算法：
    /// 1. 对所有 message 按空格/标点分词
    /// 2. 按 token 数量分组
    /// 3. 组内逐 token 比较，标记变化位置为 Param
    /// 4. 单条组（无同类）→ 每条作为独立模板（保留原始字符）
    pub fn extract(batch: &[LogLine]) -> TemplateBatch {
        if batch.is_empty() {
            return TemplateBatch::default();
        }

        // 分词
        let tokenized: Vec<Vec<String>> = batch.iter().map(|l| Self::tokenize(&l.message)).collect();

        // 按 token 数分组
        let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
        for (i, tokens) in tokenized.iter().enumerate() {
            groups.entry(tokens.len()).or_default().push(i);
        }

        let mut templates: Vec<Template> = Vec::new();
        let mut template_map: HashMap<String, u16> = HashMap::new();
        let mut records = Vec::with_capacity(batch.len());

        for (_len, indices) in groups {
            if indices.len() < 2 {
                // 单条无法聚类：每条作为独立模板
                for &i in &indices {
                    let log = &batch[i];
                    let t = Self::raw_template(&tokenized[i]);
                    let pat_id = Self::get_or_create_template(&mut templates, &mut template_map, t);
                    let params = Self::extract_params(&tokenized[i], &templates[pat_id as usize]);
                    records.push(Self::build_record(log, pat_id, params, i));
                }
                continue;
            }

            // 组内聚类：找公共 token 模式
            let first = &tokenized[indices[0]];
            let mut is_fixed = vec![true; first.len()];

            for &idx in indices.iter().skip(1) {
                let tokens = &tokenized[idx];
                for (j, (a, b)) in first.iter().zip(tokens.iter()).enumerate() {
                    if a != b {
                        is_fixed[j] = false;
                    }
                }
            }

            // 生成模板
            let t = Self::build_template_from_mask(first, &is_fixed);
            let pat_id = Self::get_or_create_template(&mut templates, &mut template_map, t);

            // 为组内所有行生成记录
            for &idx in &indices {
                let log = &batch[idx];
                let params = Self::extract_params_with_mask(&tokenized[idx], &is_fixed);
                records.push(Self::build_record(log, pat_id, params, idx));
            }
        }

        // 恢复原始顺序
        records.sort_by_key(|r| r.original_idx);

        // 计算时间戳差值：首行存绝对值，后续存 delta
        let mut prev_ts: i64 = 0;
        for (i, rec) in records.iter_mut().enumerate() {
            let abs_ts = rec.ts_delta;
            if i == 0 {
                prev_ts = abs_ts;
            } else {
                rec.ts_delta = abs_ts - prev_ts;
                prev_ts = abs_ts;
            }
        }

        TemplateBatch { templates, records }
    }

    /// 对 TemplateBatch 应用 64-bit XOR-P 编码
    ///
    /// ref_reset: 每 N 行重置参考行（默认 16，查询友好）
    pub fn encode_xor(batch: &TemplateBatch, ref_reset: usize) -> Vec<EncodedRecord> {
        let mut result = Vec::with_capacity(batch.records.len());
        let mut ref_params: Vec<String> = Vec::new();
        let mut ref_idx = 0usize;

        for (i, rec) in batch.records.iter().enumerate() {
            let mut encoding_data = Vec::new();
            encoding_data.extend_from_slice(&(rec.params.len() as u32).to_le_bytes());

            if i % ref_reset == 0 {
                // 重置参考行：直接存储原始参数值（原始字符串，非 XOR-P）
                ref_params = rec.params.clone();
                ref_idx = i;
                for p in &rec.params {
                    let bytes = p.as_bytes();
                    encoding_data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    encoding_data.extend_from_slice(bytes);
                }
            } else {
                // 非参考行：XOR-P 编码
                for (p, base) in rec.params.iter().zip(ref_params.iter()) {
                    let encoded = Self::xor_param_64bit(p, base);
                    encoding_data.extend_from_slice(&encoded);
                }
            }

            result.push(EncodedRecord {
                ts_delta: rec.ts_delta,
                svc_id: rec.svc_id,
                level: rec.level.clone(),
                pat_id: rec.pat_id,
                param_encoding: ParamEncoding {
                    ref_idx: (i - ref_idx) as u16,
                    data: encoding_data,
                },
            });
        }

        result
    }

    /// 解码 XOR-P 编码的记录（需传入参考行的参数值）
    pub fn decode_xor(encoded: &EncodedRecord, ref_params: &[String]) -> Vec<String> {
        let mut params = Vec::new();
        let data = &encoded.param_encoding.data;
        let mut offset = 0;

        if data.len() < 4 {
            return params;
        }
        let param_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        offset += 4;

        if encoded.param_encoding.ref_idx == 0 {
            // 参考行：直接读取原始参数
            for _ in 0..param_count {
                let len = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
                offset += 4;
                let s = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
                offset += len;
                params.push(s);
            }
        } else {
            // 非参考行：XOR-P 解码
            for i in 0..param_count {
                let base = ref_params.get(i).map(|s| s.as_str()).unwrap_or("");
                let (param, consumed) = Self::decode_xor_param_64bit(&data[offset..], base);
                params.push(param);
                offset += consumed;
            }
        }

        params
    }

    // ---------- 私有工具 ----------

    fn tokenize(msg: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        for ch in msg.chars() {
            if ch.is_whitespace() {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                tokens.push(ch.to_string());
            } else if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' || ch == ':' {
                current.push(ch);
            } else {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                tokens.push(ch.to_string());
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }
        tokens
    }

    fn raw_template(tokens: &[String]) -> Vec<TemplatePart> {
        tokens.iter().map(|t| TemplatePart::Literal(t.clone())).collect()
    }

    fn build_template_from_mask(first: &[String], is_fixed: &[bool]) -> Vec<TemplatePart> {
        first
            .iter()
            .zip(is_fixed.iter())
            .map(|(token, fixed)| {
                if *fixed {
                    TemplatePart::Literal(token.clone())
                } else {
                    TemplatePart::Param
                }
            })
            .collect()
    }

    fn build_record(log: &LogLine, pat_id: u16, params: Vec<String>, idx: usize) -> TemplateRecord {
        TemplateRecord {
            original_idx: idx,
            ts_delta: log.ts as i64,
            svc_id: 0, // 由调用方后续映射
            level: log.level.clone(),
            pat_id,
            params,
        }
    }

    fn get_or_create_template(
        templates: &mut Vec<Template>,
        map: &mut HashMap<String, u16>,
        parts: Vec<TemplatePart>,
    ) -> u16 {
        let sig = Self::template_signature(&parts);
        if let Some(&id) = map.get(&sig) {
            return id;
        }
        let id = templates.len() as u16;
        templates.push(Template { id, parts });
        map.insert(sig, id);
        id
    }

    fn template_signature(parts: &[TemplatePart]) -> String {
        parts
            .iter()
            .map(|p| match p {
                TemplatePart::Literal(s) => s.clone(),
                TemplatePart::Param => "*".to_string(),
            })
            .collect::<String>()
    }

    fn extract_params(tokens: &[String], template: &Template) -> Vec<String> {
        let mut params = Vec::new();
        for (token, part) in tokens.iter().zip(template.parts.iter()) {
            if matches!(part, TemplatePart::Param) {
                params.push(token.clone());
            }
        }
        params
    }

    fn extract_params_with_mask(tokens: &[String], is_fixed: &[bool]) -> Vec<String> {
        tokens
            .iter()
            .zip(is_fixed.iter())
            .filter_map(|(t, fixed)| if !fixed { Some(t.clone()) } else { None })
            .collect()
    }

    // ---------- 64-bit XOR-P 编解码 ----------

    /// 对单个参数值做 64-bit 对齐 XOR-P 编码
    ///
    /// 格式：
    ///   u16  num_chunks    ← 多少个 8-byte 块
    ///   u16  original_len  ← 原始字符串字节长度（解码时截断用）
    ///   [u8] bitmap        ← 每 bit 表示对应块是否非零（1 = 有差异）
    ///   [u8] literals      ← 仅对 bitmap=1 的块存储 8-byte XOR 值
    pub fn xor_param_64bit(curr: &str, base: &str) -> Vec<u8> {
        let curr_b = curr.as_bytes();
        let base_b = base.as_bytes();
        let max_len = ((curr_b.len().max(base_b.len()) + 7) / 8) * 8;
        let num_chunks = max_len / 8;
        let bitmap_len = (num_chunks + 7) / 8;

        let mut bitmap = vec![0u8; bitmap_len];
        let mut literals = Vec::new();

        for i in 0..num_chunks {
            let off = i * 8;
            let c = Self::read_u64_le(curr_b, off, max_len);
            let b = Self::read_u64_le(base_b, off, max_len);
            let x = c ^ b;

            if x != 0 {
                bitmap[i / 8] |= 1 << (i % 8);
                literals.extend_from_slice(&x.to_le_bytes());
            }
        }

        let mut result = Vec::with_capacity(4 + bitmap_len + literals.len());
        result.extend_from_slice(&(num_chunks as u16).to_le_bytes());
        result.extend_from_slice(&(curr_b.len() as u16).to_le_bytes());
        result.extend_from_slice(&bitmap);
        result.extend_from_slice(&literals);
        result
    }

    pub fn decode_xor_param_64bit(data: &[u8], base: &str) -> (String, usize) {
        if data.len() < 2 {
            return (base.to_string(), 0);
        }
        let num_chunks = u16::from_le_bytes([data[0], data[1]]) as usize;
        let original_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let bitmap_len = (num_chunks + 7) / 8;
        let bitmap = &data[4..4 + bitmap_len];

        let base_b = base.as_bytes();
        let max_len = num_chunks * 8;
        let mut buf = vec![0u8; max_len];
        let copy_len = base_b.len().min(max_len);
        buf[..copy_len].copy_from_slice(&base_b[..copy_len]);

        let mut lit_offset = 4 + bitmap_len;
        let mut result_u64s = vec![0u64; num_chunks];

        for i in 0..num_chunks {
            result_u64s[i] = Self::read_u64_le(&buf, i * 8, max_len);
        }

        for i in 0..num_chunks {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            if bitmap[byte_idx] & (1 << bit_idx) != 0 {
                let x = u64::from_le_bytes([
                    data[lit_offset],
                    data[lit_offset + 1],
                    data[lit_offset + 2],
                    data[lit_offset + 3],
                    data[lit_offset + 4],
                    data[lit_offset + 5],
                    data[lit_offset + 6],
                    data[lit_offset + 7],
                ]);
                result_u64s[i] ^= x;
                lit_offset += 8;
            }
        }

        for (i, v) in result_u64s.iter().enumerate() {
            let off = i * 8;
            buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }

        let s = String::from_utf8_lossy(&buf[..original_len]).to_string();
        (s, lit_offset)
    }

    pub fn read_u64_le(bytes: &[u8], offset: usize, len: usize) -> u64 {
        let mut buf = [0u8; 8];
        let avail = len.saturating_sub(offset);
        let copy = avail.min(8).min(bytes.len().saturating_sub(offset));
        if copy > 0 && offset < bytes.len() {
            buf[..copy].copy_from_slice(&bytes[offset..offset + copy]);
        }
        u64::from_le_bytes(buf)
    }
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(idx: usize, msg: &str) -> LogLine {
        LogLine {
            ts: 1000 + idx as u64 * 100,
            service: "app".to_string(),
            level: "I".to_string(),
            message: msg.to_string(),
        }
    }

    #[test]
    fn test_template_extraction_basic() {
        let logs = vec![
            make_log(0, "User 12345 logged in from 192.168.1.1"),
            make_log(1, "User 67890 logged in from 192.168.1.2"),
            make_log(2, "User 11111 logged in from 192.168.1.3"),
            make_log(3, "Query SELECT * FROM users executed in 45ms"),
            make_log(4, "Query SELECT * FROM orders executed in 120ms"),
        ];

        let batch = TemplateExtractor::extract(&logs);

        // 应提取 2 个模板（User 行和 Query 行）
        assert_eq!(batch.templates.len(), 2);
        assert_eq!(batch.records.len(), 5);

        // User 模板应有 2 个参数（user_id, ip）
        let user_rec = &batch.records[0];
        assert_eq!(user_rec.params.len(), 2);
        assert_eq!(user_rec.params[0], "12345");
        assert_eq!(user_rec.params[1], "192.168.1.1");

        // Query 模板应有 1 个参数（table）和 1 个参数（time）？
        // 实际上 "SELECT * FROM users" 中 "users" 是参数，"45ms" 是参数
        let query_rec = &batch.records[3];
        assert!(query_rec.params.len() >= 1);
    }

    #[test]
    fn test_new_template_fallback() {
        let logs = vec![
            make_log(0, "User 12345 logged in"),
            make_log(1, "Completely different format with no similarity at all"),
        ];

        let batch = TemplateExtractor::extract(&logs);

        // 两条不同长度，各自成为独立模板
        assert_eq!(batch.templates.len(), 2);
        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.records[0].params.len(), 0); // 独立模板无参数
        assert_eq!(batch.records[1].params.len(), 0);
    }

    #[test]
    fn test_xor_roundtrip() {
        let base = "192.168.1.100";
        let curr = "192.168.1.200";

        let encoded = TemplateExtractor::xor_param_64bit(curr, base);
        let (decoded, _) = TemplateExtractor::decode_xor_param_64bit(&encoded, base);

        assert_eq!(decoded, curr);
    }

    #[test]
    fn test_xor_identical() {
        let s = "hello_world_12345";
        let encoded = TemplateExtractor::xor_param_64bit(s, s);
        // 完全相同：bitmap 全零，只有头部
        // 17 bytes → 3 chunks → bitmap = ceil(3/8) = 1 byte
        // 格式：u16 num_chunks + u16 original_len + bitmap = 2 + 2 + 1 = 5
        assert_eq!(encoded.len(), 5);
        let (decoded, _) = TemplateExtractor::decode_xor_param_64bit(&encoded, s);
        assert_eq!(decoded, s);
    }

    #[test]
    fn test_xor_encode_decode_batch() {
        let logs = vec![
            make_log(0, "User 12345 logged in from 192.168.1.1"),
            make_log(1, "User 67890 logged in from 192.168.1.2"),
            make_log(2, "User 11111 logged in from 192.168.1.3"),
        ];

        let batch = TemplateExtractor::extract(&logs);
        let encoded = TemplateExtractor::encode_xor(&batch, 16);

        assert_eq!(encoded.len(), 3);

        // 首行 ref_idx=0，存原始值
        assert_eq!(encoded[0].param_encoding.ref_idx, 0);

        // 第二行 ref_idx=1，参考第一行
        assert_eq!(encoded[1].param_encoding.ref_idx, 1);

        // 解码验证
        let ref_params = batch.records[0].params.clone();
        let decoded = TemplateExtractor::decode_xor(&encoded[1], &ref_params);
        assert_eq!(decoded, batch.records[1].params);
    }

    #[test]
    fn test_xor_reset_interval() {
        let logs: Vec<LogLine> = (0..20)
            .map(|i| make_log(i, &format!("User {} logged in", i)))
            .collect();

        let batch = TemplateExtractor::extract(&logs);
        let encoded = TemplateExtractor::encode_xor(&batch, 5); // 每 5 行重置

        // 行 0: ref_idx=0
        assert_eq!(encoded[0].param_encoding.ref_idx, 0);
        // 行 4: ref_idx=4（仍在同一参考链）
        assert_eq!(encoded[4].param_encoding.ref_idx, 4);
        // 行 5: ref_idx=0（重置，参考行 5 自身）
        assert_eq!(encoded[5].param_encoding.ref_idx, 0);
    }

    #[test]
    fn test_64bit_alignment() {
        // 验证 8 字节对齐：长度 5 和长度 13 都 padding 到 8/16
        let short = "12345";        // 5 bytes → 1 chunk (8 bytes)
        let long = "1234567890123"; // 13 bytes → 2 chunks (16 bytes)

        let enc1 = TemplateExtractor::xor_param_64bit(short, short);
        let enc2 = TemplateExtractor::xor_param_64bit(long, long);

        // 相同内容编码后：num_chunks 不同，bitmap 都应为零
        let chunks1 = u16::from_le_bytes([enc1[0], enc1[1]]);
        let chunks2 = u16::from_le_bytes([enc2[0], enc2[1]]);
        assert_eq!(chunks1, 1);
        assert_eq!(chunks2, 2);

        // 验证 original_len 正确存储
        let len1 = u16::from_le_bytes([enc1[2], enc1[3]]);
        let len2 = u16::from_le_bytes([enc2[2], enc2[3]]);
        assert_eq!(len1, 5);
        assert_eq!(len2, 13);
    }
// 将以下内容追加到 src/agent/template.rs 的 #[cfg(test)] mod tests 中

#[test]
fn test_extract_empty_batch() {
    let empty: Vec<LogLine> = vec![];
    let batch = TemplateExtractor::extract(&empty);
    assert!(batch.templates.is_empty());
    assert!(batch.records.is_empty());
}

#[test]
fn test_extract_single_log() {
    let logs = vec![make_log(0, "only one log message")];
    let batch = TemplateExtractor::extract(&logs);
    assert_eq!(batch.templates.len(), 1);
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0].params.len(), 0); // 单条无参数
}

#[test]
fn test_extract_identical_messages() {
    // 完全相同的 message 应归为同一模板，无参数
    let logs: Vec<LogLine> = (0..5)
        .map(|i| make_log(i, "Identical log message here"))
        .collect();
    let batch = TemplateExtractor::extract(&logs);
    assert_eq!(batch.templates.len(), 1);
    assert_eq!(batch.records.len(), 5);
    for rec in &batch.records {
        assert_eq!(rec.params.len(), 0);
    }
}

#[test]
fn test_extract_unicode_params() {
    let logs = vec![
        make_log(0, "用户 张三 登录成功"),
        make_log(1, "用户 李四 登录成功"),
        make_log(2, "用户 王五 登录成功"),
    ];
    let batch = TemplateExtractor::extract(&logs);
    assert_eq!(batch.templates.len(), 1);
    assert_eq!(batch.records.len(), 3);
    assert_eq!(batch.records[0].params.len(), 1);
    assert_eq!(batch.records[0].params[0], "张三");
    assert_eq!(batch.records[1].params[0], "李四");
}

#[test]
fn test_extract_emoji_and_special() {
    let logs = vec![
        make_log(0, "🎉 Party at 2026-05-15 with 🎂"),
        make_log(1, "🎉 Party at 2026-05-16 with 🎁"),
    ];
    let batch = TemplateExtractor::extract(&logs);
    assert_eq!(batch.templates.len(), 1);
    assert_eq!(batch.records.len(), 2);
    // "2026-05-15" 和 "🎂"/"🎁" 是参数
    assert!(batch.records[0].params.len() >= 1);
}

#[test]
fn test_extract_very_long_message() {
    let long_base = "a".repeat(4096);
    let logs = vec![
        make_log(0, &format!("{} {}", long_base, "suffix1")),
        make_log(1, &format!("{} {}", long_base, "suffix2")),
    ];
    let batch = TemplateExtractor::extract(&logs);
    assert_eq!(batch.templates.len(), 1);
    assert_eq!(batch.records.len(), 2);
}

#[test]
fn test_extract_no_common_pattern() {
    // 同一长度但完全不同内容
    let logs = vec![
        make_log(0, "Alpha beta gamma"),
        make_log(1, "One two three four"),
        make_log(2, "Xyzzy plugh plover"),
    ];
    let batch = TemplateExtractor::extract(&logs);
    // 3 条同长度，但逐 token 比较后无公共模式
    // 实际行为：组内聚类，first 与后续比较，标记变化位置
    // "Alpha" vs "One" -> 不同 -> Param
    // "beta" vs "two" -> 不同 -> Param
    // ... 最终可能整个模板都是 Param
    assert!(batch.templates.len() >= 1);
    assert_eq!(batch.records.len(), 3);
}

#[test]
fn test_xor_param_length_mismatch() {
    let base = "short";
    let curr = "this is a much longer string with many characters";
    let encoded = TemplateExtractor::xor_param_64bit(curr, base);
    let (decoded, _) = TemplateExtractor::decode_xor_param_64bit(&encoded, base);
    assert_eq!(decoded, curr);
}

#[test]
fn test_xor_param_base_longer_than_curr() {
    let base = "this is the long base string for testing";
    let curr = "tiny";
    let encoded = TemplateExtractor::xor_param_64bit(curr, base);
    let (decoded, _) = TemplateExtractor::decode_xor_param_64bit(&encoded, base);
    assert_eq!(decoded, curr);
}

#[test]
fn test_xor_param_empty_string() {
    let base = "nonempty";
    let curr = "";
    let encoded = TemplateExtractor::xor_param_64bit(curr, base);
    let (decoded, _) = TemplateExtractor::decode_xor_param_64bit(&encoded, base);
    assert_eq!(decoded, "");
}

#[test]
fn test_xor_param_exactly_8_bytes() {
    let base = "12345678";
    let curr = "abcdefgh";
    let encoded = TemplateExtractor::xor_param_64bit(curr, base);
    // 1 chunk, bitmap 可能非零
    let chunks = u16::from_le_bytes([encoded[0], encoded[1]]);
    assert_eq!(chunks, 1);
    let (decoded, _) = TemplateExtractor::decode_xor_param_64bit(&encoded, base);
    assert_eq!(decoded, curr);
}

#[test]
fn test_xor_param_exactly_16_bytes() {
    let base = "1234567890123456";
    let curr = "abcdefghijklmnop";
    let encoded = TemplateExtractor::xor_param_64bit(curr, base);
    let chunks = u16::from_le_bytes([encoded[0], encoded[1]]);
    assert_eq!(chunks, 2);
    let (decoded, _) = TemplateExtractor::decode_xor_param_64bit(&encoded, base);
    assert_eq!(decoded, curr);
}

#[test]
fn test_encode_xor_empty_params() {
    // 无参数日志的 XOR 编码
    let logs = vec![
        make_log(0, "No params here"),
        make_log(1, "No params here"),
    ];
    let batch = TemplateExtractor::extract(&logs);
    let encoded = TemplateExtractor::encode_xor(&batch, 16);
    assert_eq!(encoded.len(), 2);
    // 参数数量为 0，编码数据应很短
    assert_eq!(encoded[0].param_encoding.data.len(), 4); // 仅 u32 param_count = 0
}

#[test]
fn test_template_batch_pattern_table_roundtrip() {
    let logs = vec![
        make_log(0, "User 12345 logged in from 192.168.1.1"),
        make_log(1, "User 67890 logged in from 192.168.1.2"),
        make_log(2, "Query SELECT * FROM users executed in 45ms"),
        make_log(3, "Query SELECT * FROM orders executed in 120ms"),
    ];
    let batch = TemplateExtractor::extract(&logs);
    let table = batch.serialize_pattern_table();
    let templates = TemplateBatch::deserialize_pattern_table(&table).unwrap();

    assert_eq!(templates.len(), batch.templates.len());
    for (a, b) in batch.templates.iter().zip(templates.iter()) {
        assert_eq!(a.parts.len(), b.parts.len());
        for (pa, pb) in a.parts.iter().zip(b.parts.iter()) {
            assert_eq!(pa, pb);
        }
    }
}

#[test]
fn test_template_deserialize_error_truncated() {
    let bad_data = vec![0x01, 0x00]; // 声称 1 个 part，但无后续数据
    let result = Template::deserialize(&bad_data);
    assert!(result.is_err());
}

#[test]
fn test_template_deserialize_error_unknown_tag() {
    let mut buf = vec![0x01, 0x00]; // 1 part
    buf.push(0x99); // 未知 tag
    let result = Template::deserialize(&buf);
    assert!(result.is_err());
}

#[test]
fn test_read_u64_le_bounds() {
    let bytes = b"hello";
    assert_eq!(TemplateExtractor::read_u64_le(bytes, 0, 5), 0x6f6c6c6568); // "hello" little-endian
    assert_eq!(TemplateExtractor::read_u64_le(bytes, 10, 5), 0); // offset 越界
    assert_eq!(TemplateExtractor::read_u64_le(bytes, 3, 5), 0x6f6c); // 部分读取
}

#[test]
fn test_tokenize_various() {
    let cases = vec![
        ("simple", vec!["simple"]),
        ("two words", vec!["two", " ", "words"]),
        ("a,b.c", vec!["a", ",", "b.c"]),
        ("num123_456", vec!["num123_456"]),
    ];
    for (input, expected) in cases {
        let tokens = TemplateExtractor::tokenize(input);
        assert_eq!(tokens, expected.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    }
}
}

// ==================== PatternTable 序列化（供 storage.rs 使用）====================

impl Template {
    /// 序列化为字节流（TLV 格式）
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.parts.len() as u16).to_le_bytes());
        for part in &self.parts {
            match part {
                TemplatePart::Literal(s) => {
                    buf.push(0x01);
                    let bytes = s.as_bytes();
                    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    buf.extend_from_slice(bytes);
                }
                TemplatePart::Param => {
                    buf.push(0x02);
                }
            }
        }
        buf
    }

    /// 从字节流反序列化
    pub fn deserialize(data: &[u8]) -> io::Result<(Self, usize)> {
        if data.len() < 2 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "template too short"));
        }
        let part_count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut offset = 2;
        let mut parts = Vec::with_capacity(part_count);
        for _ in 0..part_count {
            if offset >= data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "template part tag"));
            }
            let tag = data[offset];
            offset += 1;
            if tag == 0x01 {
                if offset + 4 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "literal len"));
                }
                let len = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
                offset += 4;
                if offset + len > data.len() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "literal bytes"));
                }
                let s = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
                parts.push(TemplatePart::Literal(s));
                offset += len;
            } else if tag == 0x02 {
                parts.push(TemplatePart::Param);
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown part tag"));
            }
        }
        Ok((Template { id: 0, parts }, offset))
    }
}

impl TemplateBatch {
    /// 序列化整个 PatternTable
    pub fn serialize_pattern_table(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.templates.len() as u16).to_le_bytes());
        for t in &self.templates {
            buf.extend_from_slice(&t.serialize());
        }
        buf
    }

    /// 从字节流反序列化 PatternTable
    pub fn deserialize_pattern_table(data: &[u8]) -> io::Result<Vec<Template>> {
        if data.len() < 2 {
            return Ok(Vec::new());
        }
        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut offset = 2;
        let mut templates = Vec::with_capacity(count);
        for i in 0..count {
            let (mut t, consumed) = Template::deserialize(&data[offset..])?;
            t.id = i as u16;
            templates.push(t);
            offset += consumed;
        }
        Ok(templates)
    }
}