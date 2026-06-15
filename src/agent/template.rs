//! mini-obs/agent/template.rs
//! 模板提取与 64-bit XOR-P 参数编码
//!
//! 核心设计：
//! - Batch 级模板提取：Prefix Tree (Trie) 聚类 + 自底向上子树合并
//! - 无匹配 → 自动创建新模板，保留原始字符
//! - 强类型参数：对整数、十六进制、IPv4 等常见日志参数做二进制编码
//! - XOR-P 按 ARM64 字长（64-bit / 8 bytes）对齐操作（保留，供 Legacy 路径使用）
//! - 编码格式：bitmap + literals，紧凑且 SIMD 友好

use std::collections::HashMap;
use std::io;

use crate::shared::format::LogLine;

// ==================== 数据模型 ====================

/// 参数类型：用于将文本参数压缩为强类型二进制
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamType {
    /// 普通字符串，按 UTF-8 原样存储
    String = 0,
    /// 有符号整数（i64 little-endian）
    Integer = 1,
    /// 十六进制整数（0x...，u64 little-endian）
    Hex = 2,
    /// IPv4 地址（4 bytes）
    IPv4 = 3,
    /// HDFS 风格 Block ID：blk_<integer>（i64 + 1 byte 前缀标记）
    BlockId = 4,
    /// IPv4:Port 组合（4 bytes IP + 2 bytes port）
    IPv4Port = 5,
    /// 时间戳分量：YYMMDD / HHMMSS / SSS 等紧凑格式
    Timestamp = 6,
    /// 文件路径：以 '/' 开头的路径，保持字符串但标记类型
    Path = 7,
}

impl ParamType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(ParamType::String),
            1 => Some(ParamType::Integer),
            2 => Some(ParamType::Hex),
            3 => Some(ParamType::IPv4),
            4 => Some(ParamType::BlockId),
            5 => Some(ParamType::IPv4Port),
            6 => Some(ParamType::Timestamp),
            7 => Some(ParamType::Path),
            _ => None,
        }
    }
}

/// 强类型参数：类型 + 二进制表示
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedParam {
    pub ty: ParamType,
    pub bytes: Vec<u8>,
}

impl TypedParam {
    /// 从字符串自动检测类型并编码。
    /// 仅在能保证无损往返时才启用强类型编码。
    pub fn from_str(s: &str) -> Self {
        if let Some(bytes) = Self::try_ipv4_port(s) {
            return Self { ty: ParamType::IPv4Port, bytes };
        }
        if let Some(bytes) = Self::try_ipv4(s) {
            return Self { ty: ParamType::IPv4, bytes };
        }
        if let Some(bytes) = Self::try_timestamp(s) {
            return Self { ty: ParamType::Timestamp, bytes };
        }
        if let Some(bytes) = Self::try_block_id(s) {
            return Self { ty: ParamType::BlockId, bytes };
        }
        if let Some(bytes) = Self::try_hex(s) {
            return Self { ty: ParamType::Hex, bytes };
        }
        if let Some(bytes) = Self::try_integer(s) {
            return Self { ty: ParamType::Integer, bytes };
        }
        if Self::looks_like_path(s) {
            return Self {
                ty: ParamType::Path,
                bytes: s.as_bytes().to_vec(),
            };
        }
        Self {
            ty: ParamType::String,
            bytes: s.as_bytes().to_vec(),
        }
    }

    /// 解码为原始字符串
    pub fn to_string(&self) -> String {
        match self.ty {
            ParamType::String => String::from_utf8_lossy(&self.bytes).to_string(),
            ParamType::Integer => {
                if self.bytes.len() >= 8 {
                    let v = i64::from_le_bytes([
                        self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                        self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7],
                    ]);
                    format!("{}", v)
                } else {
                    String::from_utf8_lossy(&self.bytes).to_string()
                }
            }
            ParamType::Hex => {
                if self.bytes.len() >= 8 {
                    let v = u64::from_le_bytes([
                        self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                        self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7],
                    ]);
                    format!("0x{:x}", v)
                } else {
                    String::from_utf8_lossy(&self.bytes).to_string()
                }
            }
            ParamType::IPv4 => {
                if self.bytes.len() >= 4 {
                    format!("{}.{}.{}.{}", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3])
                } else {
                    String::from_utf8_lossy(&self.bytes).to_string()
                }
            }
            ParamType::BlockId => {
                if self.bytes.len() >= 9 {
                    let v = i64::from_le_bytes([
                        self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3],
                        self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7],
                    ]);
                    match self.bytes[8] {
                        b'b' => format!("blk_{}", v),
                        _ => format!("blk_{}", v),
                    }
                } else {
                    String::from_utf8_lossy(&self.bytes).to_string()
                }
            }
            ParamType::IPv4Port => {
                if self.bytes.len() >= 6 {
                    let ip = format!("{}.{}.{}.{}", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]);
                    let port = u16::from_le_bytes([self.bytes[4], self.bytes[5]]);
                    format!("{}:{}", ip, port)
                } else {
                    String::from_utf8_lossy(&self.bytes).to_string()
                }
            }
            ParamType::Timestamp => {
                if self.bytes.len() >= 4 && self.bytes[0] == 0 {
                    format!("{:02}{:02}{:02}", self.bytes[1], self.bytes[2], self.bytes[3])
                } else {
                    String::from_utf8_lossy(&self.bytes).to_string()
                }
            }
            ParamType::Path => String::from_utf8_lossy(&self.bytes).to_string(),
        }
    }

    pub(crate) fn try_integer(s: &str) -> Option<Vec<u8>> {
        // 拒绝前导零、正号等会导致往返不一致的格式
        if s.is_empty() || s == "-" {
            return None;
        }
        let mut chars = s.chars();
        let first = chars.next().unwrap();
        if first == '+' {
            return None;
        }
        if first == '0' && s.len() > 1 {
            return None; // 前导零，保持字符串
        }
        if first == '-' && s.len() > 1 && s.as_bytes()[1] == b'0' {
            return None; // -0xxx 保持字符串
        }
        for c in chars {
            if !c.is_ascii_digit() {
                return None;
            }
        }
        let v: i64 = s.parse().ok()?;
        Some(v.to_le_bytes().to_vec())
    }

    pub(crate) fn try_hex(s: &str) -> Option<Vec<u8>> {
        if s.len() < 3 {
            return None;
        }
        let bytes = s.as_bytes();
        if bytes[0] != b'0' || (bytes[1] != b'x' && bytes[1] != b'X') {
            return None;
        }
        // 只接受小写 0x 前缀，避免大小写往返不一致
        if bytes[1] != b'x' {
            return None;
        }
        // 拒绝前导零，如 0x00abc
        if s.len() > 3 && bytes[2] == b'0' {
            return None;
        }
        let payload = &s[2..];
        if payload.is_empty() {
            return None;
        }
        for c in payload.chars() {
            if !c.is_ascii_hexdigit() {
                return None;
            }
        }
        let v = u64::from_str_radix(payload, 16).ok()?;
        Some(v.to_le_bytes().to_vec())
    }

    pub(crate) fn try_ipv4(s: &str) -> Option<Vec<u8>> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut result = Vec::with_capacity(4);
        for p in parts {
            if p.is_empty() || p.len() > 3 {
                return None;
            }
            // 拒绝前导零
            if p.len() > 1 && p.as_bytes()[0] == b'0' {
                return None;
            }
            let v: u8 = p.parse().ok()?;
            result.push(v);
        }
        Some(result)
    }

    pub(crate) fn try_ipv4_port(s: &str) -> Option<Vec<u8>> {
        // 格式：IP:port，如 10.251.73.220:50010
        if let Some(colon_pos) = s.rfind(':') {
            let ip_part = &s[..colon_pos];
            let port_part = &s[colon_pos + 1..];
            if port_part.is_empty() || port_part.len() > 5 {
                return None;
            }
            // 拒绝前导零
            if port_part.len() > 1 && port_part.as_bytes()[0] == b'0' {
                return None;
            }
            let port: u16 = port_part.parse().ok()?;
            let ip_bytes = Self::try_ipv4(ip_part)?;
            let mut result = ip_bytes;
            result.extend_from_slice(&port.to_le_bytes());
            return Some(result);
        }
        None
    }

    pub(crate) fn try_block_id(s: &str) -> Option<Vec<u8>> {
        // 格式：blk_<integer> 或 blk_-<integer>
        if !s.starts_with("blk_") {
            return None;
        }
        let num_part = &s[4..];
        if num_part.is_empty() {
            return None;
        }
        // 拒绝前导零，如 blk_0123
        if num_part.len() > 1 && num_part.as_bytes()[0] == b'0' {
            return None;
        }
        if num_part.len() > 2 && num_part.starts_with("-0") {
            return None;
        }
        let v: i64 = num_part.parse().ok()?;
        let mut result = v.to_le_bytes().to_vec();
        result.push(b'b'); // 前缀标记 'b' 表示 blk_
        Some(result)
    }

    pub(crate) fn try_timestamp(s: &str) -> Option<Vec<u8>> {
        // 仅处理 6 位日期/时间分量，如 081109 / 203615。
        // 1-3 位数字保持 Integer，避免与带前导零的常规数字混淆。
        if s.len() == 6 && s.chars().all(|c| c.is_ascii_digit()) {
            let v: u32 = s.parse().ok()?;
            let a = (v / 10000) as u8;       // 高 2 位
            let b = ((v / 100) % 100) as u8; // 中 2 位
            let c = (v % 100) as u8;         // 低 2 位
            if a <= 99 && b <= 99 && c <= 99 {
                // 0xYYMMDD 与 0xHHMMSS 在值域上可能重叠；
                // 统一按 6 位数字处理，解码时输出原始 6 位数字，符合往返要求。
                return Some(vec![0, a, b, c]);
            }
        }
        None
    }

    pub(crate) fn looks_like_path(s: &str) -> bool {
        s.starts_with('/') && s.len() > 1
    }
}

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
    /// 强类型参数值，与模板中的 Param 一一对应
    pub params: Vec<TypedParam>,
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
    /// 编码后字节流：u32(param_count) + [u8 type + payload]...
    pub data: Vec<u8>,
}

// ==================== 模板提取器 ====================

pub struct TemplateExtractor;

impl TemplateExtractor {
    /// 从一批日志中提取模板
    ///
    /// 算法：Prefix Tree (Trie) + 自底向上子树合并
    ///
    /// 1. 改进分词：按空格分割，不保留空格 token，标点作为独立 token
    /// 2. 按 token 类型序列预分组（纯类型，不依赖首 token 值）
    /// 3. 每组内构建值-Trie：每条消息是一条从根到叶的路径
    /// 4. 自底向上合并结构相同的子树 → 多子节点合并为 Param 节点
    /// 5. 从合并后的 Trie 提取模板并分配记录
    pub fn extract(batch: &[LogLine]) -> TemplateBatch {
        if batch.is_empty() {
            return TemplateBatch::default();
        }

        // 1. 改进分词（不保留空白 token）
        let tokenized: Vec<Vec<String>> = batch.iter().map(|l| Self::tokenize_v2(&l.message)).collect();

        // 2. 按 token 类型序列预分组（纯类型序列，无首 token 值依赖）
        let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, tokens) in tokenized.iter().enumerate() {
            let type_seq = Self::type_sequence(tokens);
            groups.entry(type_seq).or_default().push(i);
        }

        let mut templates: Vec<Template> = Vec::new();
        let mut template_map: HashMap<String, u16> = HashMap::new();
        let mut records = Vec::with_capacity(batch.len());

        // 3. 对每组执行位置对齐分析，提取模板
        for (_type_seq, indices) in &groups {
            let idx_list: Vec<usize> = indices.clone();
            if idx_list.len() < 2 {
                // 单条消息：创建全 Literal 模板
                for &i in &idx_list {
                    let log = &batch[i];
                    let raw: Vec<TemplatePart> = tokenized[i].iter()
                        .map(|t| TemplatePart::Literal(t.clone())).collect();
                    if raw.is_empty() { continue; }
                    let pid = Self::get_or_create_template(&mut templates, &mut template_map, raw);
                    records.push(Self::build_record(log, pid, vec![], i));
                }
                continue;
            }

            // 位置对齐：逐位置比较，相同=Literal，不同=Param
            let first = &tokenized[idx_list[0]];
            let n_tokens = first.len();
            // 检查组内所有消息 token 数相同（类型序列已保证）
            let mut is_fixed = vec![true; n_tokens];
            for &idx in &idx_list[1..] {
                let tokens = &tokenized[idx];
                for j in 0..n_tokens.min(tokens.len()) {
                    if tokenized[idx_list[0]][j] != tokens[j] {
                        is_fixed[j] = false;
                    }
                }
            }

            let fixed_count = is_fixed.iter().filter(|&&f| f).count();
            let min_fixed = (n_tokens / 4).max(2);
            let degenerate = fixed_count < min_fixed;

            if degenerate {
                // 退化：按前几个 token 的精确值子分组
                let mut sub_groups: HashMap<String, Vec<usize>> = HashMap::new();
                for &idx in &idx_list {
                    let tokens = &tokenized[idx];
                    let prefix: String = tokens.iter()
                        .take(4.min(tokens.len()))
                        .map(|t| t.clone())
                        .collect::<Vec<_>>()
                        .join("\0");
                    sub_groups.entry(prefix).or_default().push(idx);
                }

                for (_prefix, sub_indices) in sub_groups {
                    if sub_indices.len() < 2 {
                        for &i in &sub_indices {
                            let raw: Vec<TemplatePart> = tokenized[i].iter()
                                .map(|t| TemplatePart::Literal(t.clone())).collect();
                            if raw.is_empty() { continue; }
                            let pid = Self::get_or_create_template(&mut templates, &mut template_map, raw);
                            records.push(Self::build_record(&batch[i], pid, vec![], i));
                        }
                        continue;
                    }

                    let sub_first = &tokenized[sub_indices[0]];
                    let mut sub_fixed = vec![true; sub_first.len()];
                    for &idx in &sub_indices[1..] {
                        let tokens = &tokenized[idx];
                        for j in 0..sub_first.len().min(tokens.len()) {
                            if sub_first[j] != tokens[j] {
                                sub_fixed[j] = false;
                            }
                        }
                    }
                    let parts = Self::mask_to_parts(sub_first, &sub_fixed);
                    let pid = Self::get_or_create_template(&mut templates, &mut template_map, parts);
                    for &idx in &sub_indices {
                        let params = Self::extract_params_from_mask(&tokenized[idx], &sub_fixed);
                        records.push(Self::build_record(&batch[idx], pid, params, idx));
                    }
                }
            } else {
                let parts = Self::mask_to_parts(first, &is_fixed);
                let pid = Self::get_or_create_template(&mut templates, &mut template_map, parts);
                for &idx in &idx_list {
                    let params = Self::extract_params_from_mask(&tokenized[idx], &is_fixed);
                    records.push(Self::build_record(&batch[idx], pid, params, idx));
                }
            }
        }

        // 4. 恢复原始顺序
        records.sort_by_key(|r| r.original_idx);

        // 5. 计算时间戳差值
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

    // ---------- Prefix Tree (Trie) 实现 ----------

    /// 对 TemplateBatch 应用 64-bit XOR-P 编码
    ///
    /// ref_reset: 每 N 行重置参考行（默认 16，查询友好）
    pub fn encode_xor(batch: &TemplateBatch, ref_reset: usize) -> Vec<EncodedRecord> {
        let mut result = Vec::with_capacity(batch.records.len());
        let mut ref_params: Vec<TypedParam> = Vec::new();
        let mut ref_idx = 0usize;

        for (i, rec) in batch.records.iter().enumerate() {
            let mut encoding_data = Vec::new();
            encoding_data.extend_from_slice(&(rec.params.len() as u32).to_le_bytes());

            // 当参数数量或类型与参考行不一致时，当前行必须作为新的参考行，
            // 否则 zip 截断会导致参数丢失，解压后数据损坏。
            let need_new_ref = i % ref_reset == 0
                || rec.params.len() != ref_params.len()
                || rec.params.iter().zip(ref_params.iter()).any(|(a, b)| a.ty != b.ty);

            if need_new_ref {
                // 重置参考行：直接存储原始参数值（强类型二进制）
                ref_params = rec.params.clone();
                ref_idx = i;
                for p in &rec.params {
                    encoding_data.push(p.ty as u8);
                    encoding_data.extend_from_slice(&(p.bytes.len() as u32).to_le_bytes());
                    encoding_data.extend_from_slice(&p.bytes);
                }
            } else {
                // 非参考行：XOR-P 编码（在强类型二进制上执行）
                for (p, base) in rec.params.iter().zip(ref_params.iter()) {
                    encoding_data.push(p.ty as u8);
                    let encoded = Self::xor_param_bytes(&p.bytes, &base.bytes);
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

    /// 解码 XOR-P 编码的记录（需传入参考行的强类型参数）
    pub fn decode_xor(encoded: &EncodedRecord, ref_params: &[TypedParam]) -> Vec<TypedParam> {
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
                if offset >= data.len() {
                    break;
                }
                let ty = ParamType::from_u8(data[offset]).unwrap_or(ParamType::String);
                offset += 1;
                if offset + 4 > data.len() {
                    break;
                }
                let len = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
                offset += 4;
                if offset + len > data.len() {
                    break;
                }
                let bytes = data[offset..offset + len].to_vec();
                offset += len;
                params.push(TypedParam { ty, bytes });
            }
        } else {
            // 非参考行：XOR-P 解码
            for i in 0..param_count {
                if offset >= data.len() {
                    break;
                }
                let ty = ParamType::from_u8(data[offset]).unwrap_or(ParamType::String);
                offset += 1;
                let base = ref_params.get(i).map(|p| p.bytes.as_slice()).unwrap_or(&[]);
                let (decoded_bytes, consumed) = Self::decode_xor_param_bytes(&data[offset..], base);
                params.push(TypedParam { ty, bytes: decoded_bytes });
                offset += consumed;
            }
        }

        params
    }

    // ---------- 私有工具 ----------

    /// v2 分词：保留空白作为独立 token（确保模板重建时保留空格）。
    /// 标点符号作为独立 token 保留。
    fn tokenize_v2(msg: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        for ch in msg.chars() {
            if ch.is_whitespace() {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                tokens.push(ch.to_string());
            } else if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' || ch == ':' || ch == '/' {
                current.push(ch);
            } else {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                tokens.push(ch.to_string());
            }
        }
        if !current.is_empty() {
            tokens.push(current);
        }
        tokens
    }

    /// 计算 token 类型序列（纯类型，不依赖 token 值），用于预分组。
    /// 空格标记为 's'。
    fn type_sequence(tokens: &[String]) -> String {
        let mut seq = String::with_capacity(tokens.len());
        for t in tokens {
            seq.push(Self::type_char(t));
        }
        seq
    }

    /// 单个 token 的类型字符
    fn type_char(t: &str) -> char {
        if t.chars().all(|c| c.is_whitespace())    { return 's'; }
        if TypedParam::try_ipv4_port(t).is_some()  { return 'P'; }
        if TypedParam::try_ipv4(t).is_some()       { return 'I'; }
        if TypedParam::try_timestamp(t).is_some()   { return 'T'; }
        if TypedParam::try_block_id(t).is_some()    { return 'B'; }
        if TypedParam::try_hex(t).is_some()         { return 'H'; }
        if TypedParam::try_integer(t).is_some()     { return 'N'; }
        if TypedParam::looks_like_path(t)           { return 'h'; }
        if t.chars().all(|c| c.is_ascii_punctuation()) { return 'C'; }
        'W'
    }

    fn build_record(log: &LogLine, pat_id: u16, params: Vec<TypedParam>, idx: usize) -> TemplateRecord {
        TemplateRecord {
            original_idx: idx,
            ts_delta: log.ts as i64,
            svc_id: 0,
            level: log.level.clone(),
            pat_id,
            params,
        }
    }

    /// 从 Literal/Param 掩码构建模板 parts
    fn mask_to_parts(tokens: &[String], is_fixed: &[bool]) -> Vec<TemplatePart> {
        tokens.iter().zip(is_fixed.iter())
            .map(|(t, &fixed)| if fixed { TemplatePart::Literal(t.clone()) } else { TemplatePart::Param })
            .collect()
    }

    /// 从掩码中提取参数值
    fn extract_params_from_mask(tokens: &[String], is_fixed: &[bool]) -> Vec<TypedParam> {
        tokens.iter().zip(is_fixed.iter())
            .filter_map(|(t, &fixed)| if !fixed { Some(TypedParam::from_str(t)) } else { None })
            .collect()
    }

    fn get_or_create_template(
        templates: &mut Vec<Template>,
        map: &mut HashMap<String, u16>,
        parts: Vec<TemplatePart>,
    ) -> u16 {
        // 模板签名：用于去重
        let sig: String = parts.iter().map(|p| match p {
            TemplatePart::Literal(s) => s.clone(),
            TemplatePart::Param => "*".to_string(),
        }).collect();
        if let Some(&id) = map.get(&sig) {
            return id;
        }
        let id = templates.len() as u16;
        templates.push(Template { id, parts });
        map.insert(sig, id);
        id
    }

    // ---------- 64-bit XOR-P 编解码（字节级） ----------

    /// 对两个字节串做 64-bit 对齐 XOR-P 编码
    ///
    /// 格式：
    ///   u16  num_chunks    ← 多少个 8-byte 块
    ///   u16  original_len  ← 原始字节长度（解码时截断用）
    ///   [u8] bitmap        ← 每 bit 表示对应块是否非零（1 = 有差异）
    ///   [u8] literals      ← 仅对 bitmap=1 的块存储 8-byte XOR 值
    pub fn xor_param_bytes(curr: &[u8], base: &[u8]) -> Vec<u8> {
        let max_len = ((curr.len().max(base.len()) + 7) / 8) * 8;
        let num_chunks = max_len / 8;
        let bitmap_len = (num_chunks + 7) / 8;

        let mut bitmap = vec![0u8; bitmap_len];
        let mut literals = Vec::new();

        for i in 0..num_chunks {
            let off = i * 8;
            let c = Self::read_u64_le(curr, off, max_len);
            let b = Self::read_u64_le(base, off, max_len);
            let x = c ^ b;

            if x != 0 {
                bitmap[i / 8] |= 1 << (i % 8);
                literals.extend_from_slice(&x.to_le_bytes());
            }
        }

        let mut result = Vec::with_capacity(4 + bitmap_len + literals.len());
        result.extend_from_slice(&(num_chunks as u16).to_le_bytes());
        result.extend_from_slice(&(curr.len() as u16).to_le_bytes());
        result.extend_from_slice(&bitmap);
        result.extend_from_slice(&literals);
        result
    }

    pub fn decode_xor_param_bytes(data: &[u8], base: &[u8]) -> (Vec<u8>, usize) {
        if data.len() < 2 {
            return (base.to_vec(), 0);
        }
        let num_chunks = u16::from_le_bytes([data[0], data[1]]) as usize;
        let original_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        let bitmap_len = (num_chunks + 7) / 8;
        let bitmap = &data[4..4 + bitmap_len];

        let max_len = num_chunks * 8;
        let mut buf = vec![0u8; max_len];
        let copy_len = base.len().min(max_len);
        buf[..copy_len].copy_from_slice(&base[..copy_len]);

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

        (buf[..original_len].to_vec(), lit_offset)
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

// ==================== Prefix Tree (Trie) 节点 ====================

/// Trie 节点：每个节点代表消息序列中的一个 token 位置。
///
/// 构建完成后通过 `compute_structure_keys()` 自底向上计算子树结构键。
/// 提取时通过子节点结构键比较判断每个位置是 Param 还是 Literal。
struct TrieNode {
    token: String,
    children: HashMap<String, TrieNode>,
    count: usize,
    msg_indices: Vec<usize>,
    /// 子树结构键（自底向上计算，用于判断子节点位置是 Param 还是 Literal）
    structure_key: String,
    /// 合并后的备选 token（子树合并时保留的参数值）
    alt_tokens: Vec<String>,
}

impl TrieNode {
    fn new_root() -> Self {
        Self { token: String::new(), children: HashMap::new(), count: 0, msg_indices: Vec::new(), structure_key: String::new(), alt_tokens: Vec::new() }
    }

    fn new(token: String) -> Self {
        Self { token, children: HashMap::new(), count: 0, msg_indices: Vec::new(), structure_key: String::new(), alt_tokens: Vec::new() }
    }

    /// 插入一条消息的 token 序列
    fn insert(&mut self, tokens: &[String], msg_idx: usize) {
        self.count += 1;
        if tokens.is_empty() {
            self.msg_indices.push(msg_idx);
            return;
        }
        let child = self.children
            .entry(tokens[0].clone())
            .or_insert_with(|| TrieNode::new(tokens[0].clone()));
        child.insert(&tokens[1..], msg_idx);
    }

    /// 自底向上标记 Param 节点。
    ///
    /// 自底向上计算每个节点的子树结构键。
    ///
    /// 结构键用于判断两个子树是否具有相同的 Literal/Param 模式。
    /// 键的格式：
    ///   "."               — 叶节点（无子节点）
    ///   "<T1,T2>"         — Param 位置（多个同结构子节点，T 是子节点 token 类型）
    ///   "[T:k,...]"       — 分支点（多个不同结构子节点）
    ///   <child_key>       — 单一子节点（跟随子节点的结构键）
    fn compute_structure_keys(&mut self) {
        for child in self.children.values_mut() {
            child.compute_structure_keys();
        }

        self.structure_key = if self.children.is_empty() {
            ".".to_string()
        } else if self.children.len() == 1 {
            self.children.values().next().unwrap().structure_key.clone()
        } else {
            let child_keys: Vec<&str> = self.children.values().map(|c| c.structure_key.as_str()).collect();
            let first = child_keys[0];
            if child_keys.iter().all(|&k| k == first) {
                // 所有子节点结构相同 → 该位置是 Param
                let mut types: Vec<String> = self.children.keys()
                    .map(|k| TemplateExtractor::type_char(k).to_string())
                    .collect();
                types.sort();
                format!("<{}>", types.join(","))
            } else {
                // 子节点结构不同 → 分支点（各自独立模板）
                let mut parts: Vec<String> = self.children.iter()
                    .map(|(k, v)| format!("{}:{}", TemplateExtractor::type_char(k), v.structure_key))
                    .collect();
                parts.sort();
                format!("[{}]", parts.join(","))
            }
        };
    }

    /// 合并结构相同的子节点的子树，使更深层的 Param 能被正确识别。
    ///
    /// 当多个子节点结构相同时，将它们的子树递归合并到第一个子节点中，
    /// 让更深层的不同值（如分散在不同分支的 IP）能在合并后的节点中比较。
    fn merge_identical_children(&mut self) {
        if self.children.len() <= 1 {
            for child in self.children.values_mut() {
                child.merge_identical_children();
            }
            return;
        }

        let first_key = self.children.values().next().unwrap().structure_key.clone();
        let all_same = self.children.values().all(|c| c.structure_key == first_key);

        if !all_same {
            for child in self.children.values_mut() {
                child.merge_identical_children();
            }
            return;
        }

        // 所有子节点结构相同 → 合并它们的子树以便更深层比较
        let tokens: Vec<String> = self.children.keys().cloned().collect();
        let mut merged = Vec::new();
        for token in &tokens[1..] {
            if let Some(child) = self.children.remove(token) {
                merged.push(child);
            }
        }

        if let Some(first) = self.children.values_mut().next() {
            for other in merged {
                first.merge_from(other);
            }
            // 递归合并更深层
            first.merge_identical_children();
            // 重新计算结构键（子树已合并）
            first.compute_structure_keys();
        }

        // 重新计算当前节点的结构键
        self.compute_structure_keys();
    }

    /// 将另一个节点的子树合并到当前节点中
    fn merge_from(&mut self, other: TrieNode) {
        self.count += other.count;
        self.msg_indices.extend(other.msg_indices);
        if !other.token.is_empty() && other.token != self.token {
            self.alt_tokens.push(other.token.clone());
        }
        self.alt_tokens.extend(other.alt_tokens);
        for (token, other_child) in other.children {
            if let Some(my_child) = self.children.get_mut(&token) {
                my_child.merge_from(other_child);
            } else {
                self.children.insert(token, other_child);
            }
        }
    }

    /// 所有可能的 token 值（包括合并来的备选 token）
    fn all_tokens(&self) -> Vec<String> {
        let mut tokens = vec![self.token.clone()];
        tokens.extend(self.alt_tokens.clone());
        tokens
    }

    /// 判断当前节点的子节点位置是否为 Param。
    /// 当有多个子节点且它们的子树结构相同时返回 true。
    fn children_are_param(&self) -> bool {
        if self.children.len() <= 1 {
            return false;
        }
        let first_key = &self.children.values().next().unwrap().structure_key;
        self.children.values().all(|c| c.structure_key == *first_key)
    }

    /// 从合并后的 Trie 提取模板并分配记录。
    ///
    /// 遍历 Trie，在 Param 节点处收集子节点的 token 作为参数值，
    /// 在 Literal 节点处将 token 加入模板定义。
    fn extract_templates_and_records(
        &self,
        batch: &[LogLine],
        templates: &mut Vec<Template>,
        template_map: &mut HashMap<String, u16>,
        records: &mut Vec<TemplateRecord>,
    ) {
        self._extract(batch, templates, template_map, records, &[], &[]);
    }

    fn _extract(
        &self,
        batch: &[LogLine],
        templates: &mut Vec<Template>,
        template_map: &mut HashMap<String, u16>,
        records: &mut Vec<TemplateRecord>,
        parts_so_far: &[TemplatePart],
        params_so_far: &[TypedParam],
    ) {
        // 叶节点（无子节点）
        if self.children.is_empty() {
            let pat_id = if parts_so_far.is_empty() {
                // 单条消息：创建全 Literal 模板
                for &idx in &self.msg_indices {
                    if idx >= batch.len() { continue; }
                    let raw: Vec<TemplatePart> = TemplateExtractor::tokenize_v2(&batch[idx].message)
                        .iter().map(|t| TemplatePart::Literal(t.clone())).collect();
                    if raw.is_empty() { continue; }
                    let pid = TemplateExtractor::get_or_create_template(templates, template_map, raw);
                    records.push(TemplateExtractor::build_record(&batch[idx], pid, vec![], idx));
                }
                return;
            } else {
                TemplateExtractor::get_or_create_template(templates, template_map, parts_so_far.to_vec())
            };

            for &idx in &self.msg_indices {
                if idx >= batch.len() { continue; }
                records.push(TemplateExtractor::build_record(&batch[idx], pat_id, params_so_far.to_vec(), idx));
            }
            return;
        }

        if self.children_are_param() {
            // 当前节点的子节点都是 Param：每个子节点的 token（含 alt_tokens）是参数值
            // 但合并后只剩一个子节点，所以用 all_tokens() 获取全部参数值
            let new_parts = [parts_so_far, &[TemplatePart::Param]].concat();
            if self.children.len() == 1 {
                // 合并后的情况：单个子节点持有所有参数值的 tokens
                let child = self.children.values().next().unwrap();
                let tokens = child.all_tokens();
                for token in &tokens {
                    if token.is_empty() { continue; }
                    let mut p = params_so_far.to_vec();
                    p.push(TypedParam::from_str(token));
                    child._extract(batch, templates, template_map, records, &new_parts, &p);
                }
            } else {
                // 未合并：每个子节点对应一个参数值
                for child in self.children.values() {
                    let mut p = params_so_far.to_vec();
                    p.push(TypedParam::from_str(&child.token));
                    child._extract(batch, templates, template_map, records, &new_parts, &p);
                }
            }
        } else if self.children.len() == 1 {
            // 单一 Literal 子节点
            let (token, child) = self.children.iter().next().unwrap();
            let new_parts = [parts_so_far, &[TemplatePart::Literal(token.clone())]].concat();
            child._extract(batch, templates, template_map, records, &new_parts, params_so_far);
        } else {
            // 多个不同结构的子节点 → 各自独立模板分支
            for child in self.children.values() {
                let new_parts = [parts_so_far, &[TemplatePart::Literal(child.token.clone())]].concat();
                child._extract(batch, templates, template_map, records, &new_parts, params_so_far);
            }
        }
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
    fn test_typed_param_integer() {
        let p = TypedParam::from_str("12345");
        assert_eq!(p.ty, ParamType::Integer);
        assert_eq!(p.to_string(), "12345");
        assert_eq!(p.bytes.len(), 8);
    }

    #[test]
    fn test_typed_param_hex() {
        let p = TypedParam::from_str("0x80004005");
        assert_eq!(p.ty, ParamType::Hex);
        assert_eq!(p.to_string(), "0x80004005");
        assert_eq!(p.bytes.len(), 8);
    }

    #[test]
    fn test_typed_param_ipv4() {
        let p = TypedParam::from_str("192.168.1.1");
        assert_eq!(p.ty, ParamType::IPv4);
        assert_eq!(p.to_string(), "192.168.1.1");
        assert_eq!(p.bytes.len(), 4);
    }

    #[test]
    fn test_typed_param_string() {
        let p = TypedParam::from_str("hello-world");
        assert_eq!(p.ty, ParamType::String);
        assert_eq!(p.to_string(), "hello-world");
    }

    #[test]
    fn test_typed_param_reject_leading_zeros() {
        // 前导零会导致往返不一致，应保持字符串
        let p = TypedParam::from_str("007");
        assert_eq!(p.ty, ParamType::String);
        assert_eq!(p.to_string(), "007");
    }

    #[test]
    fn test_typed_param_block_id() {
        let p = TypedParam::from_str("blk_38865049064139660");
        assert_eq!(p.ty, ParamType::BlockId);
        assert_eq!(p.to_string(), "blk_38865049064139660");
        assert_eq!(p.bytes.len(), 9);

        let p2 = TypedParam::from_str("blk_-6952295868487656571");
        assert_eq!(p2.ty, ParamType::BlockId);
        assert_eq!(p2.to_string(), "blk_-6952295868487656571");
    }

    #[test]
    fn test_typed_param_ipv4_port() {
        let p = TypedParam::from_str("10.251.73.220:50010");
        assert_eq!(p.ty, ParamType::IPv4Port);
        assert_eq!(p.to_string(), "10.251.73.220:50010");
        assert_eq!(p.bytes.len(), 6);
    }

    #[test]
    fn test_typed_param_timestamp() {
        let p = TypedParam::from_str("081109");
        assert_eq!(p.ty, ParamType::Timestamp);
        assert_eq!(p.to_string(), "081109");

        let p2 = TypedParam::from_str("203615");
        assert_eq!(p2.ty, ParamType::Timestamp);
        assert_eq!(p2.to_string(), "203615");
    }

    #[test]
    fn test_typed_param_path() {
        let p = TypedParam::from_str("/user/root/rand/_temporary/_task_200811092030_0001_m_000590_0/part-00590.");
        assert_eq!(p.ty, ParamType::Path);
        assert_eq!(p.to_string(), "/user/root/rand/_temporary/_task_200811092030_0001_m_000590_0/part-00590.");
    }

    #[test]
    fn test_structural_grouping_prevents_cross_type_merge() {
        // 两条消息 token 数相同但语法结构完全不同，不应合并为退化模板
        let logs = vec![
            make_log(0, "PacketResponder 1 for block blk_111 terminating"),
            make_log(1, "PacketResponder 2 for block blk_222 terminating"),
            make_log(2, "BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.73.220:50010 is added to blk_333 size 67108864"),
            make_log(3, "BLOCK* NameSystem.addStoredBlock: blockMap updated: 10.251.73.221:50010 is added to blk_444 size 67108864"),
        ];
        let batch = TemplateExtractor::extract(&logs);

        // 应提取 2 个模板，而不是 1 个退化模板
        assert_eq!(batch.templates.len(), 2, "应分为 2 个不同模板");

        // 检查没有全 Param 的退化模板
        for t in &batch.templates {
            let param_count = t.parts.iter().filter(|p| matches!(p, TemplatePart::Param)).count();
            let literal_count = t.parts.len() - param_count;
            assert!(
                literal_count >= 2,
                "模板不应退化（Literal 过少）: {:?}",
                t
            );
        }
    }

    #[test]
    fn test_xor_bytes_roundtrip() {
        let base = b"192.168.1.100";
        let curr = b"192.168.1.200";
        let encoded = TemplateExtractor::xor_param_bytes(curr, base);
        let (decoded, _) = TemplateExtractor::decode_xor_param_bytes(&encoded, base);
        assert_eq!(decoded, curr);
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
        assert_eq!(user_rec.params[0].to_string(), "12345");
        assert_eq!(user_rec.params[1].to_string(), "192.168.1.1");

        // Query 模板应有参数
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

        let encoded = TemplateExtractor::xor_param_bytes(curr.as_bytes(), base.as_bytes());
        let (decoded, _) = TemplateExtractor::decode_xor_param_bytes(&encoded, base.as_bytes());

        assert_eq!(decoded, curr.as_bytes());
    }

    #[test]
    fn test_xor_identical() {
        let s = "hello_world_12345";
        let encoded = TemplateExtractor::xor_param_bytes(s.as_bytes(), s.as_bytes());
        let (decoded, _) = TemplateExtractor::decode_xor_param_bytes(&encoded, s.as_bytes());
        assert_eq!(decoded, s.as_bytes());
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
        assert_eq!(decoded.len(), batch.records[1].params.len());
        for (a, b) in decoded.iter().zip(batch.records[1].params.iter()) {
            assert_eq!(a.to_string(), b.to_string());
        }
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
        // 验证 8 字节对齐
        let short = b"12345";        // 5 bytes → 1 chunk (8 bytes)
        let long = b"1234567890123"; // 13 bytes → 2 chunks (16 bytes)

        let enc1 = TemplateExtractor::xor_param_bytes(short, short);
        let enc2 = TemplateExtractor::xor_param_bytes(long, long);

        let chunks1 = u16::from_le_bytes([enc1[0], enc1[1]]);
        let chunks2 = u16::from_le_bytes([enc2[0], enc2[1]]);
        assert_eq!(chunks1, 1);
        assert_eq!(chunks2, 2);

        let len1 = u16::from_le_bytes([enc1[2], enc1[3]]);
        let len2 = u16::from_le_bytes([enc2[2], enc2[3]]);
        assert_eq!(len1, 5);
        assert_eq!(len2, 13);
    }

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
        assert_eq!(batch.records[0].params[0].to_string(), "张三");
        assert_eq!(batch.records[1].params[0].to_string(), "李四");
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
        let logs = vec![
            make_log(0, "Alpha beta gamma"),
            make_log(1, "One two three four"),
            make_log(2, "Xyzzy plugh plover"),
        ];
        let batch = TemplateExtractor::extract(&logs);
        assert!(batch.templates.len() >= 1);
        assert_eq!(batch.records.len(), 3);
    }

    #[test]
    fn test_xor_param_length_mismatch() {
        let base = "short";
        let curr = "this is a much longer string with many characters";
        let encoded = TemplateExtractor::xor_param_bytes(curr.as_bytes(), base.as_bytes());
        let (decoded, _) = TemplateExtractor::decode_xor_param_bytes(&encoded, base.as_bytes());
        assert_eq!(decoded, curr.as_bytes());
    }

    #[test]
    fn test_xor_param_base_longer_than_curr() {
        let base = "this is the long base string for testing";
        let curr = "tiny";
        let encoded = TemplateExtractor::xor_param_bytes(curr.as_bytes(), base.as_bytes());
        let (decoded, _) = TemplateExtractor::decode_xor_param_bytes(&encoded, base.as_bytes());
        assert_eq!(decoded, curr.as_bytes());
    }

    #[test]
    fn test_xor_param_empty_string() {
        let base = "nonempty";
        let curr = "";
        let encoded = TemplateExtractor::xor_param_bytes(curr.as_bytes(), base.as_bytes());
        let (decoded, _) = TemplateExtractor::decode_xor_param_bytes(&encoded, base.as_bytes());
        assert_eq!(decoded, curr.as_bytes());
    }

    #[test]
    fn test_xor_param_exactly_8_bytes() {
        let base = b"12345678";
        let curr = b"abcdefgh";
        let encoded = TemplateExtractor::xor_param_bytes(curr, base);
        let chunks = u16::from_le_bytes([encoded[0], encoded[1]]);
        assert_eq!(chunks, 1);
        let (decoded, _) = TemplateExtractor::decode_xor_param_bytes(&encoded, base);
        assert_eq!(decoded, curr);
    }

    #[test]
    fn test_xor_param_exactly_16_bytes() {
        let base = b"1234567890123456";
        let curr = b"abcdefghijklmnop";
        let encoded = TemplateExtractor::xor_param_bytes(curr, base);
        let chunks = u16::from_le_bytes([encoded[0], encoded[1]]);
        assert_eq!(chunks, 2);
        let (decoded, _) = TemplateExtractor::decode_xor_param_bytes(&encoded, base);
        assert_eq!(decoded, curr);
    }

    #[test]
    fn test_encode_xor_empty_params() {
        let logs = vec![
            make_log(0, "No params here"),
            make_log(1, "No params here"),
        ];
        let batch = TemplateExtractor::extract(&logs);
        let encoded = TemplateExtractor::encode_xor(&batch, 16);
        assert_eq!(encoded.len(), 2);
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
        assert_eq!(TemplateExtractor::read_u64_le(bytes, 0, 5), 0x6f6c6c6568);
        assert_eq!(TemplateExtractor::read_u64_le(bytes, 10, 5), 0);
        assert_eq!(TemplateExtractor::read_u64_le(bytes, 3, 5), 0x6f6c);
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
            let tokens = TemplateExtractor::tokenize_v2(input);
            assert_eq!(tokens, expected.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        }
    }
}

// ==================== PatternTable 序列化 v2（varint，供 storage.rs 使用）====================
//
// 使用变长整数编码替代固定宽度 u16/u32：
// - part_count（通常 < 30）：1 字节 vs 原来的 2 字节
// - literal 长度（通常 < 127）：1 字节 vs 原来的 4 字节
// - template 总数：1-2 字节 vs 原来的 2 字节
//
// 对于 30-40 个模板的典型 Segment，PatternTable 可缩小 30-50%。

use crate::shared::format::{read_varuint, write_varuint};

impl Template {
    /// 序列化为字节流（TLV + varint 格式）
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varuint(&mut buf, self.parts.len() as u64);
        for part in &self.parts {
            match part {
                TemplatePart::Literal(s) => {
                    buf.push(0x01);
                    let bytes = s.as_bytes();
                    write_varuint(&mut buf, bytes.len() as u64);
                    buf.extend_from_slice(bytes);
                }
                TemplatePart::Param => {
                    buf.push(0x02);
                }
            }
        }
        buf
    }

    /// 从字节流反序列化（varint 格式）
    pub fn deserialize(data: &[u8]) -> io::Result<(Self, usize)> {
        let (part_count, mut offset) = read_varuint(data, 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "template part_count"))?;
        let part_count = part_count as usize;
        let mut parts = Vec::with_capacity(part_count);
        for _ in 0..part_count {
            if offset >= data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "template part tag"));
            }
            let tag = data[offset];
            offset += 1;
            if tag == 0x01 {
                let (len, new_off) = read_varuint(data, offset)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "literal len"))?;
                let len = len as usize;
                offset = new_off;
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
    /// 序列化整个 PatternTable（varint 模板计数）
    pub fn serialize_pattern_table(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_varuint(&mut buf, self.templates.len() as u64);
        for t in &self.templates {
            buf.extend_from_slice(&t.serialize());
        }
        buf
    }

    /// 从字节流反序列化 PatternTable（varint 模板计数）
    pub fn deserialize_pattern_table(data: &[u8]) -> io::Result<Vec<Template>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let (count, mut offset) = read_varuint(data, 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "pattern table count"))?;
        let count = count as usize;
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
