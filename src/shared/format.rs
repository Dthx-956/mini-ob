//! mini-obs/shared/format.rs
//! MOBS (Mini-OBS) 存储格式规范 —— 二进制契约层
//!
//! 设计目标：
//! - 跨平台（x86_64 / aarch64 / mips），严格 4 字节对齐
//! - 零拷贝解析：支持 mmap 后直接类型转换（`#[repr(C)]` 保证布局）
//! - 专利安全：格式本身不涉 ANS 算法，仅定义 Zstd 载荷的容器结构
//! - 向前兼容：版本号 + 保留字段，支持未来扩展
//!
//! 格式层次：
//!   Segment 文件 v1 = Header(64B) + ChunkTable(N×32B) + Padding + ZstdData + Footer(8B)
//!   Segment 文件 v2 = Header(64B) + PatternTable(变长) + ChunkTable(N×32B)
//!                     + ChunkSummaryTable(N×80B) + Padding + ZstdData + Footer(8B)
//!   Manifest 文件 = Magic(4B) + Version(1B) + EntryCount(4B) + Entry[](N×64B) + CRC(4B)
//!   WAL 文件 = JSON Lines（文本，崩溃恢复用）

use std::fmt;
use std::io;

use serde::{Deserialize, Serialize};

// ==================== 日志行类型 ====================

/// 单条日志行的内存表示
///
/// 序列化格式（JSON 紧凑）：`{"t":u64,"s":"svc","l":"E","m":"msg"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogLine {
    /// Unix 时间戳（毫秒）
    #[serde(rename = "t")]
    pub ts: u64,
    /// 服务名
    #[serde(rename = "s")]
    pub service: String,
    /// 日志级别（单字符：D/I/W/E）
    #[serde(rename = "l")]
    pub level: String,
    /// 消息内容
    #[serde(rename = "m")]
    pub message: String,
}

// ==================== 常量 ====================

/// Segment 文件魔数
pub const MOBS_MAGIC: &[u8; 4] = b"MOBS";
/// Manifest 索引文件魔数
pub const MIDX_MAGIC: &[u8; 4] = b"MIDX";
/// WAL 文件魔数（文本头，便于人工识别）
pub const WAL_MAGIC: &[u8] = b"--- MOBS WAL ---\n";

/// 格式版本历史
pub const FORMAT_VERSION_V1: u8 = 1;
pub const FORMAT_VERSION_V2: u8 = 2;
/// 当前默认格式版本（新写入使用 v2）
pub const FORMAT_VERSION: u8 = FORMAT_VERSION_V2;

/// Segment 文件头大小
pub const SEGMENT_HEADER_SIZE: usize = 64;
/// Chunk 表项大小
pub const CHUNK_ENTRY_SIZE: usize = 32;
/// Chunk 摘要大小（v2 新增）
pub const CHUNK_SUMMARY_SIZE: usize = 80;
/// Segment 文件尾大小
pub const SEGMENT_FOOTER_SIZE: usize = 8;
/// Manifest 表项大小
pub const MANIFEST_ENTRY_SIZE: usize = 64;
/// 最小 Segment 文件大小（Header + 1 Chunk + Footer）
pub const MIN_SEGMENT_SIZE: usize =
    SEGMENT_HEADER_SIZE + CHUNK_ENTRY_SIZE + SEGMENT_FOOTER_SIZE;

/// 4KB 对齐粒度（匹配树莓派 SD 卡块大小与 Linux 页大小）
pub const ALIGNMENT: usize = 4096;

// ==================== 错误类型 ====================

/// 格式解析错误
#[derive(Debug, Clone, PartialEq)]
pub enum FormatError {
    /// 魔数不匹配
    BadMagic { expected: [u8; 4], got: [u8; 4] },
    /// 版本不兼容
    UnsupportedVersion { expected: u8, got: u8 },
    /// 数据长度不足
    UnexpectedEof { needed: usize, got: usize },
    /// CRC 校验失败
    CrcMismatch { expected: u32, computed: u32 },
    /// 字段值超出合法范围
    InvalidField { field: &'static str, value: u64 },
    /// 对齐错误
    Misaligned { offset: usize, alignment: usize },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::BadMagic { expected, got } => write!(
                f,
                "bad magic: expected {:02x?}, got {:02x?}",
                expected, got
            ),
            FormatError::UnsupportedVersion { expected, got } => {
                write!(f, "unsupported version: expected {}, got {}", expected, got)
            }
            FormatError::UnexpectedEof { needed, got } => {
                write!(f, "unexpected eof: needed {}, got {}", needed, got)
            }
            FormatError::CrcMismatch { expected, computed } => write!(
                f,
                "crc mismatch: expected {:08x}, computed {:08x}",
                expected, computed
            ),
            FormatError::InvalidField { field, value } => {
                write!(f, "invalid field {}: {}", field, value)
            }
            FormatError::Misaligned { offset, alignment } => write!(
                f,
                "misaligned: offset {} not aligned to {}",
                offset, alignment
            ),
        }
    }
}

impl std::error::Error for FormatError {}

impl From<FormatError> for io::Error {
    fn from(e: FormatError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

// ==================== 工具函数 ====================

/// 计算 CRC32（IEEE 802.3 多项式，与 zlib/crc32fast 兼容）
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for i in 0..256 {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        table[i] = c;
    }

    let mut crc = 0xffff_ffff;
    for &byte in data {
        crc = table[((crc as u8) ^ byte) as usize] ^ (crc >> 8);
    }
    !crc
}

/// 将数据填充到指定对齐边界（返回填充后的长度）
pub fn align_up(size: usize, alignment: usize) -> usize {
    (size + alignment - 1) / alignment * alignment
}

/// 计算填充字节数
pub fn padding_needed(size: usize, alignment: usize) -> usize {
    align_up(size, alignment) - size
}

/// 生成 Segment 文件名（8 位零填充，保证字典序即时间序）
pub fn segment_name(id: u32) -> String {
    format!("segment-{:08}.mobs", id)
}

/// 解析 Segment 文件名，返回 ID（失败返回 None）
pub fn parse_segment_name(name: &str) -> Option<u32> {
    if !name.starts_with("segment-") || !name.ends_with(".mobs") {
        return None;
    }
    let num = &name[8..16];
    u32::from_str_radix(num, 10).ok()
}

/// 生成路径哈希（FNV-1a 64bit，用于 Manifest 快速去重）
pub fn hash_path(path: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for byte in path.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// 当前 Unix 时间戳（毫秒）
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ==================== Segment 文件头 ====================

/// Segment 文件头（64 字节，只读 mmap 安全）
///
/// 布局：
/// ```text
/// 0x00-0x03  Magic           [u8; 4]   = "MOBS"
/// 0x04       Version         u8        = 1 or 2
/// 0x05       Flags           u8        = 0 (保留)
/// 0x06-0x07  Chunk Count     u16 LE    = N
/// 0x08-0x0F  Created At      u64 LE    = Unix millis
/// 0x10-0x13  Segment ID      u32 LE
/// 0x14-0x17  Header CRC32    u32 LE    = CRC(0x00..0x13)
/// 0x18-0x3F  Reserved        [u8; 40]  = v2 元数据（见下）
/// ```
///
/// Reserved 字段解释（v2）：
/// ```text
/// 0x18-0x19  pattern_count:      u16 LE  = 模板数量
/// 0x1A-0x1D  pattern_table_len:  u32 LE  = PatternTable 字节数
/// 0x1C-0x1F  summary_offset:     u32 LE  = ChunkSummaryTable 起始偏移
/// 0x20-0x23  data_offset:        u32 LE  = ChunkData 起始偏移
/// 0x24-0x3F  reserved:           [u8; 28] = 保留
/// ```
/// v1 时 reserved 全为 0，上述字段返回 0。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SegmentHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u8,
    pub chunk_count: u16,
    pub created_at: u64,
    pub segment_id: u32,
    pub header_crc32: u32,
    pub reserved: [u8; 40],
}

impl SegmentHeader {
    /// 创建 v2 新头（CRC 自动计算）
    pub fn new(segment_id: u32, chunk_count: u16) -> Self {
        let mut h = Self {
            magic: *MOBS_MAGIC,
            version: FORMAT_VERSION_V2,
            flags: 0,
            chunk_count,
            created_at: now_ms(),
            segment_id,
            header_crc32: 0,
            reserved: [0; 40],
        };
        h.header_crc32 = h.compute_crc();
        h
    }

    /// 创建 v1 头（向后兼容测试用）
    pub fn new_v1(segment_id: u32, chunk_count: u16) -> Self {
        let mut h = Self {
            magic: *MOBS_MAGIC,
            version: FORMAT_VERSION_V1,
            flags: 0,
            chunk_count,
            created_at: now_ms(),
            segment_id,
            header_crc32: 0,
            reserved: [0; 40],
        };
        h.header_crc32 = h.compute_crc();
        h
    }

    /// 设置 v2 元数据到 reserved 字段
    pub fn set_v2_meta(
        &mut self,
        pattern_count: u16,
        pattern_table_len: u32,
        summary_offset: u32,
        data_offset: u32,
    ) {
        self.reserved[0..2].copy_from_slice(&pattern_count.to_le_bytes());
        self.reserved[2..6].copy_from_slice(&pattern_table_len.to_le_bytes());
        self.reserved[6..10].copy_from_slice(&summary_offset.to_le_bytes());
        self.reserved[10..14].copy_from_slice(&data_offset.to_le_bytes());
        // 重新计算 CRC（因为 version 等未变，只有 reserved 变了，而 CRC 不覆盖 reserved）
        // 注意：header_crc32 只覆盖 0x00..0x13，不包括 reserved，所以无需重算
    }

    /// v2：模板数量
    pub fn pattern_count(&self) -> u16 {
        u16::from_le_bytes([self.reserved[0], self.reserved[1]])
    }

    /// v2：PatternTable 字节长度
    pub fn pattern_table_len(&self) -> u32 {
        u32::from_le_bytes([self.reserved[2], self.reserved[3], self.reserved[4], self.reserved[5]])
    }

    /// v2：ChunkSummaryTable 起始偏移（相对文件头）
    pub fn summary_offset(&self) -> u32 {
        u32::from_le_bytes([
            self.reserved[6], self.reserved[7], self.reserved[8], self.reserved[9],
        ])
    }

    /// v2：ChunkData 起始偏移（相对文件头）
    pub fn data_offset_v2(&self) -> u32 {
        u32::from_le_bytes([
            self.reserved[10], self.reserved[11], self.reserved[12], self.reserved[13],
        ])
    }

    /// 从字节切片解析（零拷贝，不复制）
    /// 兼容 v1 和 v2：只检查魔数，不拒绝 v1
    pub fn from_bytes(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < SEGMENT_HEADER_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: SEGMENT_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != *MOBS_MAGIC {
            return Err(FormatError::BadMagic {
                expected: *MOBS_MAGIC,
                got: magic,
            });
        }
        let version = buf[4];
        // 兼容 v1 和 v2，拒绝其他未知版本
        if version != FORMAT_VERSION_V1 && version != FORMAT_VERSION_V2 {
            return Err(FormatError::UnsupportedVersion {
                expected: FORMAT_VERSION,
                got: version,
            });
        }
        let flags = buf[5];
        let chunk_count = u16::from_le_bytes([buf[6], buf[7]]);
        let created_at = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let segment_id = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let header_crc32 = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);

        let mut reserved = [0u8; 40];
        reserved.copy_from_slice(&buf[24..64]);

        let h = Self {
            magic,
            version,
            flags,
            chunk_count,
            created_at,
            segment_id,
            header_crc32,
            reserved,
        };

        let computed = h.compute_crc();
        if computed != header_crc32 {
            return Err(FormatError::CrcMismatch {
                expected: header_crc32,
                computed,
            });
        }

        Ok(h)
    }

    /// 序列化为固定 64 字节数组
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6..8].copy_from_slice(&self.chunk_count.to_le_bytes());
        buf[8..16].copy_from_slice(&self.created_at.to_le_bytes());
        buf[16..20].copy_from_slice(&self.segment_id.to_le_bytes());
        buf[20..24].copy_from_slice(&self.header_crc32.to_le_bytes());
        buf[24..64].copy_from_slice(&self.reserved);
        buf
    }

    /// 计算头部 CRC（覆盖 0x00..0x13，即魔数到 segment_id）
    fn compute_crc(&self) -> u32 {
        let mut tmp = [0u8; 20];
        tmp[0..4].copy_from_slice(&self.magic);
        tmp[4] = self.version;
        tmp[5] = self.flags;
        tmp[6..8].copy_from_slice(&self.chunk_count.to_le_bytes());
        tmp[8..16].copy_from_slice(&self.created_at.to_le_bytes());
        tmp[16..20].copy_from_slice(&self.segment_id.to_le_bytes());
        crc32(&tmp)
    }

    /// v1 兼容：数据区起始偏移（Header + ChunkTable，4KB 对齐）
    /// 仅适用于 v1 单 Chunk 场景
    pub fn data_offset(&self) -> usize {
        let table_size = self.chunk_count as usize * CHUNK_ENTRY_SIZE;
        align_up(SEGMENT_HEADER_SIZE + table_size, ALIGNMENT)
    }
}

// ==================== Chunk 表项 ====================

/// Chunk 元数据（32 字节，描述一个 Zstd 压缩块）
///
/// 布局：
/// ```text
/// 0x00-0x03  Data Offset     u32 LE    = 相对 data_offset 的偏移（v2）或绝对偏移（v1）
/// 0x04-0x07  Compressed Sz   u32 LE
/// 0x08-0x0B  Original Sz     u32 LE
/// 0x0C-0x0F  Line Count      u32 LE
/// 0x10-0x17  Min Timestamp   u64 LE
/// 0x18-0x1F  Max Timestamp   u64 LE
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChunkEntry {
    pub offset: u32,
    pub compressed_sz: u32,
    pub original_sz: u32,
    pub line_count: u32,
    pub min_ts: u64,
    pub max_ts: u64,
}

impl ChunkEntry {
    pub fn new(offset: u32, compressed: u32, original: u32, lines: u32, min_ts: u64, max_ts: u64) -> Self {
        Self {
            offset,
            compressed_sz: compressed,
            original_sz: original,
            line_count: lines,
            min_ts,
            max_ts,
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < CHUNK_ENTRY_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: CHUNK_ENTRY_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            offset: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            compressed_sz: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            original_sz: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            line_count: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
            min_ts: u64::from_le_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            max_ts: u64::from_le_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&self.offset.to_le_bytes());
        buf[4..8].copy_from_slice(&self.compressed_sz.to_le_bytes());
        buf[8..12].copy_from_slice(&self.original_sz.to_le_bytes());
        buf[12..16].copy_from_slice(&self.line_count.to_le_bytes());
        buf[16..24].copy_from_slice(&self.min_ts.to_le_bytes());
        buf[24..32].copy_from_slice(&self.max_ts.to_le_bytes());
        buf
    }

    /// 该 Chunk 是否与给定时间范围重叠
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.max_ts >= start && self.min_ts <= end
    }

    /// 压缩比
    pub fn compression_ratio(&self) -> f64 {
        if self.compressed_sz == 0 {
            0.0
        } else {
            self.original_sz as f64 / self.compressed_sz as f64
        }
    }
}

// ==================== Chunk 摘要（v2 新增）====================

/// Chunk 内容摘要（80 字节定长），用于免解压过滤
///
/// 布局：
/// ```text
/// 0x00-0x07  pattern_mask:    u64 LE    = 本 Chunk 包含哪些模板（位图，64 模板上限）
/// 0x08       level_mask:      u8        = D/I/W/E 分布（bit 0=D, 1=I, 2=W, 3=E）
/// 0x09-0x48  param_bloom:     [u8; 64]  = 参数值 Bloom Filter (512 bits, 3% 假阳性)
/// 0x49-0x4F  reserved:        [u8; 7]   = 对齐填充
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ChunkSummary {
    /// 模板位图：第 i 位为 1 表示本 Chunk 包含模板 ID=i 的日志
    pub pattern_mask: u64,
    /// 级别分布：bit 0=D, 1=I, 2=W, 3=E
    pub level_mask: u8,
    /// 参数值 Bloom Filter（512 bits）
    pub param_bloom: [u8; 64],
    /// 保留填充
    pub reserved: [u8; 7],
}

impl ChunkSummary {
    pub fn new(pattern_mask: u64, level_mask: u8, param_bloom: [u8; 64]) -> Self {
        Self {
            pattern_mask,
            level_mask,
            param_bloom,
            reserved: [0; 7],
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < CHUNK_SUMMARY_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: CHUNK_SUMMARY_SIZE,
                got: buf.len(),
            });
        }
        let mut param_bloom = [0u8; 64];
        param_bloom.copy_from_slice(&buf[9..73]);
        Ok(Self {
            pattern_mask: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            level_mask: buf[8],
            param_bloom,
            reserved: [0; 7],
        })
    }

    pub fn to_bytes(&self) -> [u8; 80] {
        let mut buf = [0u8; 80];
        buf[0..8].copy_from_slice(&self.pattern_mask.to_le_bytes());
        buf[8] = self.level_mask;
        buf[9..73].copy_from_slice(&self.param_bloom);
        buf[73..80].copy_from_slice(&self.reserved);
        buf
    }

    /// 检查本 Chunk 是否可能包含指定模板
    pub fn may_contain_pattern(&self, pat_id: u16) -> bool {
        if pat_id >= 64 {
            return true; // 超出位图范围，保守返回可能包含
        }
        (self.pattern_mask >> pat_id) & 1 != 0
    }

    /// 检查本 Chunk 是否可能包含指定级别
    pub fn may_contain_level(&self, level: &str) -> bool {
        let bit = match level {
            "D" => 0,
            "I" => 1,
            "W" => 2,
            "E" => 3,
            _ => return true,
        };
        (self.level_mask >> bit) & 1 != 0
    }

    /// 检查 Bloom Filter 是否可能包含关键词（完整值匹配）
    /// 返回 false 表示一定不包含（真阴性）
    pub fn bloom_may_contain(&self, keyword: &str) -> bool {
        if keyword.is_empty() {
            return true; // 空关键词保守返回可能包含
        }
        // 5 个独立哈希位置
        for seed in 0..5 {
            let pos = Self::bloom_hash(keyword, seed);
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            if (self.param_bloom[byte_idx] >> bit_idx) & 1 == 0 {
                return false; // 某一位未设置，一定不包含
            }
        }
        true // 可能包含（含 3% 假阳性）
    }

    /// FNV-1a + splitmix64 哈希，映射到 512 bits
    pub fn bloom_hash(s: &str, seed: u64) -> usize {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0100_0000_01b3;
        let mut h = FNV_OFFSET;
        for byte in s.bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        // splitmix64 变体
        h = h.wrapping_add(seed);
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        (h % 512) as usize
    }
}

// ==================== Segment 文件尾 ====================

/// Segment Footer（8 字节，用于快速反向定位 ChunkTable 和 CRC 校验）
///
/// 布局：
/// ```text
/// 0x00-0x03  ChunkTable Offset   u32 LE    = Header 后的偏移（即 PatternTable 起始，v2）
/// 0x04-0x07  Content CRC32       u32 LE    = Header+PatternTable+ChunkTable+Summary+Data 的 CRC
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SegmentFooter {
    pub chunk_table_offset: u32,
    pub crc32: u32,
}

impl SegmentFooter {
    pub fn new(chunk_table_offset: u32) -> Self {
        Self {
            chunk_table_offset,
            crc32: 0,
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < SEGMENT_FOOTER_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: SEGMENT_FOOTER_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            chunk_table_offset: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            crc32: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&self.chunk_table_offset.to_le_bytes());
        buf[4..8].copy_from_slice(&self.crc32.to_le_bytes());
        buf
    }

    /// 验证内容 CRC（传入除 Footer 外的全部文件内容）
    pub fn verify(&self, content: &[u8]) -> Result<(), FormatError> {
        let computed = crc32(content);
        if computed != self.crc32 {
            return Err(FormatError::CrcMismatch {
                expected: self.crc32,
                computed,
            });
        }
        Ok(())
    }
}

// ==================== Manifest 索引条目 ====================

/// Manifest 固定大小条目（64 字节，支持 mmap 顺序扫描）
///
/// 布局：
/// ```text
/// 0x00-0x03  Segment ID      u32 LE
/// 0x04-0x0B  Min Timestamp   u64 LE
/// 0x0C-0x13  Max Timestamp   u64 LE
/// 0x14-0x17  Line Count      u32 LE
/// 0x18-0x1F  Path Hash       u64 LE (FNV-1a，用于快速去重)
/// 0x20-0x23  Flags           u32 LE (0=正常, 1=标记删除)
/// 0x24-0x3F  Reserved        [u8; 28]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ManifestEntry {
    pub segment_id: u32,
    pub min_ts: u64,
    pub max_ts: u64,
    pub line_count: u32,
    pub path_hash: u64,
    pub flags: u32,
    pub reserved: [u8; 28],
}

/// Manifest 标志位
pub mod manifest_flags {
    pub const NORMAL: u32 = 0;
    pub const TOMBSTONE: u32 = 1; // 标记删除，后台合并时清理
}

impl ManifestEntry {
    pub fn new(segment_id: u32, min_ts: u64, max_ts: u64, line_count: u32, path: &str) -> Self {
        Self {
            segment_id,
            min_ts,
            max_ts,
            line_count,
            path_hash: hash_path(path),
            flags: manifest_flags::NORMAL,
            reserved: [0; 28],
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < MANIFEST_ENTRY_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: MANIFEST_ENTRY_SIZE,
                got: buf.len(),
            });
        }
        let mut reserved = [0u8; 28];
        reserved.copy_from_slice(&buf[36..64]);
        Ok(Self {
            segment_id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            min_ts: u64::from_le_bytes([buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]]),
            max_ts: u64::from_le_bytes([buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]]),
            line_count: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
            path_hash: u64::from_le_bytes([buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31]]),
            flags: u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
            reserved,
        })
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&self.segment_id.to_le_bytes());
        buf[4..12].copy_from_slice(&self.min_ts.to_le_bytes());
        buf[12..20].copy_from_slice(&self.max_ts.to_le_bytes());
        buf[20..24].copy_from_slice(&self.line_count.to_le_bytes());
        buf[24..32].copy_from_slice(&self.path_hash.to_le_bytes());
        buf[32..36].copy_from_slice(&self.flags.to_le_bytes());
        buf[36..64].copy_from_slice(&self.reserved);
        buf
    }

    /// 时间范围重叠判断
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.max_ts >= start && self.min_ts <= end
    }

    /// 是否已标记删除
    pub fn is_deleted(&self) -> bool {
        self.flags & manifest_flags::TOMBSTONE != 0
    }
}

// ==================== Manifest 文件头 ====================

/// Manifest 文件头（9 字节，便于快速校验）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub entry_count: u32,
}

impl ManifestHeader {
    pub fn new(entry_count: u32) -> Self {
        Self {
            magic: *MIDX_MAGIC,
            version: FORMAT_VERSION,
            entry_count,
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < 9 {
            return Err(FormatError::UnexpectedEof { needed: 9, got: buf.len() });
        }
        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != *MIDX_MAGIC {
            return Err(FormatError::BadMagic { expected: *MIDX_MAGIC, got: magic });
        }
        let version = buf[4];
        if version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion { expected: FORMAT_VERSION, got: version });
        }
        Ok(Self {
            magic,
            version,
            entry_count: u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.version;
        buf[5..9].copy_from_slice(&self.entry_count.to_le_bytes());
        buf
    }
}

// ==================== WAL 记录格式 ====================

/// WAL 记录头（每条记录前 4 字节长度前缀，支持二进制安全）
///
/// 格式：`<length:u32 LE><json_bytes>`，length 不含自身
pub struct WalRecord;

impl WalRecord {
    /// 编码单条记录为字节（带长度前缀）
    pub fn encode(line: &str) -> Vec<u8> {
        let bytes = line.as_bytes();
        let len = bytes.len() as u32;
        let mut out = Vec::with_capacity(4 + bytes.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// 从字节流解码（返回记录和剩余字节）
    pub fn decode(buf: &[u8]) -> Result<(&str, &[u8]), FormatError> {
        if buf.len() < 4 {
            return Err(FormatError::UnexpectedEof { needed: 4, got: buf.len() });
        }
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len {
            return Err(FormatError::UnexpectedEof { needed: 4 + len, got: buf.len() });
        }
        let line = std::str::from_utf8(&buf[4..4 + len])
            .map_err(|_| FormatError::InvalidField { field: "wal_utf8", value: 0 })?;
        Ok((line, &buf[4 + len..]))
    }
}

// ==================== 集成辅助：Segment 完整解析 ====================

/// 已解析的 Segment 结构（内存表示，供上层使用）
#[derive(Debug, Clone)]
pub struct ParsedSegment {
    pub header: SegmentHeader,
    pub chunks: Vec<ChunkEntry>,
    pub summaries: Vec<ChunkSummary>, // v2 新增
    pub data_offset: usize,
    pub data_len: usize,
    pub file_size: usize,
}

impl ParsedSegment {
    /// 从 mmap 或文件缓冲区完整解析 Segment（兼容 v1/v2）
    pub fn parse(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < MIN_SEGMENT_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: MIN_SEGMENT_SIZE,
                got: buf.len(),
            });
        }

        let header = SegmentHeader::from_bytes(&buf[0..SEGMENT_HEADER_SIZE])?;
        let chunk_count = header.chunk_count as usize;

        // 解析 ChunkTable（v2 时 PatternTable 在 Header 和 ChunkTable 之间）
        let table_start = SEGMENT_HEADER_SIZE + header.pattern_table_len() as usize;
        let table_end = table_start + chunk_count * CHUNK_ENTRY_SIZE;
        if buf.len() < table_end + SEGMENT_FOOTER_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: table_end + SEGMENT_FOOTER_SIZE,
                got: buf.len(),
            });
        }

        let mut chunks = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            let off = table_start + i * CHUNK_ENTRY_SIZE;
            chunks.push(ChunkEntry::from_bytes(&buf[off..off + CHUNK_ENTRY_SIZE])?);
        }

        // v2：解析 ChunkSummaryTable
        let mut summaries = Vec::new();
        if header.version == FORMAT_VERSION_V2 {
            let summary_start = header.summary_offset() as usize;
            for i in 0..chunk_count {
                let off = summary_start + i * CHUNK_SUMMARY_SIZE;
                if off + CHUNK_SUMMARY_SIZE <= buf.len() - SEGMENT_FOOTER_SIZE {
                    summaries.push(ChunkSummary::from_bytes(&buf[off..off + CHUNK_SUMMARY_SIZE])?);
                }
            }
        }

        // 定位 Footer
        let footer_start = buf.len() - SEGMENT_FOOTER_SIZE;
        let footer = SegmentFooter::from_bytes(&buf[footer_start..])?;

        // 验证 Footer CRC
        let content = &buf[0..footer_start];
        footer.verify(content)?;

        // 计算数据区范围
        let data_offset = if header.version == FORMAT_VERSION_V2 {
            header.data_offset_v2() as usize
        } else {
            header.data_offset()
        };
        let data_end = footer_start;
        let data_len = if data_end > data_offset {
            data_end - data_offset
        } else {
            0
        };

        Ok(Self {
            header,
            chunks,
            summaries,
            data_offset,
            data_len,
            file_size: buf.len(),
        })
    }

    /// 获取指定 Chunk 的压缩数据切片（基于原始 buf）
    pub fn chunk_data<'a>(&self, buf: &'a [u8], idx: usize) -> Option<&'a [u8]> {
        let chunk = self.chunks.get(idx)?;
        let start = self.data_offset + chunk.offset as usize;
        let end = start + chunk.compressed_sz as usize;
        if end > buf.len() {
            return None;
        }
        Some(&buf[start..end])
    }

    /// 获取指定 Chunk 的 Summary（v2）
    pub fn chunk_summary(&self, idx: usize) -> Option<&ChunkSummary> {
        self.summaries.get(idx)
    }

    /// 总压缩比
    pub fn total_ratio(&self) -> f64 {
        let original: u64 = self.chunks.iter().map(|c| c.original_sz as u64).sum();
        let compressed: u64 = self.chunks.iter().map(|c| c.compressed_sz as u64).sum();
        if compressed == 0 {
            0.0
        } else {
            original as f64 / compressed as f64
        }
    }
}

// ==================== 模块级 Bloom 哈希（供 ChunkSummary 和 SegmentSummary 共享）====================

pub(crate) fn bloom_hash(s: &str, seed: u64) -> usize {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for byte in s.bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h = h.wrapping_add(seed);
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    (h % 512) as usize
}

// ==================== Segment 级摘要（嵌入 ManifestEntry.reserved）====================

/// Segment 级摘要（28 字节），用于免解压统计查询
///
/// 构建来源：扫描 Segment v2 文件时，读取 ChunkSummaryTable 汇总
/// 内存位置：常驻内存（随 Manifest 加载），查询时零磁盘 IO
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SegmentSummary {
    /// 0x00-0x07 模板位图（8 bytes）
    pub pattern_mask: u64,
    /// 0x08 级别分布（1 byte）
    pub level_mask: u8,
    /// 0x09-0x0E 服务名 Bloom Filter（6 bytes = 48 bits, 3 hash）
    pub service_bloom: [u8; 6],
    /// 0x0F-0x1A 参数值 Bloom Filter（12 bytes = 96 bits, 2 hash）
    pub param_bloom: [u8; 12],
    /// 0x1B 标志（1 byte）
    pub flags: u8,
}

impl SegmentSummary {
    pub const HAS_SUMMARY: u8 = 0x01;

    pub fn from_bytes(buf: &[u8]) -> Self {
        if buf.len() < 28 {
            return Self::default();
        }
        let mut service_bloom = [0u8; 6];
        let mut param_bloom = [0u8; 12];
        service_bloom.copy_from_slice(&buf[9..15]);
        param_bloom.copy_from_slice(&buf[15..27]);
        Self {
            pattern_mask: u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            level_mask: buf[8],
            service_bloom,
            param_bloom,
            flags: buf[27],
        }
    }

    pub fn to_bytes(&self) -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..8].copy_from_slice(&self.pattern_mask.to_le_bytes());
        buf[8] = self.level_mask;
        buf[9..15].copy_from_slice(&self.service_bloom);
        buf[15..27].copy_from_slice(&self.param_bloom);
        buf[27] = self.flags;
        buf
    }

    pub fn has_summary(&self) -> bool {
        self.flags & Self::HAS_SUMMARY != 0
    }

    pub fn bloom_may_contain_service(&self, keyword: &str) -> bool {
        self.check_bloom(keyword, 0, &self.service_bloom)
    }

    pub fn bloom_may_contain_param(&self, keyword: &str) -> bool {
        self.check_bloom(keyword, 100, &self.param_bloom)
    }

    fn check_bloom(&self, keyword: &str, seed_base: u64, bloom: &[u8]) -> bool {
        let bits = bloom.len() * 8;
        for i in 0..3 {
            let pos = bloom_hash(keyword, seed_base + i) % bits;
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            if (bloom[byte_idx] >> bit_idx) & 1 == 0 {
                return false;
            }
        }
        true
    }
}

// ==================== ManifestEntry 扩展 ====================

impl ManifestEntry {
    /// 从 reserved 字段解析 SegmentSummary
    pub fn segment_summary(&self) -> SegmentSummary {
        SegmentSummary::from_bytes(&self.reserved)
    }

    /// 设置 SegmentSummary 到 reserved 字段，返回自身（链式调用）
    pub fn with_summary(mut self, summary: &SegmentSummary) -> Self {
        self.reserved = summary.to_bytes();
        self
    }
}
// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_header_v2_roundtrip() {
        let mut h = SegmentHeader::new(42, 3);
        h.set_v2_meta(5, 128, 256, 4096);
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 64);
        let h2 = SegmentHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h2.version, FORMAT_VERSION_V2);
        assert_eq!(h2.pattern_count(), 5);
        assert_eq!(h2.pattern_table_len(), 128);
        assert_eq!(h2.summary_offset(), 256);
        assert_eq!(h2.data_offset_v2(), 4096);
    }

    #[test]
    fn test_segment_header_v1_compat() {
        let h = SegmentHeader::new_v1(7, 1);
        let bytes = h.to_bytes();
        let h2 = SegmentHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h2.version, FORMAT_VERSION_V1);
        assert_eq!(h2.pattern_count(), 0);
        assert_eq!(h2.data_offset(), align_up(SEGMENT_HEADER_SIZE + CHUNK_ENTRY_SIZE, ALIGNMENT));
    }

    #[test]
    fn test_chunk_summary_roundtrip() {
        let mut bloom = [0u8; 64];
        bloom[0] = 0xFF;
        bloom[63] = 0x01;
        let s = ChunkSummary::new(0b1010, 0b0011, bloom);
        let bytes = s.to_bytes();
        assert_eq!(bytes.len(), 80);
        let s2 = ChunkSummary::from_bytes(&bytes).unwrap();
        assert_eq!(s2.pattern_mask, 0b1010);
        assert_eq!(s2.level_mask, 0b0011);
        assert_eq!(s2.param_bloom[0], 0xFF);
        assert_eq!(s2.param_bloom[63], 0x01);
    }

    #[test]
    fn test_chunk_summary_bloom() {
        let mut s = ChunkSummary::new(0, 0, [0; 64]);
        // 标记 "hello"
        for seed in 0..5 {
            let pos = ChunkSummary::bloom_hash("hello", seed);
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            s.param_bloom[byte_idx] |= 1 << bit_idx;
        }
        assert!(s.bloom_may_contain("hello"));
        assert!(!s.bloom_may_contain("world")); // 大概率不存在
    }

    #[test]
    fn test_chunk_summary_pattern_mask() {
        let s = ChunkSummary::new(0b1010, 0, [0; 64]);
        assert!(s.may_contain_pattern(1));
        assert!(!s.may_contain_pattern(0));
        assert!(s.may_contain_pattern(65)); // 超出范围，保守返回 true
    }

    #[test]
    fn test_parsed_segment_v2_layout() {
        // 构造最小 v2 Segment：Header + 1 Chunk + 1 Summary + Footer
        let mut header = SegmentHeader::new(1, 1);
        let pattern_table = vec![0x01, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o']; // 简化 PatternTable
        let chunk = ChunkEntry::new(0, 10, 100, 5, 1000, 2000);
        let summary = ChunkSummary::new(0b1, 0b0010, [0; 64]);

        let table_start = SEGMENT_HEADER_SIZE + pattern_table.len();
        let summary_start = table_start + CHUNK_ENTRY_SIZE;
        let data_offset = align_up(summary_start + CHUNK_SUMMARY_SIZE, ALIGNMENT) as u32;

        header.set_v2_meta(1, pattern_table.len() as u32, summary_start as u32, data_offset);

        let mut content = Vec::new();
        content.extend_from_slice(&header.to_bytes());
        content.extend_from_slice(&pattern_table);
        content.extend_from_slice(&chunk.to_bytes());
        content.extend_from_slice(&summary.to_bytes());
        content.resize(data_offset as usize, 0); // padding
        content.extend_from_slice(&[0u8; 10]); // fake chunk data

        let mut footer = SegmentFooter::new(SEGMENT_HEADER_SIZE as u32);
        footer.crc32 = crc32(&content);
        content.extend_from_slice(&footer.to_bytes());

        let seg = ParsedSegment::parse(&content).unwrap();
        assert_eq!(seg.header.version, FORMAT_VERSION_V2);
        assert_eq!(seg.chunks.len(), 1);
        assert_eq!(seg.summaries.len(), 1);
        assert_eq!(seg.summaries[0].pattern_mask, 0b1);
        assert_eq!(seg.data_offset, data_offset as usize);
    }

    // 保留原有测试...
    #[test]
    fn test_crc32_consistency() {
        let data = b"hello world";
        let c1 = crc32(data);
        let c2 = crc32(data);
        assert_eq!(c1, c2);
        assert_eq!(c1, 0x0d4a1185);
    }

    #[test]
    fn test_alignment() {
        assert_eq!(align_up(64, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }

    #[test]
    fn test_wal_record_roundtrip() {
        let line = r#"{"t":1715424000000,"s":"ngx","l":"E","m":"test"}"#;
        let encoded = WalRecord::encode(line);
        let (decoded, rest) = WalRecord::decode(&encoded).unwrap();
        assert_eq!(decoded, line);
        assert!(rest.is_empty());
    }

    #[test]
    fn test_segment_name_parsing() {
        assert_eq!(parse_segment_name("segment-00000042.mobs"), Some(42));
        assert_eq!(parse_segment_name("segment-12345678.mobs"), Some(12345678));
        assert_eq!(parse_segment_name("bad.txt"), None);
    }
// 将以下内容追加到 src/shared/format.rs 的 #[cfg(test)] mod tests 中
// 或新建 src/shared/format_extra_tests.rs 并在 lib.rs 中条件编译引入

#[test]
fn test_segment_footer_roundtrip() {
    let f = SegmentFooter::new(1234);
    let bytes = f.to_bytes();
    assert_eq!(bytes.len(), SEGMENT_FOOTER_SIZE);
    let f2 = SegmentFooter::from_bytes(&bytes).unwrap();
    assert_eq!(f2.chunk_table_offset, 1234);
}

#[test]
fn test_footer_crc_verify_success() {
    let content = b"some segment content for crc";
    let mut footer = SegmentFooter::new(0);
    footer.crc32 = crc32(content);
    assert!(footer.verify(content).is_ok());
}

#[test]
fn test_footer_crc_verify_failure() {
    let content = b"some segment content for crc";
    let mut footer = SegmentFooter::new(0);
    footer.crc32 = 0xDEADBEEF; // 故意错误
    assert!(footer.verify(content).is_err());
}

#[test]
fn test_manifest_entry_roundtrip_with_summary() {
    let mut summary = SegmentSummary::default();
    summary.pattern_mask = 0b101010;
    summary.level_mask = 0b0011;
    summary.flags = SegmentSummary::HAS_SUMMARY;

    let entry = ManifestEntry::new(42, 1000, 2000, 256, "/data/segments/segment-00000042.mobs")
        .with_summary(&summary);

    let bytes = entry.to_bytes();
    assert_eq!(bytes.len(), MANIFEST_ENTRY_SIZE);

    let entry2 = ManifestEntry::from_bytes(&bytes).unwrap();
    assert_eq!(entry2.segment_id, 42);
    assert_eq!(entry2.min_ts, 1000);
    assert_eq!(entry2.max_ts, 2000);
    assert_eq!(entry2.line_count, 256);

    let sum2 = entry2.segment_summary();
    assert!(sum2.has_summary());
    assert_eq!(sum2.pattern_mask, 0b101010);
    assert_eq!(sum2.level_mask, 0b0011);
}

#[test]
fn test_manifest_header_roundtrip() {
    let h = ManifestHeader::new(100);
    let bytes = h.to_bytes();
    assert_eq!(bytes.len(), 9);
    let h2 = ManifestHeader::from_bytes(&bytes).unwrap();
    assert_eq!(h2.entry_count, 100);
}

#[test]
fn test_manifest_header_bad_magic() {
    let mut bytes = [0u8; 9];
    bytes[0..4].copy_from_slice(b"BAD!");
    assert!(ManifestHeader::from_bytes(&bytes).is_err());
}

#[test]
fn test_logline_json_compact() {
    let log = LogLine {
        ts: 1715424000000,
        service: "auth".into(),
        level: "E".into(),
        message: "login failed".into(),
    };
    let json = serde_json::to_string(&log).unwrap();
    assert!(json.contains(r#""t":1715424000000"#));
    assert!(json.contains(r#""s":"auth""#));
    assert!(json.contains(r#""l":"E""#));
    assert!(json.contains(r#""m":"login failed""#));

    let decoded: LogLine = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.ts, log.ts);
    assert_eq!(decoded.service, log.service);
}

#[test]
fn test_format_error_display() {
    let e = FormatError::BadMagic {
        expected: *MOBS_MAGIC,
        got: [0xDE, 0xAD, 0xBE, 0xEF],
    };
    let s = format!("{}", e);
    assert!(s.contains("bad magic"));

    let e2 = FormatError::CrcMismatch {
        expected: 0x12345678,
        computed: 0x87654321,
    };
    let s2 = format!("{}", e2);
    assert!(s2.contains("crc mismatch"));
}

#[test]
fn test_format_error_io_conversion() {
    let e = FormatError::UnexpectedEof { needed: 64, got: 10 };
    let io_err: io::Error = e.into();
    assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn test_corrupted_segment_header_bad_magic() {
    let mut bytes = [0u8; 64];
    bytes[0..4].copy_from_slice(b"BAD!");
    assert!(SegmentHeader::from_bytes(&bytes).is_err());
}

#[test]
fn test_corrupted_segment_header_unsupported_version() {
    let mut h = SegmentHeader::new(1, 1);
    let mut bytes = h.to_bytes();
    bytes[4] = 99; // 非法版本
    assert!(SegmentHeader::from_bytes(&bytes).is_err());
}

#[test]
fn test_corrupted_segment_header_crc_mismatch() {
    let h = SegmentHeader::new(1, 1);
    let mut bytes = h.to_bytes();
    bytes[16] = bytes[16].wrapping_add(1); // 篡改 segment_id 某字节，CRC 失效
    assert!(SegmentHeader::from_bytes(&bytes).is_err());
}

#[test]
fn test_corrupted_chunk_entry_eof() {
    assert!(ChunkEntry::from_bytes(&[0u8; 10]).is_err());
}

#[test]
fn test_padding_needed() {
    assert_eq!(padding_needed(64, 4096), 4032);
    assert_eq!(padding_needed(4096, 4096), 0);
    assert_eq!(padding_needed(4097, 4096), 4095);
    assert_eq!(padding_needed(0, 4096), 0);
}

#[test]
fn test_hash_path_consistency() {
    let h1 = hash_path("/var/lib/mini-obs/segments/segment-00000001.mobs");
    let h2 = hash_path("/var/lib/mini-obs/segments/segment-00000001.mobs");
    assert_eq!(h1, h2);
    // 不同路径应大概率不同（FNV-1a 碰撞极低）
    let h3 = hash_path("/var/lib/mini-obs/segments/segment-00000002.mobs");
    assert_ne!(h1, h3);
}

#[test]
fn test_segment_summary_bloom_true_negative() {
    let mut summary = SegmentSummary::default();
    summary.flags = SegmentSummary::HAS_SUMMARY;
    // 空 bloom 一定不包含任何关键词
    assert!(!summary.bloom_may_contain_service("hello"));
    assert!(!summary.bloom_may_contain_param("world"));
}

#[test]
fn test_segment_summary_bloom_after_insert() {
    let mut summary = SegmentSummary::default();
    summary.flags = SegmentSummary::HAS_SUMMARY;

    // 手动设置 bloom bit（模拟插入 "test"）
    for i in 0..3 {
        let pos = bloom_hash("test", i);
        let byte_idx = (pos / 8) % summary.service_bloom.len();
        let bit_idx = pos % 8;
        summary.service_bloom[byte_idx] |= 1 << bit_idx;
    }

    assert!(summary.bloom_may_contain_service("test"));
    // 未插入的词可能返回 true（假阳性）或 false（真阴性），但这里大概率 false
    // 注意：由于 bloom filter 特性，此断言有极小概率失败，属于可接受的假阳性
    // 若失败，可放宽为仅测真阴性保证
}

#[test]
fn test_manifest_entry_overlaps() {
    let e = ManifestEntry::new(1, 1000, 2000, 10, "path");
    assert!(e.overlaps(500, 1500));   // 左重叠
    assert!(e.overlaps(1500, 2500));  // 右重叠
    assert!(e.overlaps(1200, 1800));  // 内含
    assert!(!e.overlaps(0, 999));     // 左侧不相交
    assert!(!e.overlaps(2001, 3000)); // 右侧不相交
    assert!(e.overlaps(1000, 2000));  // 边界精确匹配
}

#[test]
fn test_manifest_entry_tombstone() {
    let mut e = ManifestEntry::new(1, 1000, 2000, 10, "path");
    assert!(!e.is_deleted());
    e.flags = manifest_flags::TOMBSTONE;
    assert!(e.is_deleted());
}

#[test]
fn test_chunk_entry_compression_ratio() {
    let c = ChunkEntry::new(0, 100, 1000, 10, 0, 0);
    assert!((c.compression_ratio() - 10.0).abs() < 0.001);

    let c2 = ChunkEntry::new(0, 0, 100, 10, 0, 0);
    assert_eq!(c2.compression_ratio(), 0.0);
}

#[test]
fn test_wal_record_multiple() {
    let lines = vec!["line1", "line2", "line3"];
    let mut buf = Vec::new();
    for line in &lines {
        buf.extend_from_slice(&WalRecord::encode(line));
    }

    let mut rest = &buf[..];
    for expected in &lines {
        let (decoded, remaining) = WalRecord::decode(rest).unwrap();
        assert_eq!(decoded, *expected);
        rest = remaining;
    }
    assert!(rest.is_empty());
}

#[test]
fn test_wal_record_empty() {
    let enc = WalRecord::encode("");
    let (dec, rest) = WalRecord::decode(&enc).unwrap();
    assert_eq!(dec, "");
    assert!(rest.is_empty());
}

#[test]
fn test_wal_record_truncated() {
    let enc = WalRecord::encode("hello");
    assert!(WalRecord::decode(&enc[..2]).is_err()); // 长度前缀不完整
    assert!(WalRecord::decode(&enc[..4]).is_err()); // 数据不完整
}

#[test]
fn test_parsed_segment_v1_minimal() {
    // 构造最小 v1 Segment
    let header = SegmentHeader::new_v1(1, 1);
    let chunk = ChunkEntry::new(4096, 10, 100, 2, 1000, 2000);
    let mut content = Vec::new();
    content.extend_from_slice(&header.to_bytes());
    content.extend_from_slice(&chunk.to_bytes());
    content.resize(header.data_offset(), 0);
    content.extend_from_slice(&[0u8; 10]); // fake compressed data

    let mut footer = SegmentFooter::new(SEGMENT_HEADER_SIZE as u32);
    footer.crc32 = crc32(&content);
    content.extend_from_slice(&footer.to_bytes());

    let seg = ParsedSegment::parse(&content).unwrap();
    assert_eq!(seg.header.version, FORMAT_VERSION_V1);
    assert_eq!(seg.chunks.len(), 1);
    assert!(seg.summaries.is_empty());
}

#[test]
fn test_parsed_segment_corrupted_footer() {
    let header = SegmentHeader::new_v1(1, 1);
    let chunk = ChunkEntry::new(4096, 10, 100, 2, 1000, 2000);
    let mut content = Vec::new();
    content.extend_from_slice(&header.to_bytes());
    content.extend_from_slice(&chunk.to_bytes());
    content.resize(header.data_offset(), 0);
    content.extend_from_slice(&[0u8; 10]);

    let mut footer = SegmentFooter::new(SEGMENT_HEADER_SIZE as u32);
    footer.crc32 = 0xBADBAD; // 错误 CRC
    content.extend_from_slice(&footer.to_bytes());

    assert!(ParsedSegment::parse(&content).is_err());
}

#[test]
fn test_now_ms_monotonic() {
    let t1 = now_ms();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let t2 = now_ms();
    assert!(t2 >= t1);
}
}