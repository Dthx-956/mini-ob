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
//!   Segment 文件 = Header(64B) + ChunkTable(N×32B) + Padding + ZstdData + Footer(8B)
//!   Manifest 文件 = Magic(4B) + Version(1B) + EntryCount(4B) + Entry[](N×64B) + CRC(4B)
//!   WAL 文件 = JSON Lines（文本，崩溃恢复用）

use std::fmt;
use std::io;

// ==================== 常量 ====================

/// Segment 文件魔数
pub const MOBS_MAGIC: [u8; 4] = *b"MOBS";
/// Manifest 索引文件魔数
pub const MIDX_MAGIC: [u8; 4] = *b"MIDX";
/// WAL 文件魔数（文本头，便于人工识别）
pub const WAL_MAGIC: &[u8] = b"--- MOBS WAL ---\n";

/// 当前格式版本号
pub const FORMAT_VERSION: u8 = 1;

/// Segment 文件头大小
pub const SEGMENT_HEADER_SIZE: usize = 64;
/// Chunk 表项大小
pub const CHUNK_ENTRY_SIZE: usize = 32;
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
/// 0x04       Version         u8        = 1
/// 0x05       Flags           u8        = 0 (保留)
/// 0x06-0x07  Chunk Count     u16 LE    = N
/// 0x08-0x0F  Created At      u64 LE    = Unix millis
/// 0x10-0x13  Segment ID      u32 LE
/// 0x14-0x17  Header CRC32    u32 LE    = CRC(0x00..0x13)
/// 0x18-0x3F  Reserved        [u8; 40]  = 0
/// ```
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
    /// 创建新头（CRC 自动计算）
    pub fn new(segment_id: u32, chunk_count: u16) -> Self {
        let mut h = Self {
            magic: MOBS_MAGIC,
            version: FORMAT_VERSION,
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

    /// 从字节切片解析（零拷贝，不复制）
    pub fn from_bytes(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < SEGMENT_HEADER_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: SEGMENT_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != MOBS_MAGIC {
            return Err(FormatError::BadMagic {
                expected: MOBS_MAGIC,
                got: magic,
            });
        }
        let version = buf[4];
        if version != FORMAT_VERSION {
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

    /// 数据区起始偏移（Header + ChunkTable，4KB 对齐）
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
/// 0x00-0x03  Data Offset     u32 LE    = 相对文件开头的偏移
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

// ==================== Segment 文件尾 ====================

/// Segment Footer（8 字节，用于快速反向定位 ChunkTable 和 CRC 校验）
///
/// 布局：
/// ```text
/// 0x00-0x03  ChunkTable Offset   u32 LE    = Header 后的偏移
/// 0x04-0x07  Content CRC32       u32 LE    = Header+Table+Data 的 CRC
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
/// 0x18-0x1F  Path Hash       u64 LE    (FNV-1a，用于快速去重)
/// 0x20-0x23  Flags           u32 LE    (0=正常, 1=标记删除)
/// 0x24-0x3F  Reserved        [u8; 28]
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            magic: MIDX_MAGIC,
            version: FORMAT_VERSION,
            entry_count,
        }
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < 9 {
            return Err(FormatError::UnexpectedEof { needed: 9, got: buf.len() });
        }
        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != MIDX_MAGIC {
            return Err(FormatError::BadMagic { expected: MIDX_MAGIC, got: magic });
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
    pub data_offset: usize,
    pub data_len: usize,
    pub file_size: usize,
}

impl ParsedSegment {
    /// 从 mmap 或文件缓冲区完整解析 Segment
    pub fn parse(buf: &[u8]) -> Result<Self, FormatError> {
        if buf.len() < MIN_SEGMENT_SIZE {
            return Err(FormatError::UnexpectedEof {
                needed: MIN_SEGMENT_SIZE,
                got: buf.len(),
            });
        }

        let header = SegmentHeader::from_bytes(&buf[0..SEGMENT_HEADER_SIZE])?;
        let chunk_count = header.chunk_count as usize;

        // 解析 ChunkTable
        let table_start = SEGMENT_HEADER_SIZE;
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

        // 定位 Footer
        let footer_start = buf.len() - SEGMENT_FOOTER_SIZE;
        let footer = SegmentFooter::from_bytes(&buf[footer_start..])?;

        // 验证 Footer CRC（覆盖除 Footer 外的全部内容）
        let content = &buf[0..footer_start];
        footer.verify(content)?;

        // 验证 Footer 中的 table offset 是否匹配
        let expected_table_offset = SEGMENT_HEADER_SIZE as u32;
        if footer.chunk_table_offset != expected_table_offset {
            return Err(FormatError::InvalidField {
                field: "chunk_table_offset",
                value: footer.chunk_table_offset as u64,
            });
        }

        // 计算数据区范围
        let data_offset = header.data_offset();
        let data_end = footer_start;
        let data_len = if data_end > data_offset {
            data_end - data_offset
        } else {
            0
        };

        Ok(Self {
            header,
            chunks,
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

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_header_roundtrip() {
        let h = SegmentHeader::new(42, 3);
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), 64);
        let h2 = SegmentHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h.segment_id, h2.segment_id);
        assert_eq!(h.chunk_count, h2.chunk_count);
        assert_eq!(h.version, 1);
    }

    #[test]
    fn test_chunk_entry_roundtrip() {
        let c = ChunkEntry::new(4096, 1024, 8192, 100, 1715424000000, 1715424009999);
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), 32);
        let c2 = ChunkEntry::from_bytes(&bytes).unwrap();
        assert_eq!(c.offset, c2.offset);
        assert_eq!(c.compressed_sz, c2.compressed_sz);
        assert!(c.overlaps(1715424005000, 1715424010000));
        assert!(!c.overlaps(1715424010000, 1715424020000));
    }

    #[test]
    fn test_manifest_entry_roundtrip() {
        let m = ManifestEntry::new(7, 1000, 2000, 500, "/data/segments/segment-00000007.mobs");
        let bytes = m.to_bytes();
        assert_eq!(bytes.len(), 64);
        let m2 = ManifestEntry::from_bytes(&bytes).unwrap();
        assert_eq!(m.segment_id, m2.segment_id);
        assert_eq!(m.path_hash, m2.path_hash);
        assert!(m.overlaps(1500, 2500));
    }

    #[test]
    fn test_crc32_consistency() {
        let data = b"hello world";
        let c1 = crc32(data);
        let c2 = crc32(data);
        assert_eq!(c1, c2);
        // 与已知值交叉验证（zlib 兼容）
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

    #[test]
    fn test_parsed_segment_validation() {
        // 构造一个最小合法 Segment
        let header = SegmentHeader::new(1, 1);
        let chunk = ChunkEntry::new(4096, 10, 100, 5, 1000, 2000);
        let footer = {
            let mut f = SegmentFooter::new(SEGMENT_HEADER_SIZE as u32);
            let mut content = Vec::new();
            content.extend_from_slice(&header.to_bytes());
            content.extend_from_slice(&chunk.to_bytes());
            // 填充到 4KB
            let data_offset = header.data_offset();
            let padding = vec![0u8; data_offset - content.len()];
            content.extend_from_slice(&padding);
            // 假数据
            content.extend_from_slice(&[0u8; 10]); // chunk.compressed_sz = 10
            f.crc32 = crc32(&content);
            f
        };

        let mut buf = Vec::new();
        buf.extend_from_slice(&header.to_bytes());
        buf.extend_from_slice(&chunk.to_bytes());
        let data_offset = header.data_offset();
        buf.resize(data_offset + 10, 0); // 数据区 + 假压缩数据
        buf.extend_from_slice(&footer.to_bytes());

        let seg = ParsedSegment::parse(&buf).unwrap();
        assert_eq!(seg.header.segment_id, 1);
        assert_eq!(seg.chunks.len(), 1);
        assert_eq!(seg.total_ratio(), 10.0); // original 100 / compressed 10
    }
}
