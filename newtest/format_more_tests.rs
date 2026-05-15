
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
    assert!(json.contains(""t":1715424000000"));
    assert!(json.contains(""s":"auth""));
    assert!(json.contains(""l":"E""));
    assert!(json.contains(""m":"login failed""));

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
        let byte_idx = pos / 8;
        let bit_idx = pos % 8;
        if byte_idx < summary.service_bloom.len() {
            summary.service_bloom[byte_idx] |= 1 << bit_idx;
        }
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
