
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
    assert_eq!(encoded[0].param_encoding.data.len(), 2); // 仅 u16 param_count = 0
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
    assert_eq!(TemplateExtractor::read_u64_le(bytes, 3, 5), 0x6f); // 部分读取
}

#[test]
fn test_tokenize_various() {
    let cases = vec![
        ("simple", vec!["simple"]),
        ("two words", vec!["two", " ", "words"]),
        ("a,b.c", vec!["a", ",", "b", ".", "c"]),
        ("num123_456", vec!["num123_456"]),
    ];
    for (input, expected) in cases {
        let tokens = TemplateExtractor::tokenize(input);
        assert_eq!(tokens, expected.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    }
}
