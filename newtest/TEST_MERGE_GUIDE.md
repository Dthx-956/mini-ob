# Mini-OBS 追加测试合并指南

## 文件清单

| 文件 | 目标位置 | 说明 |
|------|---------|------|
| `format_more_tests.rs` | `src/shared/format.rs` 的 `#[cfg(test)] mod tests` 中 | format 层追加 22 个测试 |
| `compressor_more_tests.rs` | `src/agent/compressor.rs` 的 `#[cfg(test)] mod tests` 中 | 压缩层追加 8 个测试 |
| `index_more_tests.rs` | `src/agent/index.rs` 的 `#[cfg(test)] mod tests` 中 | 索引层追加 12 个测试 |
| `collector_more_tests.rs` | `src/agent/collector.rs` 的 `#[cfg(test)] mod tests` 中 | 采集层追加 13 个测试 |
| `storage_more_tests.rs` | `src/agent/storage.rs` 的 `#[cfg(test)] mod tests` 中 | 存储层追加 14 个测试 |
| `template_more_tests.rs` | `src/agent/template.rs` 的 `#[cfg(test)] mod tests` 中 | 模板层追加 16 个测试 |
| `integration_tests.rs` | `tests/integration_tests.rs`（新建） | 端到端集成测试 10 个 |

## 合并步骤

### 1. 单元测试追加（复制粘贴）

对每个 `*_more_tests.rs` 文件，将其中的 `#[test]` 函数复制到对应源文件的 `#[cfg(test)] mod tests { ... }` 块内。

例如，打开 `src/shared/format.rs`，在最后一个 `}` 之前（即 `mod tests` 结束之前）粘贴 `format_more_tests.rs` 的内容。

### 2. 集成测试部署

```bash
mkdir -p tests
cp integration_tests.rs tests/integration_tests.rs
```

确保 `Cargo.toml` 中 `[dependencies]` 已包含测试所需的 crate（当前依赖已足够，无需新增）。

### 3. 运行全部测试

```bash
# 单元测试
cargo test

# 仅 format 层
cargo test shared::format

# 仅 agent 层
cargo test agent::

# 集成测试
cargo test --test integration_tests

# 包含打印输出
cargo test -- --nocapture
```

## 测试覆盖矩阵

| 模块 | 原有测试 | 追加测试 | 覆盖重点 |
|------|---------|---------|---------|
| format | 8 | 22 | 错误处理、损坏数据、边界值、JSON roundtrip、CRC 验证、Manifest 全链路 |
| compressor | 2 | 8 | 空 batch、JSON fallback、大 batch、压缩比、字典、损坏数据、Unicode |
| index | 4 | 12 | query_range、query_by_id、持久化、自愈重建、ID 单调性、stats、并发 |
| collector | 8 | 13 | 文件 tail、ISO 时间戳、降级、超长行、stop 信号、nginx 状态码、level 推断 |
| storage | 3 | 14 | WAL 恢复、多 segment、时间边界、limit、关键词、大消息、高频写入、损坏容错 |
| template | 7 | 16 | 空 batch、单条、相同消息、Unicode、超长消息、XOR 边界、PatternTable roundtrip、错误处理 |
| integration | 0 | 10 | E2E 写入查询、压缩比、Collector+Storage 管道、崩溃恢复、并发、Index 自愈、性能基准 |

**总计：新增 85 个测试用例**

## 已知注意事项

1. **文件 tail 测试**：`collector_more_tests.rs` 中的 `test_file_tail_collection` 使用临时文件，在 Windows 上可能需要调整路径分隔符。
2. **字典测试**：`test_compressor_with_dictionary` 依赖 `zstd::dict::from_samples`，若你的 zstd crate 版本未启用此功能，可能需要条件编译或移除。
3. **性能基准**：`test_bulk_write_performance` 的 5 秒阈值是 Debug 模式下的宽松值，CI 中若使用 `--release` 应大幅缩短。
4. **Bloom Filter 假阳性**：`test_segment_summary_bloom_after_insert` 存在理论上的假阳性概率（约 3%），若偶发失败可放宽断言或增加 seed 数量。
5. **并发测试**：`test_concurrent_append` 假设 `StorageEngine::append` 的锁竞争不会导致死锁，若未来改为 lock-free 需同步更新。

## 快速验证脚本

```bash
#!/bin/bash
set -e

echo "=== Running all tests ==="
cargo test -- --nocapture

echo ""
echo "=== Running integration tests ==="
cargo test --test integration_tests -- --nocapture

echo ""
echo "=== Test complete ==="
```
