#!/bin/bash
# mini-obs-test-runner.sh
# 一键运行全部追加测试的验证脚本

set -e

echo "========================================"
echo "Mini-OBS 追加测试验证脚本"
echo "========================================"

# 检查是否在项目根目录
if [ ! -f "Cargo.toml" ]; then
    echo "Error: 请在 mini-obs 项目根目录运行此脚本"
    exit 1
fi

echo ""
echo "[1/8] 运行 format 层追加测试..."
cargo test shared::format -- --nocapture

echo ""
echo "[2/8] 运行 compressor 层追加测试..."
cargo test agent::compressor -- --nocapture

echo ""
echo "[3/8] 运行 index 层追加测试..."
cargo test agent::index -- --nocapture

echo ""
echo "[4/8] 运行 collector 层追加测试..."
cargo test agent::collector -- --nocapture

echo ""
echo "[5/8] 运行 storage 层追加测试..."
cargo test agent::storage -- --nocapture

echo ""
echo "[6/8] 运行 template 层追加测试..."
cargo test agent::template -- --nocapture

echo ""
echo "[7/8] 运行集成测试..."
cargo test --test integration_tests -- --nocapture

echo ""
echo "[8/8] 运行全部单元测试（防回归）..."
cargo test

echo ""
echo "========================================"
echo "所有测试通过 ✓"
echo "========================================"
