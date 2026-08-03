#!/usr/bin/env bash
# ============================================================================
# build.sh — 一键构建（Git Bash / MSYS2 下用，Windows 也支持）
# 用法: ./build.sh [target.exe] [out.exe]
# ============================================================================
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
PACKER="$BUILD/packer/Release/pearmor-packer.exe"
STUB="$BUILD/stub/Release/pearmor-stub.exe"
TARGET="${1:-}"
OUT="${2:-$ROOT/packed_app.exe}"

echo "[1/4] cmake configure"
cmake -S "$ROOT" -B "$BUILD" -A x64 -DPEARMOR_BUILD_TEST=ON

echo "[2/4] build packer + test_payload"
cmake --build "$BUILD" --config Release --target packer test_payload --parallel

if [ -z "$TARGET" ]; then
    TARGET="$BUILD/test/Release/test_payload.exe"
fi
[ -f "$TARGET" ] || { echo "错误: 目标不存在 $TARGET"; exit 1; }

echo "[3/4] pack $TARGET -> stub/packer_config.h"
"$PACKER" "$TARGET" "$ROOT/stub/packer_config.h"

echo "[4/4] build stub (with embedded payload)"
cmake --build "$BUILD" --config Release --target stub --parallel

cp -f "$STUB" "$OUT"
echo "完成: $OUT"
