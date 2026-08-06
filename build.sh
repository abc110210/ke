#!/usr/bin/env bash
# ============================================================================
# build.sh — 一键构建（Git Bash / MSYS2 下用，Windows 也支持）
# 用法: ./build.sh [target.exe] [out.exe]
# 与 build.ps1 同构：stub 负载无关，packer 运行期把密文拼到 stub 末尾（overlay）。
# ============================================================================
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
PACKER="$BUILD/Release/pearmor-packer.exe"
STUB="$BUILD/Release/pearmor-stub.exe"
TARGET="${1:-}"
OUT="${2:-}"

echo "[1/3] cmake configure"
cmake -S "$ROOT" -B "$BUILD" -A x64 -DPEARMOR_BUILD_TEST=ON

echo "[2/3] build packer + stub"
cmake --build "$BUILD" --config Release --target packer stub --parallel

# test/ 下的用户 exe 优先；样例 test_payload.cpp 存在才回退样例
if [ -z "$TARGET" ]; then
    USER_EXE="$(ls "$ROOT"/test/*.exe 2>/dev/null | head -1)"
    if [ -n "$USER_EXE" ]; then
        TARGET="$USER_EXE"
    elif [ -f "$ROOT/test/test_payload.cpp" ]; then
        TARGET="$BUILD/Release/test_payload.exe"
    else
        echo "错误: test/ 下无 exe 且 test_payload.cpp 已删除，请放入目标程序"; exit 1
    fi
fi
[ -f "$TARGET" ] || { echo "错误: 目标不存在 $TARGET"; exit 1; }
if [ -z "$OUT" ]; then
    OUT="$ROOT/$(basename "$TARGET" .exe)_packed.exe"
fi

echo "[3/3] pack $TARGET -> $OUT (overlay 拼接)"
"$PACKER" "$TARGET" -o "$OUT" -stub "$STUB"
echo "完成: $OUT"
