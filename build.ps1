# ============================================================================
# build.ps1 — 一键构建：编译 加壳器 + 壳运行时 + 样例 -> 加壳 -> 产出成品 EXE
# 用法:
#   powershell -ExecutionPolicy Bypass -File build.ps1 [-Target <app.exe>] [-Out <out.exe>]
# 缺省 Target 时使用 test/test_payload.cpp 自检样例。
#
# 架构说明（overlay 拼接版）：
#   - stub 是"负载无关"的固定运行时（不再依赖 packer 生成的 config 头），
#     三个 target（packer/stub/test_payload）可一次编译；
#   - 加壳器运行期把密文负载拼接进 stub 二进制末尾（overlay），
#     产出最终成品 exe —— 下载加壳器 + stub 即可在任意 Windows 上加壳，
#     无需本地 MSVC 重编译。
# ============================================================================
param(
    [string]$Target = "",
    [string]$Out = "",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Build  = Join-Path $Root "build"
$Packer = Join-Path $Build "Release\pearmor-packer.exe"
$Stub   = Join-Path $Build "Release\pearmor-stub.exe"

if ($Clean -and (Test-Path $Build)) { Remove-Item -Recurse -Force $Build }

# ---- 阶段 0：配置 ----
Write-Host "[1/3] CMake 配置..." -ForegroundColor Cyan
& cmake -S $Root -B $Build -A x64 -DPEARMOR_BUILD_TEST=ON
if ($LASTEXITCODE -ne 0) { throw "cmake configure 失败" }

# ---- 阶段 1：一次编译 加壳器 + 壳运行时 + 样例（stub 已负载无关） ----
Write-Host "[2/3] 编译 加壳器 + 壳运行时 + 样例..." -ForegroundColor Cyan
& cmake --build $Build --config Release --target packer stub test_payload --parallel
if ($LASTEXITCODE -ne 0) { throw "cmake build 失败" }

# ---- 阶段 2：确定目标并加壳 ----
if (-not $Target) {
    $Target = Join-Path $Build "Release\test_payload.exe"
}
if (-not (Test-Path $Target)) { throw "未找到目标程序: $Target" }
if (-not $Out) { $Out = Join-Path $Root "packed_app.exe" }

Write-Host "[3/3] 加壳 $Target -> $Out" -ForegroundColor Cyan
& $Packer $Target -o $Out -stub $Stub
if ($LASTEXITCODE -ne 0) { throw "packer 加壳失败" }
Write-Host "完成: $Out" -ForegroundColor Green
