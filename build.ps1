# ============================================================================
# build.ps1 — 一键构建：打包器 -> 加密负载 -> 嵌入壳 -> 产出加壳后的 EXE
# 用法:
#   powershell -ExecutionPolicy Bypass -File build.ps1 [-Target <app.exe>] [-Out <out.exe>]
# 缺省 Target 时使用 test/test_payload.cpp 自检样例。
# ============================================================================
param(
    [string]$Target = "",
    [string]$Out = "",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Build  = Join-Path $Root "build"
$Packer = Join-Path $Build "packer\Release\pearmor-packer.exe"
$Stub   = Join-Path $Build "stub\Release\pearmor-stub.exe"

if ($Clean -and (Test-Path $Build)) { Remove-Item -Recurse -Force $Build }

# ---- 阶段 0：配置 + 编译 打包器 与 自检样例 ----
Write-Host "[1/4] CMake 配置..." -ForegroundColor Cyan
& cmake -S $Root -B $Build -A x64 -DPEARMOR_BUILD_TEST=ON
if ($LASTEXITCODE -ne 0) { throw "cmake configure 失败" }

Write-Host "[2/4] 编译打包器 + 样例..." -ForegroundColor Cyan
& cmake --build $Build --config Release --target packer test_payload --parallel
if ($LASTEXITCODE -ne 0) { throw "cmake build(packer) 失败" }

# ---- 阶段 1：确定负载并打包 ----
if (-not $Target) {
    $Target = Join-Path $Build "test_payload\Release\test_payload.exe"
}
if (-not (Test-Path $Target)) { throw "未找到目标程序: $Target" }

if (-not $Out) { $Out = Join-Path $Root "packed_app.exe" }
$Header = Join-Path $Root "stub\packer_config.h"

Write-Host "[3/4] 打包 $Target -> $Header" -ForegroundColor Cyan
& $Packer $Target $Header
if ($LASTEXITCODE -ne 0) { throw "packer 失败" }

# ---- 阶段 2：用新负载重新编译壳 ----
Write-Host "[4/4] 编译嵌入加密负载的壳..." -ForegroundColor Cyan
& cmake --build $Build --config Release --target stub --parallel
if ($LASTEXITCODE -ne 0) { throw "cmake build(stub) 失败" }

Copy-Item -Force $Stub $Out
Write-Host "完成: $Out" -ForegroundColor Green
