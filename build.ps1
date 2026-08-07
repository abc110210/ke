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

# ---- 阶段 1：一次编译 加壳器 + 壳运行时（样例 test_payload 存在才编译，可选） ----
Write-Host "[2/3] 编译 加壳器 + 壳运行时 + 样例..." -ForegroundColor Cyan
# 注意：目标列表必须是 PowerShell 数组（@(...)），不能是空格分隔的字符串！
# 字符串 "packer stub" 会被 cmake/MSBuild 当成单个工程名 → MSB1009: Project file does not exist
$Targets = @("packer", "stub")
if (Test-Path (Join-Path $Root "test\test_payload.cpp")) { $Targets += "test_payload" }
& cmake --build $Build --config Release --target $Targets --parallel
if ($LASTEXITCODE -ne 0) { throw "cmake build 失败" }

# ---- 阶段 1.5：编译 client（如果源码存在，编译后覆盖 test/ 下的 exe） ----
# CI 135：之前 test/HanbotSavesUploader.exe 是预编译的旧版，client/CMakeLists.txt 改动不生效。
# 改为 CI 从 client/ 源码编译，保证 CMakeLists.txt 的编译选项变更能自动反映到加壳目标。
$clientDir = Join-Path $Root "client"
if (Test-Path (Join-Path $clientDir "CMakeLists.txt")) {
    Write-Host "[1.5/3] 编译 client (HanbotSavesUploader)..." -ForegroundColor Cyan
    $clientBuild = Join-Path $Build "client"
    # 递归查找 WebView2 SDK（CI runner 可能在不同路径）
    $wv2Include = Get-ChildItem $Root -Recurse -Filter "WebView2.h" -ErrorAction SilentlyContinue | Select-Object -First 1
    $wv2Lib = Get-ChildItem $Root -Recurse -Filter "WebView2LoaderStatic.lib" -ErrorAction SilentlyContinue | Select-Object -First 1
    $wv2Env = @{}
    if ($wv2Include) { $wv2Env["WEBVIEW2_INCLUDE_DIR"] = $wv2Include.DirectoryName }
    if ($wv2Lib) { $wv2Env["WEBVIEW2_LIB_DIR"] = $wv2Lib.DirectoryName }
    foreach ($k in $wv2Env.Keys) {
        Set-Item -Path "Env:$k" -Value $wv2Env[$k]
        Write-Host "  $k = $($wv2Env[$k])"
    }
    & cmake -S $clientDir -B $clientBuild -A x64 2>&1 | Write-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[1.5/3] client cmake configure 失败，跳过（用 test/ 下已有 exe）" -ForegroundColor Yellow
    } else {
        & cmake --build $clientBuild --config Release --parallel 2>&1 | Write-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[1.5/3] client 编译失败，跳过（用 test/ 下已有 exe）" -ForegroundColor Yellow
        } else {
            # 找编译出的 exe 并覆盖到 test/
            $clientExe = Join-Path $clientBuild "Release\HanbotSavesUploader.exe"
            if (Test-Path $clientExe) {
                Copy-Item $clientExe (Join-Path $Root "test\HanbotSavesUploader.exe") -Force
                Write-Host "[1.5/3] client 编译成功，已覆盖 test/HanbotSavesUploader.exe" -ForegroundColor Green
            }
        }
    }
}
# ---- 阶段 2：确定目标并加壳 ----
# 目标优先级：显式 -Target > test/ 下用户放入的 exe > 样例 test_payload（可选，cpp 被删则跳过）
if (-not $Target) {
    $userExe = Get-ChildItem (Join-Path $Root "test") -Filter *.exe -File -ErrorAction SilentlyContinue |
               Select-Object -First 1
    if ($userExe) {
        $Target = $userExe.FullName
        Write-Host "[3/3] 检测到用户目标: $Target（放入 test 文件夹的 exe 自动成为加壳对象）" -ForegroundColor Yellow
    } elseif (Test-Path (Join-Path $Root "test\test_payload.cpp")) {
        $Target = Join-Path $Build "Release\test_payload.exe"
        Write-Host "[3/3] test/ 下未发现用户 exe，改用样例 test_payload" -ForegroundColor Yellow
    } else {
        throw "test/ 下未发现可加壳的 exe（且 test_payload.cpp 已删除）。请把要加壳的程序放入 test/ 文件夹后重试"
    }
}
if (-not (Test-Path $Target)) { throw "未找到目标程序: $Target" }
if (-not $Out) {
    # 产物名带目标主名（如 HanbotSavesUploader_packed.exe），用户从 artifact 一眼认出
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Target)
    $Out = Join-Path $Root ($baseName + "_packed.exe")
}

Write-Host "[3/3] 加壳 $Target -> $Out" -ForegroundColor Cyan
& $Packer $Target -o $Out -stub $Stub
if ($LASTEXITCODE -ne 0) { throw "packer 加壳失败" }
Write-Host "完成: $Out" -ForegroundColor Green
