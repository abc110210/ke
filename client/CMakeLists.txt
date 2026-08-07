cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# Hanbot 存档打包上传器 —— 客户端
#
# 设计目标：
#   1. 纯 Win32 API + C++17，零第三方依赖（压缩、加密、HTTP 全自研或用系统组件）
#   2. /MT 静态链接 CRT，目标机器不需要装任何 VC++ 运行库
#   3. 只用系统自带的 winhttp / comctl32 等 DLL
# ---------------------------------------------------------------------------

project(HanbotSavesUploader VERSION 1.0.0 LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "本项目只支持 Windows 平台")
endif()

# ---------------------------------------------------------------------------
# WebView2 SDK（用于嵌入 HTML 渲染层）
#   优先用静态 loader（WebView2LoaderStatic.lib），避免额外 DLL。
#   查找顺序（越靠前越可靠）：
#     1) 环境变量 WEBVIEW2_INCLUDE_DIR / WEBVIEW2_LIB_DIR
#        —— 由 CI 递归定位真实位置后注入，可绕开 NuGet 包内部目录结构差异
#     2) -DWEBVIEW2_SDK_ROOT=<dir> 指定的 SDK 根目录，按 NuGet 布局取 build/native
#     3) 默认 <client>/../webview2sdk（CI 把包解压到仓库根目录的 webview2sdk/）
# ---------------------------------------------------------------------------
set(WEBVIEW2_SDK_ROOT "$ENV{WEBVIEW2_SDK_ROOT}" CACHE PATH "WebView2 SDK 根目录")
if(NOT WEBVIEW2_SDK_ROOT)
    set(WEBVIEW2_SDK_ROOT "${CMAKE_SOURCE_DIR}/../webview2sdk" CACHE PATH "WebView2 SDK 根目录" FORCE)
endif()

# 优先用 CI 直接给出的精确目录（已递归定位到真实位置）
if(DEFINED ENV{WEBVIEW2_INCLUDE_DIR} AND EXISTS "$ENV{WEBVIEW2_INCLUDE_DIR}/WebView2.h")
    set(WEBVIEW2_INCLUDE_DIR "$ENV{WEBVIEW2_INCLUDE_DIR}")
else()
    set(WEBVIEW2_INCLUDE_DIR "${WEBVIEW2_SDK_ROOT}/build/native/include")
endif()

if(DEFINED ENV{WEBVIEW2_LIB_DIR} AND EXISTS "$ENV{WEBVIEW2_LIB_DIR}/WebView2LoaderStatic.lib")
    set(WEBVIEW2_LOADER_LIB "$ENV{WEBVIEW2_LIB_DIR}/WebView2LoaderStatic.lib")
else()
    set(WEBVIEW2_LOADER_LIB "${WEBVIEW2_SDK_ROOT}/build/native/x64/WebView2LoaderStatic.lib")
endif()

# 用 if(EXISTS) 做确定性校验（比 find_path 的 -NOTFOUND 哨兵可靠，后者会让
# 「找不到」被当成「已找到」从而静默带着错误路径往下编，最终卡在 include）
if(NOT EXISTS "${WEBVIEW2_INCLUDE_DIR}/WebView2.h")
    message(FATAL_ERROR
        "找不到 WebView2.h。请先获取 Microsoft.Web.WebView2 包并解压到仓库根的 webview2sdk/，\n"
        "或用 -DWEBVIEW2_SDK_ROOT=<dir>（需含 build/native/include）或环境变量 WEBVIEW2_INCLUDE_DIR 指定。\n"
        "当前解析到的包含目录: ${WEBVIEW2_INCLUDE_DIR}")
endif()
if(NOT EXISTS "${WEBVIEW2_LOADER_LIB}")
    message(FATAL_ERROR
        "找不到 WebView2LoaderStatic.lib。\n当前解析到的链接库: ${WEBVIEW2_LOADER_LIB}")
endif()

message(STATUS " WebView2 包含目录 : ${WEBVIEW2_INCLUDE_DIR}")
message(STATUS " WebView2 链接库   : ${WEBVIEW2_LOADER_LIB}")

# 把 webui/index.html 以资源形式内嵌进 exe（生成 html_rc.rc）
# 唯一真源：client/webui/index.html（2026-08-04 起统一以此为单一来源；
# 根 webui/index.html 已废弃改名 _DEPRECATED_root_prototype.html，不再作为构建输入）。
set(HTML_SRC "${CMAKE_SOURCE_DIR}/webui/index.html")
# 规范化（CMAKE_SOURCE_DIR 即 client/，此处无 ".."；保留 ABSOLUTE 以防不同调用方式下路径歧义）
get_filename_component(HTML_SRC "${HTML_SRC}" ABSOLUTE)
if(NOT EXISTS "${HTML_SRC}")
    message(FATAL_ERROR
        "找不到要内嵌的 client/webui/index.html（已解析为: ${HTML_SRC}）。\n"
        "请确认 client/webui/index.html 已提交（CI 需 checkout 到该文件）。")
endif()
message(STATUS " 内嵌的 HTML 源 : ${HTML_SRC}")
# 用原生反斜杠路径；并把每个反斜杠转义成 \\，避免 RC 编译器把 \a \t 等当成转义序列
file(TO_NATIVE_PATH "${HTML_SRC}" HTML_NATIVE_PATH)
string(REPLACE "\\" "\\\\" HTML_RC_PATH "${HTML_NATIVE_PATH}")
configure_file(res/html_rc.in "${CMAKE_CURRENT_BINARY_DIR}/html_rc.rc" @ONLY)

# ---- 静态链接 CRT：/MT（Release） /MTd（Debug）----
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---- 默认 Release ----
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# 源文件
# ---------------------------------------------------------------------------
set(APP_SOURCES
    src/main.cpp
    src/config.cpp
    src/secrets.cpp
    src/util.cpp
    src/json_mini.cpp
    src/deflate.cpp
    src/inflate.cpp
    src/zip_writer.cpp
    src/zip_reader.cpp
    src/http_client.cpp
    src/lol_finder.cpp
    src/uploader.cpp
)

set(APP_HEADERS
    src/resource.h
    src/config.h
    src/secrets.h
    src/util.h
    src/json_mini.h
    src/deflate.h
    src/inflate.h
    src/zip_writer.h
    src/zip_reader.h
    src/http_client.h
    src/lol_finder.h
    src/uploader.h
)

set(APP_RESOURCES
    res/app.rc
    ${CMAKE_CURRENT_BINARY_DIR}/html_rc.rc
)

# WIN32 => 生成 GUI 子系统程序，不弹黑框
add_executable(${PROJECT_NAME} WIN32
    ${APP_SOURCES}
    ${APP_HEADERS}
    ${APP_RESOURCES}
)

target_include_directories(${PROJECT_NAME} PRIVATE src ${WEBVIEW2_INCLUDE_DIR})

# ---------------------------------------------------------------------------
# 编译定义
# ---------------------------------------------------------------------------
target_compile_definitions(${PROJECT_NAME} PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    STRICT
    WINVER=0x0A00          # Windows 10
    _WIN32_WINNT=0x0A00
    NTDDI_VERSION=0x0A000000
)

# ---------------------------------------------------------------------------
# 构建时间戳：注入到 exe，启动日志打印，便于一眼区分「到底跑的是哪个 exe」
#   专门解决反复出现的「用户以为换了新 exe、其实还在跑旧构建」排查死循环。
#   格式 ISO-8601 UTC，全 ASCII、无空格/无中文，避开 RC 编译器与 cl 的编码坑。
#   取值在 CMake 配置阶段生成（≈构建开始时刻）。
# ---------------------------------------------------------------------------
string(TIMESTAMP BUILD_TIMESTAMP "%Y-%m-%dT%H:%M:%SZ" UTC)
target_compile_definitions(${PROJECT_NAME} PRIVATE
    BUILD_TIMESTAMP="${BUILD_TIMESTAMP}"
)

# ---------------------------------------------------------------------------
# 系统库（全部是 Windows 自带的，不需要额外分发）
# ---------------------------------------------------------------------------
target_link_libraries(${PROJECT_NAME} PRIVATE
    winhttp       # HTTP 客户端
    comctl32      # 进度条 / 现代控件
    shlwapi       # 路径工具
    shell32       # 文件对话框、打开资源管理器
    ole32         # IFileDialog
    uuid
    advapi32      # 注册表、用户名
    user32
    gdi32
    bcrypt        # 加密安全随机数
    version
    uxtheme
    ws2_32        # GetMachineIp 用的 Winsock（ntohl 等）
    iphlpapi      # GetAdaptersAddresses 取本机 IP
    dwmapi        # DWM 圆角窗口属性
    ${WEBVIEW2_LOADER_LIB}   # WebView2 静态 loader
)

# ---------------------------------------------------------------------------
# MSVC 专属设置
# ---------------------------------------------------------------------------
# 混淆 / 加固准备（Release）：
#   - 全量优化：/O2（速度最大化，含自动内联）/Oi（内建函数）/GL+/LTCG（全程序优化）
#   - /Gy 按函数分拆，配合 /OPT:REF /OPT:ICF 链接期剔除未用代码、合并重复函数
#   - /GUARD:CF 控制流防护（CFG），增加逆向难度、防止间接调用被劫持
#   - Release 不生成 PDB（无 /Zi、无 /DEBUG），彻底去符号，便于后续接混淆器
#   后续若接 Obfuscator-LLVM / VMProtect：
#     1) OLLVM：把编译器换成 clang-cl（指向带 ollvm 的 LLVM），并加
#        -mllvm -fla -mllvm -sub -mllvm -bcf 等混淆 pass；本 CMake 已用 /GL+/LTCG，
#        换 clang 时改为 -flto 即可。
#     2) VMProtect / Themida：在链接产物（HanbotSavesUploader.exe）外包一层
#        虚拟化壳，需单独购买授权并在 CI 产物上跑加壳步骤。
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /utf-8                # 源码与执行字符集都按 UTF-8 处理，中文不乱码
        /W3
        /permissive-
        /Zc:__cplusplus
        /EHsc
        /MP                   # 多核编译
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/Oi>
        # CI 134: /GL + /LTCG + /GUARD:CF 全部去掉——手动 PE 映射环境与 LTCG 产生的
        # 非常规代码模式（跨函数内联/非标准栈帧/CFG 位图）不兼容，导致 CRT 启动期堆损坏。
        # 去掉后验证是否修复。如果修复，壳侧后续增加 LTCG/CFG 兼容层。
        $<$<CONFIG:Release>:/Gy>
    )

    target_link_options(${PROJECT_NAME} PRIVATE
        /MANIFEST:NO          # 清单由 res/app.rc 嵌入，避免两份清单冲突
        /SUBSYSTEM:WINDOWS
        /ENTRY:wWinMainCRTStartup
        $<$<CONFIG:Release>:/OPT:REF>
        $<$<CONFIG:Release>:/OPT:ICF>
        $<$<CONFIG:Release>:/INCREMENTAL:NO>
    )

    # rc.exe 默认按系统 ANSI 代码页解析，显式指定 UTF-8，
    # 否则 GitHub 英文环境的构建机上版本信息里的中文会变乱码
    set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} /nologo /c65001")
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "HanbotSavesUploader"
    VS_DPI_AWARE "PerMonitor"
)

# ---------------------------------------------------------------------------
# 安装 / 打包产物
# ---------------------------------------------------------------------------
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION .)

message(STATUS "----------------------------------------------------")
message(STATUS " ${PROJECT_NAME} v${PROJECT_VERSION}")
message(STATUS " 运行库     : ${CMAKE_MSVC_RUNTIME_LIBRARY} (静态)")
message(STATUS " 生成器     : ${CMAKE_GENERATOR}")
message(STATUS "----------------------------------------------------")
