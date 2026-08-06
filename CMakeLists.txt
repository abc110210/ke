cmake_minimum_required(VERSION 3.20)
project(PEArmor LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Packer（开发者工具，本机/CI 用，可带 CRT） ----
add_executable(packer
    packer/packer.cpp
)
target_compile_definitions(packer PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
if(MSVC)
    target_compile_options(packer PRIVATE /O2 /W3)
endif()
set_target_properties(packer PROPERTIES
    OUTPUT_NAME "pearmor-packer"
)

# ---- Stub（壳本体：精简、无控制台、Release 优化） ----
add_executable(stub
    stub/stub.cpp
    stub/resources.rc   # 统一图标：编译期嵌入根目录 app.ico（换图标=替换 app.ico 重编 stub）
    stub/pe_loader.h
    stub/syscall.asm
    stub/hook_shim.asm  # P3.4 注入拦截 inline hook 的汇编 shim（CI 83 修复：SSN/栈参数保真）
    stub/syscall.h
    stub/crypto_page.h
    stub/paged_loader.h
    stub/anti_debug.h
    stub/anti_dump.h
    stub/integrity.h
    stub/veh_cf.h
    stub/guard.h
    stub/codegen.h
    stub/inject_block.h
    stub/watchdog.h
)
target_include_directories(stub PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
target_link_libraries(stub PRIVATE bcrypt ntdll advapi32)
target_compile_definitions(stub PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
if(MSVC)
    target_compile_options(stub PRIVATE
        /O2
        /Gy
        /GF
        /GS-
        /W3
        /utf-8
        # 注意：刻意不启用 /guard:cf。
        # 壳会“间接调用跳进动态 VirtualAlloc 出来的 payload 内存”（OepThunk 里的 fn()），
        # 目标地址不在壳模块的 CFG 合法调用目标位图内，CFG 校验必失败并 __fastfail
        # 抛出 STATUS_STACK_BUFFER_OVERRUN(0xC0000404) 使进程秒退且不经过 TopLevelHandler
        # （表现为“跳 OEP 即崩、无 crash.log”）。壳自身靠 VEH+加密+手动映射防护，
        # CFG 对保护器无意义且会破坏 OEP 跳转，故关闭。
    )
endif()
set_target_properties(stub PROPERTIES
    OUTPUT_NAME "pearmor-stub"
    WIN32_EXECUTABLE TRUE
    # CI 78：stub 固定基址 = 0x1C0000000（远离 payload 链接基址 0x140000000）。
    # 若 payload 能加载到其 preferredBase(0x140000000)，重定位 delta=0 → 镜像内容与原版
    # 完全一致 → 对抗「目标程序自校验自身镜像完整性」场景（Hanbot 疑似：所有保护机制
    # 全排除后仍主动 RaiseException 自杀）。stub 占高地址，把 0x140000000 留给 payload。
    # 注意：stub 仍启用 ASLR（/DYNAMICBASE 默认开），基址仅作为"首选"，ASLR 可能改变它。
    LINK_FLAGS "/BASE:0x1C0000000"
)

# ---- Test payload（可选自检样例：仅当 test/test_payload.cpp 存在才构建） ----
# 注意：用户可能删除 test_payload.cpp、test/ 下只放真实目标 exe（如 HanbotSavesUploader.exe），
# 此时必须跳过该 target，否则 cmake configure 因找不到源文件而失败。
option(PEARMOR_BUILD_TEST "Build the test payload" ON)
if(PEARMOR_BUILD_TEST AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/test_payload.cpp")
    add_executable(test_payload
        test/test_payload.cpp
    )
    target_compile_definitions(test_payload PRIVATE _CRT_SECURE_NO_WARNINGS)
    if(MSVC)
        # /GS-：样例以 /ENTRY:main 直接作为入口，跳过了 CRT 的 __security_init_cookie，
        # 栈 Cookie 校验无意义且可能引发误报（0xC0000404 fast-fail）。样例本身只用纯
        # Win32 API + ExitProcess，无 CRT 收尾依赖，关闭 /GS 安全。
        target_compile_options(test_payload PRIVATE /GS-)
    endif()
    set_target_properties(test_payload PROPERTIES
        OUTPUT_NAME "test_payload"
        # 直接以 main 为原始入口，避免被壳调用时二次初始化 CRT
        LINK_FLAGS "/ENTRY:main"
    )
endif()

enable_testing()
