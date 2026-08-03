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
    stub/pe_loader.h
    stub/syscall.asm
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
        /guard:cf
    )
endif()
set_target_properties(stub PROPERTIES
    OUTPUT_NAME "pearmor-stub"
    WIN32_EXECUTABLE TRUE
)

# ---- Test payload（CI 自检用：加壳后应写验证文件并返回 0） ----
option(PEARMOR_BUILD_TEST "Build the test payload" ON)
if(PEARMOR_BUILD_TEST)
    add_executable(test_payload
        test/test_payload.cpp
    )
    target_compile_definitions(test_payload PRIVATE _CRT_SECURE_NO_WARNINGS)
    set_target_properties(test_payload PROPERTIES
        OUTPUT_NAME "test_payload"
        # 直接以 main 为原始入口，避免被壳调用时二次初始化 CRT
        LINK_FLAGS "/ENTRY:main"
    )
endif()

enable_testing()
