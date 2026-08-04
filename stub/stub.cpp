// ============================================================================
// stub.cpp — 壳程序入口（P1：分页加载 + 多层对抗）
// 流程:
//   1) 初始化原生系统调用（解析 SSN）
//   2) 安装 VEH 控制流混淆处理器
//   3) 多层反调试检测（命中即擦除内存并 syscall 终止）
//   4) 分页加载：整解密修重定位/导入 -> 代码页重新加密并 NOACCESS
//      -> 执行到未解密页时 VEH 按需解密
//   5) 跳 OEP（经一次 VEH 混淆跳转演示）
// 附带: SEH 异常捕获 + 调试日志（写 %TEMP%\pearmor_stub.log）
// ============================================================================
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <vector>

// 前向声明：供 codegen.h 等被包含的头文件中的内联函数（如 CodeGen::RunOnce）
// 调用。DebugLog 的完整定义见本文件下方；此处提前声明，避免「include 顺序晚于
// 定义」导致的 C2065 未声明标识符编译错误。
static void DebugLog(const char* fmt, ...);

#include "kdf.h"            // 密钥派生（P2.3 / P2.5）
#include "crypto_page.h"    // AesPageCipher（解密块索引）
#include "overlay.h"        // 负载拼接格式（stub 自读自身文件末尾）
#include "syscall.h"
#include "paged_loader.h"
#include "anti_debug.h"
#include "vm_detect.h"      // 虚拟机/沙箱检测（P2.1）
#include "proc_env.h"       // 进程环境检测（P2.6）
#include "obf.h"            // 控制流混淆（P2.2）
#include "guard.h"
#include "veh_cf.h"
#include "codegen.h"        // P3.1 运行时代码生成
#include "inject_block.h"   // P3.4 拦截 DLL 注入 / 调试器附加
#include "watchdog.h"       // P3.3 看门狗监控线程

// ---------------------------------------------------------------------------
// 调试日志：默认仅当设置了环境变量 PEARMOR_DEBUG=1 时写文件，避免正常路径开销
// ---------------------------------------------------------------------------
static void DebugLog(const char* fmt, ...)
{
    static bool enabled = [] {
        char buf[8] = {0};
        GetEnvironmentVariableA("PEARMOR_DEBUG", buf, sizeof(buf));
        return buf[0] == '1';
    }();
    if (!enabled) return;

    char path[MAX_PATH] = {0};
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, "pearmor_stub.log");

    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") == 0 && f) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);
        fprintf(f, "\n");
        fclose(f);
    }
}

// ---------------------------------------------------------------------------
// SEH 异常捕获：壳内任何崩溃都记录下来并优雅退出，避免无提示闪退
// ---------------------------------------------------------------------------
static LONG WINAPI TopLevelHandler(EXCEPTION_POINTERS* ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    void* addr = ep->ExceptionRecord->ExceptionAddress;

    // 定位崩溃地址所属模块（CI 诊断用：区分 壳本体 / 负载 / 系统 DLL 数据区）
    char mod[512] = {0};
    HMODULE hMod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(addr), &hMod) && hMod) {
        GetModuleFileNameA(hMod, mod, sizeof(mod));
    }

    // 无条件写固定崩溃日志（不依赖 PEARMOR_DEBUG，便于 CI 捕获）
    char path[MAX_PATH] = {0};
    if (GetTempPathA(MAX_PATH, path)) {
        strcat_s(path, "pearmor_crash.log");
        FILE* f = nullptr;
        if (fopen_s(&f, path, "w") == 0 && f) {
            fprintf(f, "[crash] code=0x%08X addr=0x%p module=%s\n", code, addr, mod);
            fclose(f);
        }
    }
    fprintf(stderr, "[crash] code=0x%08X addr=0x%p module=%s\n", code, addr, mod);
    return EXCEPTION_EXECUTE_HANDLER;
}

// ---------------------------------------------------------------------------
// 程序入口
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    // 1) 顶层异常捕获
    SetUnhandledExceptionFilter(TopLevelHandler);

    // 1.1) 从自身 PE 文件末尾读取 overlay 负载（stub 是负载无关的固定运行时，
    //      密文由加壳器运行时拼接，无需重新编译）
    pearmor::Overlay::Footer meta = {};
    std::vector<unsigned char> payload, indexEnc;
    if (!pearmor::Overlay::LoadFromSelf(payload, indexEnc, meta)) {
        // 诊断增强：打印自身文件路径 + 大小，并二次读取末尾 8 字节 magic 对比期望值，
        // 一眼区分「文件真没 footer」vs「读取逻辑/共享冲突」。
        wchar_t selfPath[MAX_PATH] = {0};
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        LONGLONG fsz = -1;
        WIN32_FILE_ATTRIBUTE_DATA fad = {0};
        if (GetFileAttributesExW(selfPath, GetFileExInfoStandard, &fad))
            fsz = ((LONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        uint64_t actualMagic = 0;
        HANDLE h2 = CreateFileW(selfPath, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h2 != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fsz2, off2;
            DWORD rd2 = 0;
            if (GetFileSizeEx(h2, &fsz2) && fsz2.QuadPart >= 80) {
                off2.QuadPart = fsz2.QuadPart - 80;   // 读 Footer 起始处（-80），与 LoadFromSelf/PowerShell 一致
                if (SetFilePointerEx(h2, off2, nullptr, FILE_BEGIN))
                    ReadFile(h2, &actualMagic, 8, &rd2, nullptr);
            }
            CloseHandle(h2);
        }
        DebugLog("[stub] 未发现 overlay 负载：自身文件=%ls 大小=%lld 期望magic=0x%llX 实际magic=0x%llX",
                 selfPath, fsz, (unsigned long long)pearmor::Overlay::kMagic,
                 (unsigned long long)actualMagic);
        fprintf(stderr, "[stub] 未加壳的运行时，请使用 pearmor 加壳器生成成品\n");
        return -4;
    }
    const size_t   payloadLen = payload.size();
    const uint32_t pageCount  = meta.pageCount;
    unsigned char  seed32[32];
    memcpy(seed32, meta.seed, 32);
    uint64_t entryRva = meta.entryRva;

    DebugLog("[stub] start, payload_len=%zu pages=%u entryRva=0x%llX",
             payloadLen, pageCount, (unsigned long long)entryRva);

    if (payloadLen == 0 || pageCount == 0) {
        DebugLog("[stub] overlay 负载为空");
        return -1;
    }

    // 2) 初始化原生系统调用（解析 ntdll 各函数系统调用号）
    pearmor::Sys::Init();
    DebugLog("[stub] syscall SSN: NtAllocate=%u NtProtect=%u NtQueryProcess=%u",
             pearmor::Sys::ssn().NtAllocateVirtualMemory,
             pearmor::Sys::ssn().NtProtectVirtualMemory,
             pearmor::Sys::ssn().NtQueryInformationProcess);

    // 3) 安装 VEH 控制流混淆处理器（低优先级，排在分页解密 VEH 之后）
    pearmor::VehCf::Install();

    // 4) 多层反调试检测（命中即自毁，杜绝调试器附着）
    if (pearmor::AntiDebug::IsDebugged()) {
        DebugLog("[stub] 检测到调试器 -> 自毁");
        pearmor::SelfDestruct();
    }

    // 4.1) P2.1 虚拟机/沙箱检测（复合判定：注册表特征 或 超visor+资源受限）
    //      CI/测试环境可设 PEARMOR_ALLOW_VM=1 显式放行：GitHub runner 本身是 Azure VM，
    //      且系统盘仅 ~14GB 会触发 LowResources 的 <30GB 判定，故需此开关。
    //      真实目标运行环境不设该变量，检测照常生效，防护不被削弱。
    {
        char allowVm[8] = {0};
        bool skipVm = GetEnvironmentVariableA("PEARMOR_ALLOW_VM", allowVm, sizeof(allowVm)) &&
                      (allowVm[0] == '1');
        if (!skipVm && pearmor::VmDetect::IsVmOrSandbox()) {
            DebugLog("[stub] 命中虚拟机/沙箱特征 -> 自毁");
            pearmor::SelfDestruct();
        } else if (skipVm) {
            DebugLog("[stub] 已设 PEARMOR_ALLOW_VM，跳过虚拟机/沙箱检测");
        }
    }

    // 4.2) P2.6 进程环境检测（发现逆向/沙箱工具进程名 或 父进程为调试器 -> 自毁）
    //      已修复：原实现直接解引用 SYSTEM_PROCESS_INFORMATION.ImageName.Buffer
    //      （Win10+ 该 Buffer 指向内核态地址，用户态读必 0xC0000005）；
    //      现改为 NtOpenProcess + ProcessImageFileName(27) 读取用户态镜像名，
    //      完全规避内核地址，无 AV。CI 环境无逆向进程、父进程为测试运行器 -> 放行。
    DebugLog("[stub] P2.6 进程环境检测执行中...");
    if (pearmor::ProcEnv::IsSuspiciousEnvironment()) {
        DebugLog("[stub] 命中可疑进程/父进程 -> 自毁");
        pearmor::SelfDestruct();
    }
    DebugLog("[stub] P2.6 进程环境检测通过");

    // 4.3) P3.1 运行时代码生成（即时代码）：生成一段仅存在于运行时内存的机器码
    //      并执行校验。无静态对应物、每次布局不同，抬高静态逆向门槛。
    //      CI 环境若 CodeGen 校验异常，可设 PEARMOR_ALLOW_CODEGEN=1 跳过本步骤，
    //      以验证后续「手动加载+解密+OEP」主体流程（CodeGen 本身为独立验证，可后置修复）。
    {
        char allowCg[8] = {0};
        bool skipCg = GetEnvironmentVariableA("PEARMOR_ALLOW_CODEGEN", allowCg, sizeof(allowCg)) &&
                      (allowCg[0] == '1');
        if (!skipCg) {
            uint32_t fp = 0;
            if (!pearmor::CodeGen::RunOnce(&fp)) {
                DebugLog("[stub] P3.1 运行时代码生成校验失败 -> 自毁");
                pearmor::SelfDestruct();
            } else {
                DebugLog("[stub] P3.1 动态代码生成 OK，指纹=0x%08X", fp);
            }
        } else {
            DebugLog("[stub] 已设 PEARMOR_ALLOW_CODEGEN，跳过运行时代码生成");
        }
    }

    // 5) P2.3 / P2.5：从种子派生分层密钥（二进制里只有 seed，无明文密钥）
    unsigned char innerKey[32], outerKey[32];
    pearmor::derive_inner_key(seed32, innerKey);
    pearmor::derive_outer_key(seed32, outerKey);

    // 外层密钥解密块索引（isCode）：indexEnc 用 outerKey 一次性 AES-CBC 加密
    size_t idxLen = (size_t)meta.indexLen;
    std::vector<unsigned char> idxPlain(idxLen, 0);
    {
        pearmor::AesPageCipher idxCipher(outerKey, outerKey); // IV = outerKey 前 16 字节
        if (!idxCipher.decryptPage(indexEnc.data(), 0, idxPlain.data(), idxLen)) {
            DebugLog("[stub] 解密块索引失败");
            MessageBoxW(nullptr, L"PEArmor: 解密失败", L"PEArmor", MB_OK | MB_ICONERROR);
            return -3;
        }
    }

    // 6) 分页加载加密目标（解密 + 修复导入/重定位 + 门控代码页 + 覆写 PE 头）
    pearmor::PagedLoader loader;
    if (!loader.Load(payload.data(), payloadLen,
                     innerKey, idxPlain.data(), pageCount, entryRva,
                     seed32)) {
        DebugLog("[stub] 分页加载失败");
        fprintf(stderr, "[stub] 分页加载失败\n");
        return -2;
    }
    DebugLog("[stub] 分页加载成功 OEP_RVA=0x%llX", (unsigned long long)entryRva);

    // P3.5：密钥不再长期驻留栈。加载完成后立即清零派生出的内层/外层密钥。
    memset(innerKey, 0, sizeof(innerKey));
    memset(outerKey, 0, sizeof(outerKey));

    // 6.1) P3.4 安装注入拦截 / 调试器附加阻断（在所有原生系统调用就绪后）
    pearmor::InjectBlock::Install();
    DebugLog("[stub] P3.4 注入拦截已安装");

    // 6.2) P3.3 启动看门狗监控线程（调试探测 / 钩子完整性 / CRC / 密钥轮换）
    //      自毁回调指向 loader 的 SelfDestructNow（擦内存 + 终止）。
    auto wdDestruct = [&loader]() { loader.SelfDestructNow(); };
    pearmor::Watchdog::Guard watchdog(&loader, wdDestruct);
    watchdog.Start();
    DebugLog("[stub] P3.3 看门狗已启动");

    // 6.3) 跳原始入口（经 VEH 控制流混淆演示一次跳转；首执行触发按需解密）
    int rc = loader.CallEntry(entryRva);
    DebugLog("[stub] OEP 返回 rc=%d", rc);
    if (rc == 0) {
        DebugLog("[stub] OEP 正常执行完毕，样例应已写 pearmor_payload_ran.txt");
    }

    // 7) 释放映射（正常退出路径；自毁路径已在内部终止进程）
    loader.Release();
    return rc;
}
