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
#include <memory>        // std::unique_ptr（看门狗 Guard 挂函数作用域）

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
    // CI 59：exit=0xC0000005 但无 crash.log → 确认 TopLevelHandler 是否被调用
    DebugLog("[crash] TopLevelHandler 触发: code=0x%08X addr=%p", (unsigned)code, addr);

    // 定位崩溃地址所属模块（CI 诊断用：区分 壳本体 / 负载 / 系统 DLL 数据区）
    char mod[512] = {0};
    HMODULE hMod = nullptr;
    uintptr_t modBase = 0;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(addr), &hMod) && hMod) {
        GetModuleFileNameA(hMod, mod, sizeof(mod));
        modBase = reinterpret_cast<uintptr_t>(hMod);
    }
    // 无条件写固定崩溃日志（不依赖 PEARMOR_DEBUG，便于 CI 捕获）
    char path[MAX_PATH] = {0};
    if (GetTempPathA(MAX_PATH, path)) {
        strcat_s(path, "pearmor_crash.log");
        FILE* f = nullptr;
        if (fopen_s(&f, path, "w") == 0 && f) {
            fprintf(f, "[crash] code=0x%08X addr=0x%p module=%s 模块内偏移=0x%llX\n",
                    code, addr, mod,
                    (unsigned long long)(modBase ? (reinterpret_cast<uintptr_t>(addr) - modBase) : 0));
            fclose(f);
        }
    }
    fprintf(stderr, "[crash] code=0x%08X addr=0x%p module=%s 模块内偏移=0x%llX\n",
            code, addr, mod,
            (unsigned long long)(modBase ? (reinterpret_cast<uintptr_t>(addr) - modBase) : 0));
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
    // 注意：此处【内联实现】完整读取逻辑（最大共享 + 重试 + 逐段校验），不依赖
    // overlay.h 的 LoadFromSelf——CI 48 实测：同样的逻辑写在 stub.cpp 里 100% 成功，
    // 写在 overlay.h 里却失败（疑 CI 编译的 overlay.h 为旧版/增量构建未重编）。
    pearmor::Overlay::Footer meta = {};
    std::vector<unsigned char> payload, indexEnc;
    bool overlayOk = false;
    // ---- r54 诊断变量：记录两种读取方式的每步结果（一次 CI 定位失败点）----
    bool   dCreate = false; DWORD dCreateErr = 0;
    bool   dSize = false;   LONGLONG dSizeVal = 0;
    bool   dSeek = false;
    DWORD  dFooterRd = 0;   uint64_t dFooterMagic = 0;
    bool   dPayloadOk = false; bool dIndexOk = false;
    bool   dMemTried = false; bool dMemPrecheck = false; uint64_t dMemMagic = 0;
    {
        // 【r54 双保险 + 分步诊断】优先文件读取（分块+重试），失败 fallback 内存镜像
        // （VirtualQuery 预检防 AV）。每步记录结果，CI 日志直接显示卡在哪一步。
        wchar_t path[MAX_PATH] = {0};
        GetModuleFileNameW(nullptr, path, MAX_PATH);
        // ---- 方式 A：文件读取（分块 + 重试）----
        HANDLE h = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 8 && h == INVALID_HANDLE_VALUE; attempt++) {
            h = CreateFileW(path, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) { dCreateErr = GetLastError(); Sleep(200); }
        }
        dCreate = (h != INVALID_HANDLE_VALUE);
        if (h != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fsz = {0};
            dSize = (GetFileSizeEx(h, &fsz) != 0);
            dSizeVal = fsz.QuadPart;
            constexpr uint64_t kFooterSz = sizeof(pearmor::Overlay::Footer); // CI 74 起含 origFileName
            bool ok = dSize && fsz.QuadPart > (LONGLONG)kFooterSz;
            if (ok) {
                LARGE_INTEGER off; off.QuadPart = fsz.QuadPart - (LONGLONG)kFooterSz;
                dSeek = SetFilePointerEx(h, off, nullptr, FILE_BEGIN) != 0;
                ok = dSeek;
                DWORD rd = 0;
                if (ok) ok = (ReadFile(h, &meta, (DWORD)kFooterSz, &rd, nullptr) != 0);
                dFooterRd = rd;
                dFooterMagic = meta.magic;
                if (ok) ok = (rd == kFooterSz && meta.magic == pearmor::Overlay::kMagic &&
                              meta.version == pearmor::Overlay::kVersion);
                if (ok) {
                    auto readAll = [&](uint64_t fileOff, void* buf, uint32_t len) -> bool {
                        LARGE_INTEGER o; o.QuadPart = (LONGLONG)fileOff;
                        if (!SetFilePointerEx(h, o, nullptr, FILE_BEGIN)) return false;
                        uint8_t* p = reinterpret_cast<uint8_t*>(buf);
                        uint32_t total = 0;
                        constexpr uint32_t CHUNK = 0x10000;   // 64KB
                        while (total < len) {
                            DWORD want = (len - total) > CHUNK ? CHUNK : (len - total);
                            DWORD got = 0;
                            if (!ReadFile(h, p + total, want, &got, nullptr) || got == 0)
                                return false;
                            total += got;
                        }
                        return true;
                    };
                    // 布局：stub | payload(payloadLen) | index(indexLen) | footer(kFooterSz)
                    // index 偏移 = 文件末尾 - kFooterSz - indexLen；payload 偏移 = index 偏移 - payloadLen。
                    // 【CI 53 实证】此前 indexOff 少了 -indexLen（写成 fsz-80=footer 位置），
                    // 从 footer 处读 indexLen 字节 → 超文件末尾 → 读不满 → Index=0。
                    uint64_t indexOff   = (uint64_t)fsz.QuadPart - kFooterSz - (uint64_t)meta.indexLen;
                    uint64_t payloadOff = indexOff - (uint64_t)meta.payloadLen;
                    ok = (payloadOff <= indexOff);
                    if (ok) {
                        try { payload.resize(meta.payloadLen); indexEnc.resize(meta.indexLen); }
                        catch (...) { ok = false; }
                    }
                    if (ok) { dPayloadOk = readAll(payloadOff, payload.data(), meta.payloadLen); ok = dPayloadOk; }
                    if (ok) { dIndexOk = readAll(indexOff, indexEnc.data(), meta.indexLen); ok = dIndexOk; }
                }
            }
            CloseHandle(h);
            overlayOk = ok;
        }
        // ---- 方式 B fallback：内存镜像读取（VirtualQuery 预检）----
        if (!overlayOk) {
            dMemTried = true;
            meta = {};
            payload.clear(); indexEnc.clear();
            HMODULE mod = GetModuleHandleW(nullptr);
            uint8_t* base = reinterpret_cast<uint8_t*>(mod);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
            DWORD fileDataEnd = nt->OptionalHeader.SizeOfHeaders;
            IMAGE_SECTION_HEADER* lastSec = nullptr;
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                DWORD end = sec[i].PointerToRawData + sec[i].SizeOfRawData;
                if (end > fileDataEnd) fileDataEnd = end;
                if (sec[i].SizeOfRawData > 0) lastSec = &sec[i];
            }
            DWORD align = nt->OptionalHeader.SectionAlignment;
            if (align < 0x1000) align = 0x1000;
            uintptr_t ovMem = 0;
            if (lastSec) {
                DWORD lastSize = (lastSec->Misc.VirtualSize > lastSec->SizeOfRawData
                                    ? lastSec->Misc.VirtualSize : lastSec->SizeOfRawData);
                DWORD memEnd = lastSec->VirtualAddress + ((lastSize + align - 1) & ~(align - 1));
                ovMem = reinterpret_cast<uintptr_t>(base) + memEnd;
            }
            LARGE_INTEGER fileSize = {0};
            WIN32_FILE_ATTRIBUTE_DATA fad = {0};
            if (GetFileAttributesExW(path, GetFileExInfoStandard, &fad))
                fileSize.QuadPart = ((LONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            uint64_t overlayTotal = (uint64_t)fileSize.QuadPart - fileDataEnd;
            constexpr uint64_t kFooterSz = sizeof(pearmor::Overlay::Footer);
            if (ovMem && overlayTotal >= kFooterSz) {
                // VirtualQuery 逐页预检：overlay 区域必须全部 COMMIT 且可读，否则放弃
                bool memReadable = true;
                MEMORY_BASIC_INFORMATION mbi;
                for (uintptr_t a = ovMem; a < ovMem + overlayTotal; a += mbi.RegionSize) {
                    if (VirtualQuery(reinterpret_cast<LPCVOID>(a), &mbi, sizeof(mbi)) == 0 ||
                        mbi.State != MEM_COMMIT ||
                        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0) {
                        memReadable = false;
                        break;
                    }
                }
                dMemPrecheck = memReadable;
                if (memReadable) {
                    uint8_t* footerPtr = reinterpret_cast<uint8_t*>(ovMem) + overlayTotal - kFooterSz;
                    memcpy(&meta, footerPtr, (size_t)kFooterSz);
                    dMemMagic = meta.magic;
                    if (meta.magic == pearmor::Overlay::kMagic &&
                        meta.version == pearmor::Overlay::kVersion) {
                        uint64_t need = (uint64_t)meta.payloadLen + (uint64_t)meta.indexLen + sizeof(pearmor::Overlay::Footer);
                        if (need <= overlayTotal) {
                            try {
                                payload.resize(meta.payloadLen);
                                indexEnc.resize(meta.indexLen);
                                memcpy(payload.data(), reinterpret_cast<void*>(ovMem), meta.payloadLen);
                                memcpy(indexEnc.data(), reinterpret_cast<void*>(ovMem + meta.payloadLen),
                                       meta.indexLen);
                                overlayOk = true;
                            } catch (...) { overlayOk = false; }
                        }
                    }
                }
            }
        }
    }
    if (!overlayOk) {
        wchar_t selfPath[MAX_PATH] = {0};
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
        LONGLONG fsz = -1;
        WIN32_FILE_ATTRIBUTE_DATA fad = {0};
        if (GetFileAttributesExW(selfPath, GetFileExInfoStandard, &fad))
            fsz = ((LONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        DebugLog("[stub] overlay 读取失败(r54)：文件方式 Create=%d(Err=%lu) Size=%d(%lld) Seek=%d FooterRd=%u FooterMagic=0x%llX Payload=%d Index=%d | 内存方式 Tried=%d Precheck=%d MemMagic=0x%llX | 自身=%ls 大小=%lld",
                 (int)dCreate, dCreateErr, (int)dSize, dSizeVal, (int)dSeek,
                 dFooterRd, (unsigned long long)dFooterMagic, (int)dPayloadOk, (int)dIndexOk,
                 (int)dMemTried, (int)dMemPrecheck, (unsigned long long)dMemMagic,
                 selfPath, fsz);
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
    //    CI 74：把原版文件名（overlay footer）传给 loader 做模块伪装。
    pearmor::PagedLoader loader;
    const wchar_t* origName = (meta.origFileName[0] != 0) ? meta.origFileName : nullptr;
    if (!loader.Load(payload.data(), payloadLen,
                     innerKey, idxPlain.data(), (uint32_t)idxPlain.size(), entryRva,
                     seed32, origName)) {
        DebugLog("[stub] 分页加载失败");
        fprintf(stderr, "[stub] 分页加载失败\n");
        return -2;
    }
    DebugLog("[stub] 分页加载成功 OEP_RVA=0x%llX", (unsigned long long)entryRva);

    // P3.5：密钥不再长期驻留栈。加载完成后立即清零派生出的内层/外层密钥。
    memset(innerKey, 0, sizeof(innerKey));
    memset(outerKey, 0, sizeof(outerKey));

    // 6.1) P3.4 安装注入拦截 / 调试器附加阻断（在所有原生系统调用就绪后）
    //      诊断开关：PEARMOR_DISABLE_INJECT_BLOCK=1 跳过安装，用于隔离
    //      "inline hook NtOpenProcess 等与业务冲突" vs "加载/解密/门控本身"。
    {
        char v[8] = {0};
        bool skipInject = GetEnvironmentVariableA("PEARMOR_DISABLE_INJECT_BLOCK", v, sizeof(v)) && (v[0] == '1');
        if (skipInject) {
            DebugLog("[stub] PEARMOR_DISABLE_INJECT_BLOCK=1，跳过注入拦截安装");
        } else {
            pearmor::InjectBlock::Install();
            DebugLog("[stub] P3.4 注入拦截已安装");
        }
    }

    // 6.2) P3.3 启动看门狗监控线程（调试探测 / 钩子完整性 / CRC / 密钥轮换）
    //      自毁回调指向 loader 的 SelfDestructNow（擦内存 + 终止）。
    //      诊断开关：PEARMOR_DISABLE_WATCHDOG=1 不启动，用于隔离
    //      "看门狗线程/密钥轮换/重加密竞态" vs "业务代码冲突"。
    //      注意：Guard 必须存活到函数结束（跳 OEP 后仍要监控），故用 unique_ptr 挂函数作用域。
    std::unique_ptr<pearmor::Watchdog::Guard> watchdog;
    {
        char v[8] = {0};
        bool skipWd = GetEnvironmentVariableA("PEARMOR_DISABLE_WATCHDOG", v, sizeof(v)) && (v[0] == '1');
        if (skipWd) {
            DebugLog("[stub] PEARMOR_DISABLE_WATCHDOG=1，跳过看门狗启动");
        } else {
            auto wdDestruct = [&loader]() { loader.SelfDestructNow(); };
            watchdog = std::make_unique<pearmor::Watchdog::Guard>(&loader, wdDestruct);
            watchdog->Start();
            DebugLog("[stub] P3.3 看门狗已启动");
        }
    }

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

// ============================================================================
// P3.4 注入拦截决策函数实现（CI 83）
// 定义在 .cpp 而非头文件：extern "C" inline 只产生弱 COMDAT 符号，
// 汇编 obj（hook_shim.asm）引用时链接失败（LNK2019），强符号才能被解析。
// 决策路径要求【可重入、无副作用、零 kernel32/user32 依赖】——
// shim 是在 ntdll 入口被跳转进来的，任何线程都可能随时进入；
// PidOfHandle 走原生 NtQueryInformationProcess syscall，不触发被钩函数。
// ============================================================================
extern "C" __declspec(noinline) int InjectShouldBlock(int which, void* arg)
{
    using namespace pearmor::InjectBlock;
    if (!g_selfPid) return 0;
    if (which == 2) {
        // NtOpenProcess：arg = CLIENT_ID*，UniqueProcess == 本进程 -> 拦截
        if (arg) {
            ULONG_PTR pid = *(const ULONG_PTR*)arg;
            if (pid == g_selfPid) return 1;
        }
        return 0;
    }
    // which 0/1：arg = ProcessHandle。目标为其它进程 -> 拦截。
    // 伪句柄 (HANDLE)-1 恒等于当前进程（GetCurrentProcess），直接比较。
    HANDLE hProc = (HANDLE)arg;
    if (hProc && hProc != (HANDLE)-1 && PidOfHandle(hProc) != g_selfPid)
        return 1;
    return 0;
}

// ============================================================================
// CI 89：工作线程 TLS 挂载（NtCreateThreadEx hook 配套）
// 系统 loader 不知道手动加载的 payload → 业务创建的工作线程 TEB 里 payload 的
// TLS 槽是 null → 工作线程访问 __declspec(thread) 变量 = null+偏移（如 this=0x20）
// → 随机崩溃（多线程先后崩、时活时崩全吻合）。解法：hook_shim.asm 的 shim1 在
// 放行 NtCreateThreadEx 前调 PrepareThreadStart，把 StartRoutine 换成 TlsMountWrapper
// ——新线程【内部】先挂 payload TLS 槽（MountCurrentThreadTls），再调原线程函数。
// ============================================================================
static void* g_origStart = nullptr;
static void* g_origArg   = nullptr;
static SRWLOCK g_wrapLock = SRWLOCK_INIT;

// 新线程入口包装器：挂 TLS 后调用原线程函数（原 StartRoutine/Argument 由
// PrepareThreadStart 存入全局；创建线程短临界区内使用，竞争窗口极小）。
static DWORD WINAPI TlsMountWrapper(LPVOID arg)
{
    (void)arg;
    void* start = g_origStart;
    void* a     = g_origArg;
    pearmor::MountCurrentThreadTls();   // 挂当前线程的 payload TLS（命名空间自由函数）
    return (reinterpret_cast<DWORD(WINAPI*)(LPVOID)>(start))(a);
}

// 被 hook_shim.asm 的 shim1（NtCreateThreadEx 放行路径）调用。
// startSlot/argSlot = 调用者栈上第 5/6 参数（StartRoutine/Argument）的地址。
// 定义在 .cpp（extern "C" 强符号，供汇编 EXTERN 引用；头文件 inline 有弱符号问题）。
extern "C" __declspec(noinline) void PrepareThreadStart(void* startSlot, void* argSlot)
{
    void* origStart = *(void**)startSlot;
    void* origArg   = *(void**)argSlot;
    AcquireSRWLockExclusive(&g_wrapLock);
    g_origStart = origStart;
    g_origArg   = origArg;
    ReleaseSRWLockExclusive(&g_wrapLock);
    *(void**)startSlot = reinterpret_cast<void*>(&TlsMountWrapper);
}
