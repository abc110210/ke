// ============================================================================
// paged_loader.h — 分页（按需解密）PE64 加载器  ★P1 核心★
//
// 设计要点：
//   1) 启动时“整镜像一次性解密”仅用于修复重定位/导入（必要步骤）；
//   2) 修复完成后，所有【代码页】立即重新加密并置 PAGE_NOACCESS；
//   3) CPU 执行到某未解密代码页 → 触发 ACCESS_VIOLATION → VEH 捕获并
//      仅解密该页 → 置 PAGE_EXECUTE_READ → 续跑；
//   4) 监控线程周期性把“空闲超时代码页”重新加密，杜绝完整明文常驻内存；
//   5) 解密即做 CRC 自校验，被 Patch 直接自毁；周期性扫描 ntdll 钩子防 Dump。
//
// 全程使用原生 Nt* 系统调用（syscall.h），绕过 Win32 API 钩子。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mutex>
#include <atomic>

#include "pe_loader.h"     // ManualPeLoader 静态辅助（重定位/导入/TLS）
#include "crypto_page.h"   // AesPageCipher 按页加解密
#include "kdf.h"           // 密钥派生（P2.3 / P2.5）
#include "syscall.h"       // 原生系统调用
#include "guard.h"         // 自毁
#include "anti_dump.h"     // ntdll 钩子检测
#include "integrity.h"     // 页面 CRC 自校验
#include "veh_cf.h"        // VEH 控制流混淆

namespace pearmor {

// 独立的 SEH 辅助函数：单独成函数，参数全为 POD，内部可安全用 __try/__except。
// （MSVC 禁止在含 C++ 对象展开的函数的函数里用 __try，故 RtlInsertInvertedFunctionTable
//  这种未文档化、可能崩溃的调用必须隔离到本函数内执行。）
static int CallRtlInsertInvertedFunctionTable(pRtlInsertInvertedFunctionTable fn,
                                              PVOID tableBase, ULONG sizeOfImage)
{
    if (!fn) return -1;
    __try {
        fn(tableBase, sizeOfImage, 0);
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1; // 触发了异常（已吞掉）
    }
}

// 正经走栈：从异常现场（通常停在 KERNELBASE!RaiseException 内）用 RtlVirtualUnwind 逐帧展开，
// 只展开系统/CRT 帧（它们自带 .pdata，可正常展开），停在「进入 payload 的前一帧」——
// 该帧的返回地址即 payload 内真实 throw 调用点（call _CxxThrowException 之下一条指令）。
// 不依赖 payload 注册 .pdata（CI 36 教训：不完整 pdata 会引发展开死循环）。
// 用途：CI 诊断"为何一进 OEP 就抛 0xE06D7363"，精确定位 throw 站点模块。
static void LogRealThrowSite(EXCEPTION_POINTERS* ep)
{
    using PFN_Lookup = PRUNTIME_FUNCTION (NTAPI*)(ULONG64, PULONG64, PVOID);
    using PFN_Unwind  = PVOID (NTAPI*)(ULONG, ULONG64, ULONG64, PRUNTIME_FUNCTION, PCONTEXT, PVOID*, PULONG64, PVOID);
    static PFN_Lookup pLookup = nullptr;
    static PFN_Unwind  pUnwind = nullptr;
    static bool resolved = false;
    if (!resolved) {
        if (HMODULE ntdll = GetModuleHandleA("ntdll.dll")) {
            pLookup = (PFN_Lookup)GetProcAddress(ntdll, "RtlLookupFunctionEntry");
            pUnwind = (PFN_Unwind )GetProcAddress(ntdll, "RtlVirtualUnwind");
        }
        resolved = true;
    }
    if (!pLookup || !pUnwind) { DebugLog("[veh] LogRealThrowSite: Rtl* 未解析，跳过"); return; }

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.Rip = ep->ContextRecord->Rip;
    ctx.Rsp = ep->ContextRecord->Rsp;
    ctx.Rbp = ep->ContextRecord->Rbp;
    ctx.Rbx = ep->ContextRecord->Rbx;
    ctx.Rsi = ep->ContextRecord->Rsi;
    ctx.Rdi = ep->ContextRecord->Rdi;
    ctx.R12 = ep->ContextRecord->R12;
    ctx.R13 = ep->ContextRecord->R13;
    ctx.R14 = ep->ContextRecord->R14;
    ctx.R15 = ep->ContextRecord->R15;

    uintptr_t pb = 0, pe = 0;
    if (PagedLoader::g_instance && !PagedLoader::g_instance->pageBase.empty()) {
        pb = (uintptr_t)PagedLoader::g_instance->pageBase[0];
        pe = pb + (size_t)PagedLoader::g_instance->pageBase.size() * PagedLoader::g_instance->pageSize;
    }

    DebugLog("[veh] === 正经走栈定位真实 throw 站点（从 RaiseException 现场向上展开）===");
    if (pb) DebugLog("[veh] payload 基址区间=[%p, %p) （#N 落在此区间即 payload 自身抛）", (void*)pb, (void*)pe);
    for (int d = 0; d < 16; d++) {
        ULONG64 imgBase = 0;
        PRUNTIME_FUNCTION fe = pLookup(ctx.Rip, &imgBase, nullptr);
        if (!fe) {
            DebugLog("[veh]   #%d rip=%p 无 .pdata（payload/未知帧边界）—— 上方一帧即真实 throw 调用点",
                     d, (void*)ctx.Rip);
            break;
        }
        ULONG64 establisher = 0;
        PVOID  handlerData = nullptr;
        // HandlerType=0：只计算调用者上下文，不触发任何语言处理器（避免重入 VEH）
        pUnwind(0, imgBase, ctx.Rip, fe, &ctx, &handlerData, &establisher, nullptr);
        char mod[256] = {0};
        HMODULE hMod = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)ctx.Rip, &hMod) && hMod)
            GetModuleFileNameA(hMod, mod, sizeof(mod));
        bool inPayload = (ctx.Rip >= pb && ctx.Rip < pe);
        DebugLog("[veh]   #%d rip=%p module=%s%s",
                 d, (void*)ctx.Rip, mod, inPayload ? "  <<< 落在 payload 内(真实 throw 站点)" : "");
        if (inPayload) break;
    }
}

class PagedLoader {
public:
    struct PageState {
        bool     decrypted = false;  // 当前为明文（可执行）
        uint64_t lastUsed  = 0;      // 最近使用时间戳(ms)
        bool     isCode    = false;  // 是否代码页（需按需解密/重加密）
        uint32_t baseCrc   = 0;      // 运行期基准 CRC（重定位/导入修复后建立）
    };

    PagedLoader() = default;
    ~PagedLoader() { Release(); }

    // P3.2 非连续内存布局开关。
    // 注意：非连续布局与「需要重定位的镜像」不兼容——重定位/导入修复假设单一连续基址，
    // 分散后跨页指针会指向未映射内存（CI 21 实测：ApplyRelocations 内 0xC0000005）。
    // 因此默认【关闭】，走标准连续手动加载（与正常 PE 加载等价，必定正确），
    // 先跑通 Load+OEP 主体流程。待 pe_loader 支持 page-resident 重定位后再开启。
    // 显式 PEARMOR_NONCONTIG=1 可启用非连续模式（当前仅用于该专项验证）。
    static bool NonContigEnabled() {
        char v[8] = {0};
        GetEnvironmentVariableA("PEARMOR_NONCONTIG", v, sizeof(v));
        return (v[0] == '1'); // 仅显式 "1" 时开启
    }

    // 全局禁门控开关（诊断用）。PEARMOR_DISABLE_GATING=1 时所有代码页保持明文可执行，
    // 不重加密、不置 NOACCESS，用于隔离"门控/VEH/C++ 展开交互"与"镜像重建(重定位/导入/解密)"
    // 两类问题。默认关（正常门控）。
    static bool GatingDisabled() {
        char v[8] = {0};
        GetEnvironmentVariableA("PEARMOR_DISABLE_GATING", v, sizeof(v));
        return (v[0] == '1');
    }

    // 主入口：加载 + 修复 + 门控代码页 + 注册 VEH + 启动监控
    // 返回 true 时 outEntryRva 为原始入口 RVA
    //   innerKey : 由 seed 经 KDF 派生的内层密钥，用于逐页解密代码
    //   isCode   : 外层密钥解密后的块索引（每页是否代码页），长度 isCodeLen
    bool Load(const unsigned char* payload, size_t payloadLen,
              const unsigned char* innerKey,        // 32 字节，由 seed 经 KDF 派生
              const unsigned char* isCode, uint32_t isCodeLen, // 外层密钥解密后的块索引
              uint64_t& outEntryRva,
              const unsigned char* seed32 = nullptr) // P3.5：密钥轮换用种子
    {
        if (!payload || payloadLen == 0) return false;
        DebugLog("[loader] ckpt: Load 进入 payloadLen=%llu", (unsigned long long)payloadLen);
        cipherData = payload;
        pageSize   = PEARMOR_PAGE_SIZE;
        pageCount  = (uint32_t)(payloadLen / pageSize);
        if (pageCount == 0) return false;
        if (seed32) memcpy(seed, seed32, 32); // 保存种子供 RotateKey 使用

        // 内层密钥解密代码页；IV 母版 = innerKey 前 16 字节（与 packer 一致）
        cipher.reset(new AesPageCipher(innerKey, innerKey));
        if (!cipher->ok) { DebugLog("[loader] AesPageCipher 初始化失败"); return false; }

        pages.resize(pageCount);

        // ---- 解析头，获取基址 / 镜像大小 / 节信息 ----
        // 先整镜像解密到临时缓冲区以便读头（避免破坏 payload 密文）
        std::vector<unsigned char> tmp(payloadLen);
        for (uint32_t i = 0; i < pageCount; i++) {
            if (!cipher->decryptPage(payload + i * pageSize, i, tmp.data() + i * pageSize, pageSize)) {
                DebugLog("[loader] 解密临时页 i=%u 失败", i);
                return false;
            }
        }

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(tmp.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { DebugLog("[loader] DOS 签名校验失败"); return false; }
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(tmp.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { DebugLog("[loader] NT 签名校验失败"); return false; }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) { DebugLog("[loader] 非 PE32+ (Magic 校验失败)"); return false; }

        const IMAGE_OPTIONAL_HEADER64& opt = nt->OptionalHeader;
        uint64_t preferredBase = opt.ImageBase;
        DWORD    sizeOfImage   = opt.SizeOfImage;

        // 标记代码页：以“外层密钥解密出的块索引”为准（P2.5 分层）。
        // 该索引由 packer 依据节特征计算并用 outerKey 加密，Stub 解密后传入，
        // 因此没有外层密钥就无法确定哪些页需要门控 —— 双密钥缺一不可。
        for (uint32_t i = 0; i < pageCount; i++) {
            pages[i].isCode = (i < isCodeLen) ? (isCode[i] != 0) : false;
        }

        // ---- 分配最终物理布局（P3.2）+ 修复用工作区 ----
        // 关键：工作区(work) 与最终物理位置(pageBase) 必须落到【同一组虚拟地址】，
        //       这样重定位按 work 算出的 delta 才与最终运行地址一致。否则非连续模式
        //       下跨页指针会被修正到已释放的临时缓冲地址，跳 OEP 必崩。
        //   非连续：代码页各自独立区域，数据页一块连续区域；work 复用这些区域。
        //   连续回退：整镜像一块连续区域，work 直接复用它（delta=0，重定位天然对）。
        pageBase.resize(pageCount, nullptr);
        nonContig = false;
        void* workBase = nullptr;

        {
            bool ok = true;
            // 1) 先尝试非连续：代码页分散分配，数据页统计数量
            uint32_t dataPages = 0;
            for (uint32_t i = 0; i < pageCount; i++) if (!pages[i].isCode) dataPages++;
            if (dataPages == 0) dataPages = 1;     // 头页通常算数据页，兜底

            for (uint32_t i = 0; i < pageCount && ok; i++) {
                if (!pages[i].isCode) continue;     // 代码页才分散
                PVOID rgn = nullptr; SIZE_T rsz = pageSize;
                NTSTATUS st = Sys::AllocateVirtualMemory(GetCurrentProcess(), &rgn, 0,
                    &rsz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!NT_SUCCESS(st) || !rgn) { ok = false; break; }
                pageRegions.push_back(rgn);
                pageBase[i] = rgn;
            }
            // 非连续：数据块也分配（work 复用其地址；运行期数据块不释放）
            if (ok && NonContigEnabled()) {
                SIZE_T dsz = (SIZE_T)dataPages * pageSize;
                PVOID db = nullptr;
                NTSTATUS st = Sys::AllocateVirtualMemory(GetCurrentProcess(), &db, 0,
                    &dsz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!NT_SUCCESS(st) || !db) { ok = false; }
                else {
                    dataBlockBase = db; dataBlockPages = dataPages;
                    for (uint32_t i = 0; i < pageCount; i++)
                        if (!pages[i].isCode) { pageBase[i] = db; db = (unsigned char*)db + pageSize; }
                    workBase = pageBase[0];          // 数据页基址当作整镜像工作区基址
                    nonContig = true;
                }
            }
            // 2) 回退：释放零散区域，统一连续分配（work 复用 imageBase）
            if (!nonContig) {
                for (void* r : pageRegions) { SIZE_T z = 0; Sys::FreeVirtualMemory(GetCurrentProcess(), &r, &z); }
                pageRegions.clear();
                PVOID base = nullptr; SIZE_T sz = sizeOfImage;
                NTSTATUS st = Sys::AllocateVirtualMemory(GetCurrentProcess(), &base, 0,
                    &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!NT_SUCCESS(st) || !base) { DebugLog("[loader] 连续回退分配失败 st=0x%08X", (unsigned)st); return false; }
                imageBase = base;                    // 连续回退：仍用 imageBase
                for (uint32_t i = 0; i < pageCount; i++)
                    pageBase[i] = (unsigned char*)base + (size_t)i * pageSize; // 连续块内各页基址（物理连续）
                workBase = base;
            }
        }

        // ---- 解密到最终物理位置（work == pageBase，故无需再 memcpy） ----
        for (uint32_t i = 0; i < pageCount; i++) {
            if (!cipher->decryptPage(payload + i * pageSize, i,
                    reinterpret_cast<unsigned char*>(pageBase[i]), pageSize)) {
                DebugLog("[loader] 解密工作区页 i=%u 失败", i);
                return false;
            }
        }

        bool relocated = (reinterpret_cast<uint64_t>(workBase) != preferredBase);
        DebugLog("[loader] ckpt: 准备 ApplyRelocations (workBase=%p preferredBase=0x%llX relocated=%d)",
                 workBase, (unsigned long long)preferredBase, (int)relocated);
        if (relocated && !ManualPeLoader::ApplyRelocations(workBase, preferredBase, opt)) { DebugLog("[loader] 应用重定位失败"); return false; }
        DebugLog("[loader] ckpt: ApplyRelocations 完成, 准备 FixImports");
        if (!ManualPeLoader::FixImports(workBase, opt)) { DebugLog("[loader] 修复导入表失败"); return false; }
        DebugLog("[loader] ckpt: FixImports 完成");
        ManualPeLoader::FixDelayImports(workBase, opt);
        if (opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
            ManualPeLoader::RunTlsCallbacks(workBase, opt);

        // ---- 注册异常展开表（RUNTIME_FUNCTION / .pdata）----
        // 实测结论（CI 36）：注册 RtlAddFunctionTable 反而导致「C++ 异常展开死循环」，
        // 最终以 0xC0000005 终止——因为手动映射镜像的 .pdata 不完整（本样例仅 2 条
        // RUNTIME_FUNCTION，见下方诊断），展开器读到无效 UnwindData 后反复重抛无法收敛。
        // 根因：payload 被手动映射后，其 .pdata 与运行时基址的对应、以及 .xdata 完整性，
        // 在当前架构下未被正确建立。这也意味着「真实 C++ 目标」的异常展开支持尚未就绪，
        // 需后续单独立项（正确搬运并注册 .pdata/.xdata，且要覆盖编译期生成的全部条目）。
        // 当前 CI 验证目标是「加载+按需解密+OEP 执行」，payload 为纯 Win32 无 C++ 异常需求，
        // 故此处【保持跳过 RtlAddFunctionTable】，避免引入展开死循环。
        DebugLog("[loader] ckpt: 跳过 RtlAddFunctionTable 注册（避免展开死循环 0xC0000005，见 CI 36）");

        imageSize = sizeOfImage;

        // 数据页/代码页均已落到最终物理位置（work == pageBase，无需 memcpy）。
        // 非连续模式下数据块已在上方分配（dataBlockBase），连续模式下整块即 imageBase。
        DebugLog("[loader] ckpt: 页已就位(无 memcpy, work==pageBase), 准备注册展开表");
        // 注意：RtlInsertInvertedFunctionTable 是未文档化的 ntdll 内部函数，签名随
        // Windows 版本变化；对手动映射的镜像调用可能破坏进程内 LdrpInvertedFunctionTable
        // 导致崩溃，且对“正常跑到 OEP 写文件”的 MVP 验证毫无必要。故默认关闭，
        // 仅在显式设置 PEARMOR_ENABLE_IFT=1 时尝试，且用 SEH 兜底避免带崩进程。
        {
            void* tableBase = (nonContig && !pageRegions.empty()) ? pageRegions[0] : imageBase;
            if (tableBase) {
                char en[8] = {0};
                GetEnvironmentVariableA("PEARMOR_ENABLE_IFT", en, sizeof(en));
                if (en[0] == '1') {
                    NtApiTable ntApis; resolveNtApis(ntApis);
                    if (ntApis.RtlInsertInvertedFunctionTable) {
                        DebugLog("[loader] ckpt: 尝试 RtlInsertInvertedFunctionTable");
                        int r = CallRtlInsertInvertedFunctionTable(
                            ntApis.RtlInsertInvertedFunctionTable,
                            reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(tableBase) & ~(uintptr_t)0xFFFF),
                            sizeOfImage);
                        DebugLog("[loader] ckpt: RtlInsertInvertedFunctionTable %s",
                                 r == 0 ? "OK" : (r == 1 ? "触发异常(已吞掉)" : "未解析到"));
                    } else {
                        DebugLog("[loader] ckpt: RtlInsertInvertedFunctionTable 未解析到");
                    }
                } else {
                    DebugLog("[loader] ckpt: 跳过 RtlInsertInvertedFunctionTable (默认关闭)");
                }
            }
        }

        // P2.4：覆写内存 PE 头（此时数据页仍为 READWRITE，可安全写入），
        //        对抗 Scylla/ImpRec 自动脱壳。头信息在修复阶段已读取完毕，覆写无副作用。
        //        非连续模式下 PE 头位于数据块内（数据页不执行，更隐蔽）。
        if (dataBlockBase) {
            DebugLog("[loader] ckpt: 覆写内存 PE 头 (CorruptHeader)");
            ManualPeLoader::CorruptHeader(dataBlockBase);
        }

        // ---- 门控：代码页重新加密 + NOACCESS；数据页保留明文 ----
        // 关键修正（CI 25 复盘）：入口页【绝不】门控（保持 EXECUTE_READ），否则"跳 OEP
        // 即触发缺页→VEH 恢复→C++ 展开上下文错乱"会把可捕获异常变成不可捕获 AV。
        // 入口页本就是最先执行的代码，门控它无保护收益，徒增 fragility。
        const uint32_t entryPage = (uint32_t)(opt.AddressOfEntryPoint / pageSize);
        gatingEnabled = !GatingDisabled();
        DebugLog("[loader] ckpt: 进入门控循环 pages=%u entryPage=%u gatingEnabled=%d",
                 pageCount, entryPage, (int)gatingEnabled);
        for (uint32_t i = 0; i < pageCount; i++) {
            if (i == entryPage) {
                // 入口页：必须可执行，绝不置 NOACCESS/非执行
                DWORD old = 0; SIZE_T sz = pageSize; PVOID p = pageBase[i];
                Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_EXECUTE_READ, &old);
                pages[i].decrypted = true;
                pages[i].baseCrc = fnv1a32(reinterpret_cast<const unsigned char*>(pageBase[i]), pageSize);
                DebugLog("[loader] ckpt: 入口页 i=%u 保持 EXECUTE_READ(不门控)", i);
                continue;
            }
            if (!gatingEnabled) {
                // 诊断模式：所有页保持明文，代码页可执行、数据页可读写
                DWORD old = 0; SIZE_T sz = pageSize; PVOID p = pageBase[i];
                if (pages[i].isCode) {
                    Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_EXECUTE_READ, &old);
                    pages[i].baseCrc = fnv1a32(reinterpret_cast<const unsigned char*>(pageBase[i]), pageSize);
                } else {
                    Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_READWRITE, &old);
                }
                pages[i].decrypted = true;
                continue;
            }
            if (pages[i].isCode) {
                DebugLog("[loader] ckpt: 门控代码页 i=%u", i);
                // 修复（重定位/导入）已完成，先记录运行期基准 CRC，再重新加密。
                // 这样后续“解密即校验”比对的是修复后的真实代码，而非打包期
                // 原始镜像（否则重定位差异会误触发自毁）。
                pages[i].baseCrc = fnv1a32(
                    reinterpret_cast<const unsigned char*>(pageBase[i]),
                    pageSize);
                if (!reencryptPageLocked(i)) { DebugLog("[loader] 重加密代码页 i=%u 失败", i); return false; }
                DebugLog("[loader] ckpt: 代码页 i=%u 已重加密+NOACCESS", i);
            } else {
                DWORD old = 0;
                SIZE_T sz = pageSize;
                PVOID p = pageBase[i];
                Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_READWRITE, &old);
                pages[i].decrypted = true;
            }
        }

        // ---- 注册 VEH（按需解密，最高优先级） ----
        DebugLog("[loader] ckpt: 注册 VEH 前");
        g_instance = this;
        vehHandle = AddVectoredExceptionHandler(1, &PagedLoader::VehHandler);

        // ---- 反 Dump 监控初始化 ----
        dumpMon.Init();

        // ---- 启动监控线程（重加密 + 钩子扫描 + 自校验） ----
        DebugLog("[loader] ckpt: 启动监控线程前");
        stopMonitor = false;
        monitorThread = CreateThread(nullptr, 0, &PagedLoader::MonitorThreadProc,
                                     this, 0, nullptr);
        DebugLog("[loader] ckpt: 监控线程已启动 hwnd=%p", (void*)monitorThread);

        outEntryRva = opt.AddressOfEntryPoint;
        DebugLog("[loader] Load 成功: pages=%u nonContig=%d (kNonContig=%d) entryRva=0x%llX",
                 pageCount, (int)nonContig, (int)NonContigEnabled(), (unsigned long long)outEntryRva);
        return true;
    }

    // 跳 OEP（入口页保持 EXECUTE_READ 直接执行；其它代码页首次执行时由 VEH 按需解密）
    int CallEntry(uint64_t entryRva)
    {
        if (pageBase.empty() || !pageBase[0]) return -1;
        pendingRva = entryRva;
        g_oepRc    = 0;
        const uint32_t ep = (uint32_t)(entryRva / pageSize);
        DebugLog("[stub] 直接跳 OEP entryRva=0x%llX 入口页 i=%u 已解密=%d 门控使能=%d",
                 (unsigned long long)entryRva, ep,
                 (int)(ep < pages.size() ? pages[ep].decrypted : -1), (int)gatingEnabled);
        // 直接跳 OEP（去掉 VehCf::RunObfuscated 的 __debugbreak 0xCC 演示混淆）：
        // 入口页保持 EXECUTE_READ，跳入即正常执行，不再依赖 VEH 缺页恢复（避免展开上下文错乱）。
        // 其它代码页仍在首次执行时触发 VEH 按需解密。
        OepThunk();
        return g_oepRc;
    }

    // P3.2：把 RVA 解析为当前物理地址（兼容非连续布局）。
    //       代码页与数据页可能落在不同区域，统一经此函数定位。
    void* SafeRvaToVa(uint64_t rva) const
    {
        uint32_t i = (uint32_t)(rva / pageSize);
        if (i >= pageCount || !pageBase[i]) return nullptr;
        return reinterpret_cast<unsigned char*>(pageBase[i]) + (rva % pageSize);
    }

    // P3.3：供看门狗调用 —— 校验当前已解密代码页 CRC。返回 false 表示被补丁。
    bool VerifyDecryptedIntegrity()
    {
        std::lock_guard<std::mutex> lk(mtx);
        for (uint32_t i = 0; i < pageCount; i++) {
            if (pages[i].isCode && pages[i].decrypted) {
                unsigned char* dst = reinterpret_cast<unsigned char*>(pageBase[i]);
                if (!Integrity::VerifyPage(dst, pages[i].baseCrc)) return false;
            }
        }
        return true;
    }

    // 真正的 OEP 调用点（由 CallEntry 直接调用，入口页已是 EXECUTE_READ）。
    // 用 ExitProcess 收尾：main 内自身也会 ExitProcess；此处兜底确保无论 OEP 是否
    // 正常返回都走统一退出路径，避免栈帧错乱（OepThunk 由普通 call 进入，非 VEH Rip 重定向）。
    static int OepExceptFilter(EXCEPTION_POINTERS* ep)
    {
        auto* rec = ep->ExceptionRecord;
        void* addr = rec->ExceptionAddress;
        char mod[256] = {0};
        HMODULE hMod = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(addr), &hMod) && hMod)
            GetModuleFileNameA(hMod, mod, sizeof(mod));
        DebugLog("[oep] 捕获到异常 code=0x%08X addr=%p module=%s",
                 (unsigned)rec->ExceptionCode, addr, mod);
        return EXCEPTION_EXECUTE_HANDLER;
    }
    static void OepThunk()
    {
        if (!g_instance) return;
        void* va = g_instance->SafeRvaToVa(g_instance->pendingRva);
        DebugLog("[oep] OepThunk 进入, 入口 VA=%p (若后续无 [oep] 日志即崩 => 崩在 payload 执行期)", va);
        auto fn = reinterpret_cast<int(*)()>(va);
        if (fn) {
            __try {
                g_oepRc = fn();
            } __except (OepExceptFilter(GetExceptionInformation())) {
                DebugLog("[oep] OEP 执行期间抛异常，已就地捕获（rc=-2）");
                g_oepRc = -2;
            }
        } else {
            DebugLog("[oep] SafeRvaToVa 返回空, 入口解析失败");
        }
        DebugLog("[oep] OEP 返回路径(正常不应到达, main 内已 ExitProcess)");
        ExitProcess(g_oepRc);
    }

    void Release()
    {
        stopMonitor = true;
        if (monitorThread) {
            WaitForSingleObject(monitorThread, INFINITE);
            CloseHandle(monitorThread);
            monitorThread = nullptr;
        }
        if (vehHandle) { RemoveVectoredExceptionHandler(vehHandle); vehHandle = nullptr; }
        // P3.2：释放所有独立区域（代码页）与数据块
        for (void* r : pageRegions) { SIZE_T z = 0; Sys::FreeVirtualMemory(GetCurrentProcess(), &r, &z); }
        pageRegions.clear();
        if (dataBlockBase) {
            SIZE_T z = 0;
            Sys::FreeVirtualMemory(GetCurrentProcess(), &dataBlockBase, &z);
            dataBlockBase = nullptr;
        }
        if (imageBase) {    // 连续回退模式下使用
            SIZE_T sz = 0;
            Sys::FreeVirtualMemory(GetCurrentProcess(), &imageBase, &sz);
            imageBase = nullptr;
        }
        pageBase.clear();
        g_instance = nullptr;
    }

    void SelfDestructNow()
    {
        stopMonitor = true;
        // P3.2：擦除所有独立代码页区域 + 数据块（均为敏感明文载体）
        for (void* r : pageRegions) {
            SIZE_T z = 0;
            pearmor::SelfDestruct(r, pageSize);
        }
        if (dataBlockBase) {
            SIZE_T z = 0; (void)z;
            pearmor::SelfDestruct(dataBlockBase, dataBlockPages * pageSize);
        }
        // 连续回退模式下擦除整块
        if (imageBase) {
            SIZE_T z = 0; (void)z;
            pearmor::SelfDestruct(imageBase, imageSize);
        }
    }

    // P3.5：密钥轮换 —— 从种子加“时间盐”重派生 activeKey，更新 cipher。
    // 已解密的代码页保持原样（仍可由旧 cipher 重加密），仅影响后续按需解密；
    // 这样休眠/快照抓到的密钥只对应某一时间窗，无法还原全程明文。
    // 轮换后立刻把临时 key 缓冲清零，敏感密钥不长期驻留堆。
    bool RotateKey()
    {
        unsigned char salt[8];
        uint64_t t = nowMs();
        memcpy(salt, &t, 8);
        unsigned char newKey[32];
        pearmor::derive_rotated_key(seed, salt, newKey);   // KDF：seed + 时间盐
        // 持锁完成「派生 + 替换 cipher」，避免监控/看门狗线程在轮换瞬间看到空 cipher
        {
            std::lock_guard<std::mutex> lk(mtx);
            if (!cipher) { memset(newKey, 0, 32); return false; }
            cipher.reset(new AesPageCipher(newKey, newKey));
            if (!cipher->ok) { memset(newKey, 0, 32); return false; }
        }
        memset(newKey, 0, 32);     // 敏感密钥立即清零
        return true;
    }

private:
    std::unique_ptr<AesPageCipher> cipher;
    const unsigned char* cipherData = nullptr;
    void*   imageBase = nullptr;        // 连续回退模式下的整镜像基址
    size_t  imageSize = 0;
    uint32_t pageCount = 0;
    uint32_t pageSize  = PEARMOR_PAGE_SIZE;

    // P3.2：非连续布局。pageBase[i] = 第 i 页的物理基址；代码页各自独立区域。
    std::vector<void*> pageBase;
    std::vector<void*> pageRegions;     // 所有独立代码页区域（释放用）
    void*   dataBlockBase = nullptr;    // 数据页集中块
    uint32_t dataBlockPages = 0;        // 数据块页数
    bool    nonContig = false;          // 是否实际启用非连续
    bool    gatingEnabled = true;       // 门控总开关（PEARMOR_DISABLE_GATING=1 时置 false）

    std::vector<PageState> pages;
    void*   vehHandle = nullptr;
    HANDLE  monitorThread = nullptr;
    std::atomic<bool> stopMonitor{false};
    std::mutex mtx;
    AntiDump::Monitor dumpMon;

    // P3.5：密钥轮换所需（种子）。派生出的活跃密钥不长期驻留。
    unsigned char seed[32] = {0};

    uint64_t pendingRva = 0;       // 待执行 OEP 的 RVA（CallEntry 设置，OepThunk 读取）
    static int g_oepRc;            // OEP 返回值（经 VEH 控制流混淆路径传递）

    static PagedLoader* g_instance;

    static uint64_t nowMs()
    {
        static LARGE_INTEGER freq = {0};
        if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
        LARGE_INTEGER c; QueryPerformanceCounter(&c);
        return (uint64_t)(c.QuadPart * 1000 / freq.QuadPart);
    }

    // 解密第 i 页（已持有锁）：解密 -> CRC 校验 -> 置可执行 -> 更新状态
    bool decryptPageLocked(uint32_t i)
    {
        unsigned char* dst = reinterpret_cast<unsigned char*>(pageBase[i]);
        if (!cipher->decryptPage(cipherData + i * pageSize, i, dst, pageSize))
            return false;
        if (!Integrity::VerifyPage(dst, pages[i].baseCrc))
            return false; // 被篡改（与运行期修复后基准不符）
        PVOID p = dst; SIZE_T sz = pageSize; ULONG old = 0;
        Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_EXECUTE_READ, &old);
        pages[i].decrypted = true;
        pages[i].lastUsed  = nowMs();
        return true;
    }

    // 重新加密第 i 页（已持有锁）：先在原地加密（页仍可读写），再置 NOACCESS
    // 注意：绝不能先置 NOACCESS 再读页 —— 那会立刻 0xC0000005（读 NOACCESS 页）。
    bool reencryptPageLocked(uint32_t i)
    {
        unsigned char* dst = reinterpret_cast<unsigned char*>(pageBase[i]);
        DebugLog("[loader] ckpt: reencrypt i=%u 加密写回前", i);
        if (!cipher->encryptPage(dst, i, dst, pageSize))
            return false;
        DebugLog("[loader] ckpt: reencrypt i=%u 置NOACCESS前", i);
        PVOID p = dst; SIZE_T sz = pageSize; ULONG old = 0;
        Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_NOACCESS, &old);
        pages[i].decrypted = false; // 标记加密态，避免 VEH/其它线程读到半成品
        DebugLog("[loader] ckpt: reencrypt i=%u 完成", i);
        return true;
    }

    static LONG CALLBACK VehHandler(EXCEPTION_POINTERS* ep)
    {
        auto* rec = ep->ExceptionRecord;
        // 诊断钩子：C++ 异常(0xE06D7363)在展开前于 VEH 层截获并记录抛点模块，
        // 便于 CI 定位（无需依赖 .pdata 展开）。不吞异常，继续搜索让进程以该退出码终止。
        if (rec->ExceptionCode == 0xE06D7363) {
            // 诊断钩子：C++ 异常在展开前于 VEH 层截获。用 RtlVirtualUnwind 正经走栈
            // 定位【真实抛点】，不依赖 payload 注册 .pdata（CI 36 教训：不完整 pdata 会展开死循环）。
            // 不吞异常，返回 CONTINUE_SEARCH 让进程以该退出码终止。
            LogRealThrowSite(ep);
            DebugLog("[veh] C++ 异常未捕获 code=0xE06D7363 (真实抛点见上方走栈，落在 payload 内即 payload 自身)");
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
            return EXCEPTION_CONTINUE_SEARCH;
        // ExceptionInformation[1] = 引发访问的虚拟地址
        uintptr_t fault = static_cast<uintptr_t>(rec->ExceptionInformation[1]);
        PagedLoader* self = g_instance;
        if (!self || self->pageBase.empty()) return EXCEPTION_CONTINUE_SEARCH;
        // P3.2：非连续布局下各页落在不同区域，逐页判定 fault 落在哪一页
        uint32_t i = self->pageCount;
        for (uint32_t k = 0; k < self->pageCount; k++) {
            uintptr_t pb = reinterpret_cast<uintptr_t>(self->pageBase[k]);
            if (pb && fault >= pb && fault < pb + self->pageSize) { i = k; break; }
        }
        if (i >= self->pageCount) {
            // 兜底：连续回退模式下用 imageBase 线性判定
            uintptr_t base = reinterpret_cast<uintptr_t>(self->imageBase);
            if (!base || fault < base || fault >= base + self->imageSize)
                return EXCEPTION_CONTINUE_SEARCH;
            i = (uint32_t)((fault - base) / self->pageSize);
            if (i >= self->pageCount) return EXCEPTION_CONTINUE_SEARCH;
        }

        std::lock_guard<std::mutex> lk(self->mtx);
        if (!self->pages[i].isCode) return EXCEPTION_CONTINUE_SEARCH;

        if (!self->pages[i].decrypted) {
            if (!self->decryptPageLocked(i)) {
                // 解密/校验失败 → 自毁（进程将终止，无需释放锁）
                self->SelfDestructNow();
                return EXCEPTION_EXECUTE_HANDLER;
            }
            // CI 铁证：非入口代码页在门控后被实际访问 → VEH 缺页解密被真实触发
            DebugLog("[loader] veh: 按需解密代码页 i=%u fault=0x%llX",
                     i, (unsigned long long)fault);
            return EXCEPTION_CONTINUE_EXECUTION;
        } else {
            // 已是明文但可能被监控线程临时置了 NOACCESS（重加密竞态）→ 恢复可执行
            PVOID p = reinterpret_cast<unsigned char*>(self->pageBase[i]);
            SIZE_T sz = self->pageSize; ULONG old = 0;
            Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_EXECUTE_READ, &old);
            self->pages[i].lastUsed = nowMs();
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    static DWORD WINAPI MonitorThreadProc(LPVOID lp)
    {
        reinterpret_cast<PagedLoader*>(lp)->MonitorLoop();
        return 0;
    }

    void MonitorLoop()
    {
        const uint64_t IDLE_MS = 600; // 空闲超过 600ms 的代码页重新加密
        while (!stopMonitor.load(std::memory_order_relaxed)) {
            Sleep(200);

            // ---- 1) 空闲代码页重加密 ----
            {
                std::lock_guard<std::mutex> lk(mtx);
                uint64_t now = nowMs();
                for (uint32_t i = 0; i < pageCount; i++) {
                    if (gatingEnabled && pages[i].isCode && pages[i].decrypted &&
                        (now - pages[i].lastUsed > IDLE_MS)) {
                        reencryptPageLocked(i);
                    }
                }
            }

            // ---- 2) ntdll 钩子扫描（防 Dump） ----
            if (dumpMon.Scan()) { SelfDestructNow(); return; }

            // ---- 3) 已解密代码页 CRC 重校验（防补丁） ----
            {
                std::lock_guard<std::mutex> lk(mtx);
                for (uint32_t i = 0; i < pageCount; i++) {
                    if (pages[i].isCode && pages[i].decrypted) {
                        unsigned char* dst = reinterpret_cast<unsigned char*>(pageBase[i]);
                        if (!Integrity::VerifyPage(dst, pages[i].baseCrc)) { SelfDestructNow(); return; }
                    }
                }
            }
        }
    }
};

// 静态成员定义（VEH 用）
inline PagedLoader* PagedLoader::g_instance = nullptr;
inline int          PagedLoader::g_oepRc = 0;

} // namespace pearmor
