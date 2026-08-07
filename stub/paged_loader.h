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

// 独立 SEH 辅助：安全读取任意地址的内存（越界/不可读返回 0 字节）。
// 参数全 POD、内部才用 __try（满足 C2712 约束）。用于诊断时 dump 崩溃点指令字节、
// 读栈顶返回地址——这些地址可能是垃圾/不可读，直接解引用会二次 AV。
static SIZE_T SafeReadBytes(uintptr_t addr, void* dst, SIZE_T want)
{
    if (!addr || !dst || !want) return 0;
    __try {
        memcpy(dst, reinterpret_cast<const void*>(addr), want);
        return want;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// 辅助：反查地址所属模块（模块名 + 模块内偏移）。诊断日志用，定位崩溃地址归属。
// 不用 __try：GetModuleHandleExW(FROM_ADDRESS) 本身不因地址非法而崩溃。
static void DescribeAddr(uintptr_t addr, char* modOut, size_t modOutSz, uintptr_t* modBaseOut)
{
    if (modOut && modOutSz) modOut[0] = 0;
    if (modBaseOut) *modBaseOut = 0;
    HMODULE hMod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(addr), &hMod) && hMod) {
        if (modBaseOut) *modBaseOut = reinterpret_cast<uintptr_t>(hMod);
        if (modOut && modOutSz)
            GetModuleFileNameA(hMod, modOut, (DWORD)modOutSz);
    }
}

// 正经走栈：从异常现场（通常停在 KERNELBASE!RaiseException 内）用 RtlVirtualUnwind 逐帧展开，
// 打印完整调用链。CI 67 前 payload 无 .pdata，展开到第一个 payload 帧即停（定位 throw 站点）；
// CI 66 起 .pdata 已注册（RtlAddFunctionTable count=1102），RtlVirtualUnwind 能展开 payload
// 帧 → 改为【继续展开全部 payload 帧】，打出 throw → 调用者 → ... → OepThunk 的完整链路，
// 用于判断 throw 来自 Hanbot 哪个业务函数（环境失败 vs 加壳破坏）。
// 无 .pdata 的帧（如纯汇编）用叶子近似（ret=*Rsp; Rsp+=8）继续，最多 16 帧。
// pb/pe 为 payload 基址区间（由 VehHandler 计算传入）。
static void LogRealThrowSite(EXCEPTION_POINTERS* ep, uintptr_t pb, uintptr_t pe)
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

    DebugLog("[veh] === 正经走栈定位真实 throw 站点（从 RaiseException 现场向上展开）===");
    if (pb) DebugLog("[veh] payload 基址区间=[%p, %p) （#N 落在此区间即 payload 自身）", (void*)pb, (void*)pe);
    for (int d = 0; d < 16; d++) {
        ULONG64 imgBase = 0;
        PRUNTIME_FUNCTION fe = pLookup(ctx.Rip, &imgBase, nullptr);
        if (!fe) {
            // 无展开数据帧（纯汇编/无栈帧）：叶子近似 ret=*Rsp; Rsp+=8 继续
            uintptr_t ret = 0;
            SafeReadBytes(static_cast<uintptr_t>(ctx.Rsp), &ret, sizeof(ret));
            DebugLog("[veh]   #%d rip=%p 无 .pdata（叶子近似）", d, (void*)ctx.Rip);
            if (!ret || ret == (uintptr_t)-1) break;
            ctx.Rip = ret;
            ctx.Rsp += 8;
            continue;
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
                 d, (void*)ctx.Rip, mod, inPayload ? "  <<< payload" : "");
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
              const unsigned char* seed32 = nullptr, // P3.5：密钥轮换用种子
              const wchar_t* origFileName = nullptr) // CI 74 模块伪装：原版 exe 文件名
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
            // CI 78：固定基址模式（PEARMOR_FIXED_BASE=1）——跳过非连续布局，直接连续分配
            // 到 preferredBase（链接基址，如 0x140000000）。若成功则 relocated=false →
            // 不应用重定位 → 镜像内容与原版完全一致 → 对抗目标程序「自校验自身镜像」。
            // 必须放最前：固定基址与「非连续分散布局」互斥。
            bool fixedBase = false;
            {
                char fb[8] = {0};
                fixedBase = GetEnvironmentVariableA("PEARMOR_FIXED_BASE", fb, sizeof(fb)) && (fb[0] == '1');
            }
            if (fixedBase) {
                PVOID base = reinterpret_cast<PVOID>(preferredBase);
                SIZE_T sz = sizeOfImage;
                NTSTATUS st = Sys::AllocateVirtualMemory(GetCurrentProcess(), &base, 0,
                    &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (NT_SUCCESS(st) && base) {
                    DebugLog("[loader] 固定基址模式: 分配到 preferredBase=%p sz=0x%zX",
                             base, sizeOfImage);
                    imageBase = base;
                    for (uint32_t i = 0; i < pageCount; i++)
                        pageBase[i] = (unsigned char*)base + (size_t)i * pageSize;
                    workBase = base;
                    nonContig = false;
                } else {
                    DebugLog("[loader] 固定基址分配失败 st=0x%08X（可能被 stub/系统占用），回退随机分配",
                             (unsigned)st);
                    fixedBase = false;
                }
            }
            // 1) 先尝试非连续：代码页分散分配，数据页统计数量
            uint32_t dataPages = 0;
            for (uint32_t i = 0; i < pageCount; i++) if (!pages[i].isCode) dataPages++;
            if (dataPages == 0) dataPages = 1;     // 头页通常算数据页，兜底

            for (uint32_t i = 0; i < pageCount && ok && !fixedBase; i++) {
                if (!pages[i].isCode) continue;     // 代码页才分散
                PVOID rgn = nullptr; SIZE_T rsz = pageSize;
                NTSTATUS st = Sys::AllocateVirtualMemory(GetCurrentProcess(), &rgn, 0,
                    &rsz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!NT_SUCCESS(st) || !rgn) { ok = false; break; }
                pageRegions.push_back(rgn);
                pageBase[i] = rgn;
            }
            // 非连续：数据块也分配（work 复用其地址；运行期数据块不释放）
            if (ok && !fixedBase && NonContigEnabled()) {
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
            if (!fixedBase && !nonContig) {
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

        // CI 87：解密后立即全量 CRC 校验（页面此刻 = 打包明文，重定位/导入还没改）。
        // 索引块布局：isCode(pageCount) + 每页明文 CRC(pageCount*4)（packer 写入）。
        // 若解密正确 → 全部页 CRC 匹配 → 加载内容=打包明文，问题在运行期；
        // 若有页不匹配 → 解密/加载缺陷实锤（哪些页、差多少）。
        {
            const uint32_t* crcTable = nullptr;
            if (isCodeLen >= (uint32_t)((size_t)pageCount + (size_t)pageCount * 4))
                crcTable = reinterpret_cast<const uint32_t*>(isCode + pageCount);
            int bad = 0;
            for (uint32_t i = 0; i < pageCount && crcTable; i++) {
                uint32_t actual = fnv1a32(reinterpret_cast<const unsigned char*>(pageBase[i]), pageSize);
                if (actual != crcTable[i]) {
                    if (bad < 8)
                        DebugLog("[loader] 解密CRC不一致 i=%u 期望=0x%08X 实际=0x%08X isCode=%d",
                                 i, crcTable[i], actual, (int)pages[i].isCode);
                    bad++;
                }
            }
            if (crcTable) DebugLog("[loader] 解密CRC校验: 共 %u 页, 不一致 %d 页", pageCount, bad);
            else DebugLog("[loader] 解密CRC校验: 旧产物无 CRC 表，跳过");
        }

        bool relocated = (reinterpret_cast<uint64_t>(workBase) != preferredBase);
        DebugLog("[loader] ckpt: 准备 ApplyRelocations (workBase=%p preferredBase=0x%llX relocated=%d)",
                 workBase, (unsigned long long)preferredBase, (int)relocated);
        if (relocated && !ManualPeLoader::ApplyRelocations(workBase, preferredBase, opt)) { DebugLog("[loader] 应用重定位失败"); return false; }
        DebugLog("[loader] ckpt: ApplyRelocations 完成, 准备 FixImports");
        // CI 74 模块伪装：FixImports 前初始化——payload 基址 = workBase（重定位基准。
        // 业务用 GetModuleHandle(NULL)+RVA 访问自身数据时，期望的“模块基址”就是
        // 重定位 delta 的基准 workBase；连续模式下 workBase=镜像线性基址，
        // 非连续模式下 workBase=数据块基址（重定位按它算 delta，必须一致）。
        // 原文件名来自 overlay（packer 写入）。这样 FixImports 替换 GetModule* 时伪装即生效。
        pearmor::ModuleFake::Init(reinterpret_cast<uintptr_t>(workBase), origFileName);
        if (!ManualPeLoader::FixImports(workBase, opt)) { DebugLog("[loader] 修复导入表失败"); return false; }
        DebugLog("[loader] ckpt: FixImports 完成");
        // CI 94/95 尝试过 LDR 模块表注册（让业务遍历模块表能看到 payload），但：
        //  - 手工置零 entry → ntdll 遍历读未初始化字段崩（ntdll 0xB832）
        //  - 复制 stub entry → 业务仍检测到异常（假 AV 回归），且组合 9 吞假 AV 也死
        // 结论：LDR 注册弊大于利，撤掉。业务检测点不是（或不仅是）LDR 模块表；
        // 主防线改为 CI 96 的「默认吞假 AV」——业务主动 RaiseException(0xC0000005)
        // 模拟取指 AV 自杀时 VEH 吞掉继续执行（CI 93 组合 9 存活 20s 实证业务能跑）。
        DebugLog("[loader] ckpt: FixImports 完成, 准备 FixDelayImports");
        // CI 54 定位：崩在 FixImports 完成 与「跳过 RtlAddFunctionTable」之间，
        // 即 FixDelayImports 或 TLS 回调执行 —— 分步打日志锁定。
        ManualPeLoader::FixDelayImports(workBase, opt);
        DebugLog("[loader] ckpt: FixDelayImports 完成");
        if (opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
            // 系统 loader 顺序：先初始化 TLS 数据（分配+拷模板+挂 TEB 槽），再执行回调。
            // CI 64：此前只执行回调、未初始化数据 → Hanbot 的 __declspec(thread) 槽指针是野值
            // → 崩在 payload 偏移 0x14E3A 的写指令（mov [rbx+rax*8+0x10],rsi 写野指针）。
            // CI 76：诊断开关 PEARMOR_DISABLE_TLS=1 跳过 TLS 初始化+回调，隔离
            // "TLS 数据挂载错误 → 业务读 __declspec(thread) 垃圾 → 主动 RaiseException" 假设。
            char tlsOff[8] = {0};
            bool skipTls = GetEnvironmentVariableA("PEARMOR_DISABLE_TLS", tlsOff, sizeof(tlsOff)) &&
                           (tlsOff[0] == '1');
            if (skipTls) {
                DebugLog("[loader] PEARMOR_DISABLE_TLS=1，跳过 TLS 初始化与回调");
            } else {
                DebugLog("[loader] ckpt: payload 含 TLS 目录, 初始化 TLS 数据");
                ManualPeLoader::InitTlsData(workBase, opt);
                DebugLog("[loader] ckpt: 执行 TLS 回调");
                ManualPeLoader::RunTlsCallbacks(workBase, opt);
                DebugLog("[loader] ckpt: TLS 回调执行完成");
            }
        }

        // ---- 注册异常展开表（RUNTIME_FUNCTION / .pdata）----
        // CI 36 教训：test_payload 的 .pdata 仅 2 条且不完整，注册导致展开死循环 0xC0000005。
        // CI 65 实测：真实 C++ 目标（Hanbot）已能跑到自己代码深处并抛 C++ 异常（0xE06D7363），
        // 但异常无法展开 → 未捕获崩溃——必须正确搬运并注册 payload 的 .pdata 才能展开。
        // RegisterPdata 已含逐条防御校验（Begin/End/UnwindData RVA 越界则整体不注册），
        // 覆盖链接器生成的全部条目，对真实目标的完整 .pdata 安全。
        ManualPeLoader::RegisterPdata(workBase, opt);

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

        // P2.4：覆写内存 PE 头（此时数据页仍为 READWRITE，可安全写入），对抗 Scylla/ImpRec。
        // 非连续模式：PE 头在数据块内（dataBlockBase）；连续回退模式：在 imageBase 开头。
        // CI 71 曾默认关闭（担心真实 GUI 目标读自身 PE 头/资源），但 CI 98 源码审查
        // （client/ 08-07）确认：业务 GetModuleHandle 只用 GetModuleHandleW("user32.dll")
        // （非 NULL），资源用 FindResourceW(g_hInst=stub 基址)——覆写 payload 头不影响
        // 业务（stub 头未动）。CI 99 起【默认开启】抗脱壳，PEARMOR_NO_CORRUPT_HEADER=1 关闭。
        void* headerTarget = dataBlockBase ? dataBlockBase : imageBase;
        char doCorrupt[8] = {0};
        bool noCorrupt =
            GetEnvironmentVariableA("PEARMOR_NO_CORRUPT_HEADER", doCorrupt, sizeof(doCorrupt)) &&
            doCorrupt[0] == '1';
        if (headerTarget && !noCorrupt) {
            DebugLog("[loader] ckpt: 覆写内存 PE 头 (CorruptHeader) target=%p", headerTarget);
            ManualPeLoader::CorruptHeader(headerTarget);
        } else if (headerTarget) {
            DebugLog("[loader] ckpt: 跳过 CorruptHeader（PEARMOR_NO_CORRUPT_HEADER=1）");
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
                NTSTATUS st = 0;   // STATUS_SUCCESS == 0（避免依赖 ntstatus.h）
                if (pages[i].isCode) {
                    st = Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_EXECUTE_READ, &old);
                    pages[i].baseCrc = fnv1a32(reinterpret_cast<const unsigned char*>(pageBase[i]), pageSize);
                } else {
                    st = Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_READWRITE, &old);
                }
                // CI 73：必须检查保护设置结果——若失败（如页未提交/对齐问题），页面保持
                // 初始 PAGE_READWRITE → 执行代码页时取指 AV（组合 2 页 57 症状），且无日志极难定位。
                if (!NT_SUCCESS(st)) {
                    DebugLog("[loader] all_off 保护设置失败 i=%u isCode=%d base=%p st=0x%08X",
                             i, (int)pages[i].isCode, pageBase[i], (unsigned)st);
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

    // 解密第 i 页（已持有锁）：先置可写再解密，最后置回可执行并更新状态。
    // 【CI 40 根因实证】门控页是 PAGE_NOACCESS，若先写明文会触发二次 AV →
    // VEH 处理器重入 → 同线程对 std::mutex 递归加锁 → _Mtx_lock 抛 std::system_error
    // (0xE06D7363 未捕获)。顺序铁律：NOACCESS -> READWRITE -> 写明文 -> 校验 -> EXECUTE_READ。
    // 【CI 41 根因实证】解密源必须是「页面内存的重加密密文」，而非打包期 cipherData：
    // 页面里存的是「重定位/导入修复后明文」的密文（门控时 encryptPage 原地写回），
    // baseCrc 也是按修复后明文建立（integrity.h 注释：修复会改变代码页内容）。
    // 用 cipherData 解出的是未修复原始明文 → CRC 不符 → 误判被篡改 → 自毁 0xC0000001。
    // 另：CBC 不能原地解密（ivc 需读当前块密文，但已被 out 覆盖），先拷密文到栈缓冲再解回。
    bool decryptPageLocked(uint32_t i)
    {
        unsigned char* dst = reinterpret_cast<unsigned char*>(pageBase[i]);
        PVOID p = dst; SIZE_T sz = pageSize; ULONG old = 0;
        if (!NT_SUCCESS(Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_READWRITE, &old)))
            return false;
        unsigned char tmp[PEARMOR_PAGE_SIZE];   // 栈缓冲：拷页面密文，防 CBC 原地解密破坏链
        memcpy(tmp, dst, pageSize);
        if (!cipher->decryptPage(tmp, i, dst, pageSize))
            return false;
        if (!Integrity::VerifyPage(dst, pages[i].baseCrc))
            return false; // 被篡改（与运行期修复后基准不符）
        if (!NT_SUCCESS(Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_EXECUTE_READ, &old)))
            return false;
        pages[i].decrypted = true;
        pages[i].lastUsed  = nowMs();
        return true;
    }

    // 重新加密第 i 页（已持有锁）：先置可写再原地加密（运行时页是 EXECUTE_READ，
    // 直接写同样会二次 AV），再置 NOACCESS。
    // 注意：绝不能先置 NOACCESS 再读页 —— 那会立刻 0xC0000005（读 NOACCESS 页）。
    bool reencryptPageLocked(uint32_t i)
    {
        unsigned char* dst = reinterpret_cast<unsigned char*>(pageBase[i]);
        DebugLog("[loader] ckpt: reencrypt i=%u 加密写回前", i);
        PVOID p = dst; SIZE_T sz = pageSize; ULONG old = 0;
        // 顺序铁律：EXECUTE_READ(或 NOACCESS) -> READWRITE -> 写密文 -> NOACCESS
        if (!NT_SUCCESS(Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_READWRITE, &old)))
            return false;
        if (!cipher->encryptPage(dst, i, dst, pageSize))
            return false;
        DebugLog("[loader] ckpt: reencrypt i=%u 置NOACCESS前", i);
        if (!NT_SUCCESS(Sys::ProtectVirtualMemory(GetCurrentProcess(), &p, &sz, PAGE_NOACCESS, &old)))
            return false;
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
            uintptr_t pb = 0, pe = 0;
            if (g_instance && !g_instance->pageBase.empty()) {
                pb = (uintptr_t)g_instance->pageBase[0];
                pe = pb + (size_t)g_instance->pageBase.size() * g_instance->pageSize;
            }
            // CI 68/69 异常类型诊断——MSVC type_info 布局（vcruntime 实测）：
            //   +0x00 vfptr，+0x08 _m_data【内嵌】结构，_m_data 内 +0x08(=tiPtr+0x10) = _m_pName。
            // 注意：_m_data 是内嵌不是指针（CI 69 按指针读 +0x08 得到垃圾 0x0006E6A0...）。
            // 名字指针 = *(void**)(tiPtr + 0x10)。若读不到名字，打印 namePtr 值便于判断
            // （0=字段空；链接时 VA=重定位没覆盖 RTTI 区；有效指针但不可读=页保护问题）。
            if (rec->NumberParameters >= 3) {
                uintptr_t tiPtr = static_cast<uintptr_t>(rec->ExceptionInformation[2]);
                uintptr_t namePtr = 0;
                if (tiPtr) SafeReadBytes(tiPtr + 0x10, &namePtr, sizeof(namePtr));
                char nm[160] = {0};
                if (namePtr) {
                    for (int k = 0; k < 159; k++) {
                        char c = 0;
                        if (!SafeReadBytes(namePtr + k, &c, 1) || !c) break;
                        nm[k] = c;
                    }
                }
                // CI 75：完整 dump 异常参数——MSVC _CxxThrowException 传 3 个参数：
                //   [0]=throwInfo（__CxxFrameHandler 用的捕获类型表）、[1]=pExceptionObject、
                //   [2]=type_info*。若 [0]==0 且 [2] 不可读 → 业务主动 RaiseException 模拟，
                //   非标准 C++ throw。另 dump type_info 头部 16 字节（MSVC 布局：
                //   +0x00 vfptr, +0x08 _m_data 内嵌, +0x10 _m_pName）。
                // CI 77：实测 n=4（标准 throw 是 3）→ 补 dump [3]（可能含异常对象/检测源信息）。
                DebugLog("[veh] 异常参数: n=%u [0]=%p [1]=%p [2]=%p [3]=%p",
                         (unsigned)rec->NumberParameters,
                         reinterpret_cast<void*>(rec->ExceptionInformation[0]),
                         reinterpret_cast<void*>(rec->ExceptionInformation[1]),
                         reinterpret_cast<void*>(rec->ExceptionInformation[2]),
                         reinterpret_cast<void*>(rec->NumberParameters > 3 ? rec->ExceptionInformation[3] : 0));
                {
                    unsigned char tih[32] = {0};
                    if (tiPtr) SafeReadBytes(tiPtr, tih, sizeof(tih));
                    DebugLog("[veh] type_info 头部: %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X | namePtr=%p name=%s",
                             tih[0], tih[1], tih[2], tih[3], tih[4], tih[5], tih[6], tih[7],
                             tih[8], tih[9], tih[10], tih[11], tih[12], tih[13], tih[14], tih[15],
                             reinterpret_cast<void*>(namePtr),
                             nm[0] ? nm : "(读不到)");
                }
                // CI 79：dump 异常对象 [1]——MSVC 标准 _CxxThrowException 布局 [1]=pExceptionObject。
                // std::exception 派生对象前 8 字节 = vfptr，+8 起可能是 what() 消息指针（MSVC 布局：
                // exception 无虚表时 +0 是 vfptr 指向 _std_exception，消息在派生类）。先 dump 头部
                // 32 字节 + 尝试按 char*/wchar_t* 读第 2 个 QWORD（常见 what() 消息指针位置）。
                {
                    uintptr_t objPtr = static_cast<uintptr_t>(rec->ExceptionInformation[1]);
                    if (objPtr) {
                        unsigned char objh[32] = {0};
                        if (SafeReadBytes(objPtr, objh, sizeof(objh))) {
                            DebugLog("[veh] 异常对象[1] 头部: %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
                                     objh[0], objh[1], objh[2], objh[3], objh[4], objh[5], objh[6], objh[7],
                                     objh[8], objh[9], objh[10], objh[11], objh[12], objh[13], objh[14], objh[15],
                                     objh[16], objh[17], objh[18], objh[19], objh[20], objh[21], objh[22], objh[23]);
                            // CI 81：通过 vfptr 反查真正的 RTTI 类名——MSVC /GR 下虚表指针
                            // 前 8 字节（vftable[-1]）即 type_info*，type_info+0x10 = 名字指针。
                            // 异常参数[2] 的 type_info 是混淆/自定义协议（namePtr=0），
                            // 而异常对象自身的 vftable 指向真实虚表（payload .rdata，门控
                            // 只门控代码页故可读），反查能拿到标准 .?AVxxx@@ 类名。
                            uintptr_t vfptr = 0;
                            if (SafeReadBytes(objPtr, &vfptr, sizeof(vfptr)) && vfptr) {
                                uintptr_t rttiTi = 0;
                                if (SafeReadBytes(vfptr - sizeof(uintptr_t), &rttiTi, sizeof(rttiTi)) && rttiTi) {
                                    uintptr_t rttiName = 0;
                                    if (SafeReadBytes(rttiTi + 0x10, &rttiName, sizeof(rttiName)) && rttiName) {
                                        char rn[160] = {0};
                                        bool okName = true;
                                        for (int k = 0; k < 159; k++) {
                                            char c = 0;
                                            if (!SafeReadBytes(rttiName + k, &c, 1)) { okName = false; break; }
                                            if (!c) break;
                                            if (c < 0x20 || c > 0x7E) { okName = false; break; }
                                            rn[k] = c;
                                        }
                                        if (okName && rn[0])
                                            DebugLog("[veh] 异常类名(vftable[-1]): %s (type_info=%p vftable=%p)",
                                                     rn, reinterpret_cast<void*>(rttiTi),
                                                     reinterpret_cast<void*>(vfptr));
                                    }
                                }
                            }
                            // CI 81：dump 异常对象 40 字节（QWORD 视角）——std::system_error
                            // 布局 +0x00 vftable、+0x08 error_code::_Val、+0x10 category*、
                            // +0x18 起 std::string；可据此读错误码值定位"resource unavailable try again"
                            // 对应的系统错误。对象在堆上（payload 可执行页外），SafeReadBytes 兜底。
                            uint64_t objq[5] = {0};
                            if (SafeReadBytes(objPtr, objq, sizeof(objq))) {
                                DebugLog("[veh] 异常对象[1] qword: [0]=%016llX [1]=%016llX [2]=%016llX [3]=%016llX [4]=%016llX",
                                         (unsigned long long)objq[0], (unsigned long long)objq[1],
                                         (unsigned long long)objq[2], (unsigned long long)objq[3],
                                         (unsigned long long)objq[4]);
                            }
                            // 尝试读 what() 消息：对象+8 处指针若指向可读 ASCII 则打印
                            uintptr_t msgPtr = 0;
                            if (SafeReadBytes(objPtr + 8, &msgPtr, sizeof(msgPtr)) && msgPtr &&
                                msgPtr > 0x10000 && msgPtr < 0x7FFFFFFFFFFF) {
                                char msgbuf[200] = {0};
                                bool printable = true;
                                for (int k = 0; k < 199; k++) {
                                    char c = 0;
                                    if (!SafeReadBytes(msgPtr + k, &c, 1)) { printable = false; break; }
                                    if (!c) break;
                                    if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') { printable = false; break; }
                                    msgbuf[k] = c;
                                }
                                if (printable && msgbuf[0])
                                    DebugLog("[veh] 异常对象 what(): %s", msgbuf);
                            }
                        }
                    }
                }
            }
            LogRealThrowSite(ep, pb, pe);
            DebugLog("[veh] C++ 异常未捕获 code=0xE06D7363 (真实抛点见上方走栈，落在 payload 内即 payload 自身)");
            // CI 77：吞异常实验——PEARMOR_SWALLOW_E06D7363=1 时返回 CONTINUE_EXECUTION
            // 而非 CONTINUE_SEARCH。若业务是「检测到异常环境→主动 RaiseException 自杀」，
            // 吞掉后业务可能继续运行（窗口照常出现）；若业务是循环检测则立即再抛。
            // 这是定位「业务为何判定自身异常」的关键实验，非默认行为。
            {
                char sw[8] = {0};
                bool swallow = GetEnvironmentVariableA("PEARMOR_SWALLOW_E06D7363", sw, sizeof(sw)) &&
                               (sw[0] == '1');
                if (swallow) {
                    DebugLog("[veh] PEARMOR_SWALLOW_E06D7363=1，吞掉该异常尝试继续执行");
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }
        // CI 66：.pdata 注册（count=1102）后异常能展开，但展开过程 fatal——
        // 0xC000041D STATUS_FATAL_USER_CALLBACK_EXCEPTION（用户回调/展开回调内致命异常）。
        // 展开器在无 AV 的情况下直接 fatal（VEH 无按需解密日志）→ 打 ExceptionAddress +
        // 走栈定位展开崩在哪一帧（哪一帧的 filter/handler/终止回调）。
        if (rec->ExceptionCode == 0xC000041D) {
            uintptr_t pb = 0, pe = 0;
            if (g_instance && !g_instance->pageBase.empty()) {
                pb = (uintptr_t)g_instance->pageBase[0];
                pe = pb + (size_t)g_instance->pageBase.size() * g_instance->pageSize;
            }
            uintptr_t rip = reinterpret_cast<uintptr_t>(rec->ExceptionAddress);
            char mod[256] = {0}; uintptr_t modBase = 0;
            DescribeAddr(rip, mod, sizeof(mod), &modBase);
            DebugLog("[veh] 展开期 fatal 0xC000041D: addr=%p (%s 偏移=0x%llX) payload区间=[%p,%p)",
                     rec->ExceptionAddress,
                     mod[0] ? mod : "?",
                     (unsigned long long)(modBase ? (rip - modBase) : 0),
                     reinterpret_cast<void*>(pb), reinterpret_cast<void*>(pe));
            LogRealThrowSite(ep, pb, pe);
            return EXCEPTION_CONTINUE_SEARCH;
        }
        if (rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
            return EXCEPTION_CONTINUE_SEARCH;
        // ExceptionInformation[1] = 引发访问的虚拟地址
        uintptr_t fault = static_cast<uintptr_t>(rec->ExceptionInformation[1]);
        PagedLoader* self = g_instance;
        if (!self || self->pageBase.empty()) return EXCEPTION_CONTINUE_SEARCH;
        // 重入保护（CI 40 教训）：本线程已在 VEH 处理器内（持锁期间又发生 AV/嵌套异常）时，
        // 若继续递归处理会对 std::mutex 同线程递归加锁 → MSVCP140 _Mtx_lock 抛
        // std::system_error(0xE06D7363) 未捕获。此处直接放行，让嵌套异常正常传播。
        static thread_local bool tl_inHandler = false;
        if (tl_inHandler) {
            // CI 59：VEH 处理器内嵌套异常 → 进程直接终止（无 crash.log）。记录嵌套 AV 现场。
            DebugLog("[veh] 重入保护触发: 嵌套异常 code=0x%08X addr=%p fault=0x%llX",
                     (unsigned)rec->ExceptionCode, rec->ExceptionAddress,
                     (unsigned long long)fault);
            return EXCEPTION_CONTINUE_SEARCH;
        }
        tl_inHandler = true;
        struct ResetTl { bool* p; ~ResetTl() { *p = false; } } tlReset{ &tl_inHandler };
        // P3.2：非连续布局下各页落在不同区域，逐页判定 fault 落在哪一页
        uint32_t i = self->pageCount;
        for (uint32_t k = 0; k < self->pageCount; k++) {
            uintptr_t pb = reinterpret_cast<uintptr_t>(self->pageBase[k]);
            if (pb && fault >= pb && fault < pb + self->pageSize) { i = k; break; }
        }
        if (i >= self->pageCount) {
            // 兜底：连续回退模式下用 imageBase 线性判定
            uintptr_t base = reinterpret_cast<uintptr_t>(self->imageBase);
            if (!base || fault < base || fault >= base + self->imageSize) {
                // CI 61：TopLevelHandler 可能被 Hanbot 覆盖（无 crash.log）——VEH 是第一机会，
                // 在此记录 Hanbot 自身代码的 AV（RIP=执行指令，fault=被访问的无效地址），
                // 即使末处理器失效也能定位崩点。
                // CI 62：addr==fault 是【取指 AV】——执行了不可执行内存。0x7FF8... 高地址
                // 疑系统模块/堆，但没打模块名判不了归属 → 补：模块反查 + RIP 指令 dump + 栈顶返回地址。
                uintptr_t rip = reinterpret_cast<uintptr_t>(rec->ExceptionAddress);
                char mod[256] = {0}; uintptr_t modBase = 0;
                DescribeAddr(rip, mod, sizeof(mod), &modBase);
                char modFault[256] = {0}; uintptr_t fBase = 0;
                DescribeAddr(fault, modFault, sizeof(modFault), &fBase);
                // RIP 处指令字节 dump（判断执行了 jmp/call/普通指令；不可读则全 0）
                unsigned char ib[16] = {0};
                SIZE_T nRead = SafeReadBytes(rip, ib, sizeof(ib));
                // CI 85：RIP 前 24 字节指令 dump（定位 rbx 来源：mov rbx,[全局] / lea rbx,[rsp+xx]）
                unsigned char pb24[24] = {0};
                SafeReadBytes(rip > 24 ? rip - 24 : 0, pb24, sizeof(pb24));
                // 栈顶返回地址（谁是调用者）
                uintptr_t rsp = ep->ContextRecord->Rsp;
                uintptr_t stackRet = 0, stackRet2 = 0;
                SafeReadBytes(rsp, &stackRet, sizeof(stackRet));
                SafeReadBytes(rsp + 8, &stackRet2, sizeof(stackRet2));
                char modRet[256] = {0}; uintptr_t retBase = 0;
                DescribeAddr(stackRet, modRet, sizeof(modRet), &retBase);
                // CI 64：新形态——addr 在 payload 镜像内（手动映射，模块表查不到故 "?"）、
                // fault 在外 → Hanbot 自身代码写野指针（RIP 字节 48 89 74 C3 10=mov [rbx+rax*8+0x10],rsi）。
                // 补关键寄存器（rax/rbx/rcx/rdx/rsi/rdi/rbp）便于追野指针来源。
                auto* ctx = ep->ContextRecord;
                // CI 73：取指 AV（fault=-1）时定位 RIP 所在页的 isCode/保护状态——
                // 若 isCode=1 但页不可执行 => all_off 分支保护设置失败；若 isCode=0 =>
                // 业务代码跳进了数据页（IAT/重定位错）。VirtualQuery 拿实际保护。
                {
                    uintptr_t rip2 = reinterpret_cast<uintptr_t>(rec->ExceptionAddress);
                    int pgIsCode = -1; DWORD pgProt = 0; uintptr_t pgBase2 = 0;
                    if (self && !self->pageBase.empty()) {
                        uintptr_t b0 = reinterpret_cast<uintptr_t>(self->pageBase[0]);
                        uintptr_t off = rip2 - b0;
                        if (rip2 >= b0 && off < (size_t)self->pageCount * self->pageSize) {
                            uint32_t pi = (uint32_t)(off / self->pageSize);
                            if (pi < self->pageCount) {
                                pgIsCode = self->pages[pi].isCode ? 1 : 0;
                                pgBase2 = reinterpret_cast<uintptr_t>(self->pageBase[pi]);
                                MEMORY_BASIC_INFORMATION mbi;
                                if (VirtualQuery(reinterpret_cast<LPCVOID>(rip2), &mbi, sizeof(mbi)))
                                    pgProt = mbi.Protect;
                            }
                        }
                    }
                    DebugLog("[veh] 取指AV页面诊断: RIP页 isCode=%d 页基址=%p 实际保护=0x%X (期望代码页=EXECUTE_READ 0x20)",
                             pgIsCode, reinterpret_cast<void*>(pgBase2), (unsigned)pgProt);
                }
                DebugLog("[veh] AV 不在镜像内: code=0x%08X addr=%p (%s%s 偏移=0x%llX) fault=%p (%s%s) RIP字节=%02X%02X%02X%02X%02X%02X%02X%02X | rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p rbp=%p rsp=%p 栈顶=%p (模块=%s) 次栈顶=%p",
                         (unsigned)rec->ExceptionCode, rec->ExceptionAddress,
                         mod[0] ? mod : "?", mod[0] ? "" : "",
                         (unsigned long long)(modBase ? (rip - modBase) : 0),
                         reinterpret_cast<void*>(fault),
                         modFault[0] ? modFault : "?", modFault[0] ? "" : "",
                         (unsigned long long)(fBase ? (fault - fBase) : 0),
                         ib[0], ib[1], ib[2], ib[3], ib[4], ib[5], ib[6], ib[7],
                         reinterpret_cast<void*>(ctx->Rax), reinterpret_cast<void*>(ctx->Rbx),
                         reinterpret_cast<void*>(ctx->Rcx), reinterpret_cast<void*>(ctx->Rdx),
                         reinterpret_cast<void*>(ctx->Rsi), reinterpret_cast<void*>(ctx->Rdi),
                         reinterpret_cast<void*>(ctx->Rbp), reinterpret_cast<void*>(rsp),
                         reinterpret_cast<void*>(stackRet),
                         modRet[0] ? modRet : "?",
                         reinterpret_cast<void*>(stackRet2));
                // CI 85：补崩溃线程 ID + RIP 前 24 字节指令（人工反汇编确认 rbx 来源——
                // 页 57 偏移 0x159/0x19A 的 mov eax,[rbx] / mov [rbx+rax*8+0x10],rsi，
                // rbx 野指针需定位它来自哪条指令的哪个全局/寄存器）。
                DebugLog("[veh] 崩溃线程 tid=%u RIP前指令=%02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
                         (unsigned)GetCurrentThreadId(),
                         pb24[0], pb24[1], pb24[2], pb24[3], pb24[4], pb24[5], pb24[6], pb24[7],
                         pb24[8], pb24[9], pb24[10], pb24[11], pb24[12], pb24[13], pb24[14], pb24[15],
                         pb24[16], pb24[17], pb24[18], pb24[19], pb24[20], pb24[21], pb24[22], pb24[23]);
                // CI 89：崩溃线程 TLS 槽检查——工作线程 TEB 里 payload TLS 槽应为
                // 非 null（CI 100 起每线程独立副本，主线程才是 g_payloadTlsData）；
                // null → 工作线程 TLS 未挂载实锤（业务 __declspec(thread) 变量地址
                // = null+偏移（this=0x20）→ 随机崩溃）。
                // 读取逻辑在 pe_loader.h 命名空间作用域（__try 不能进类成员函数 C2712）。
                if (g_payloadTlsIndex != 0xFFFFFFFFu) {
                    void* got = pearmor::PeekCurrentThreadTlsSlot();
                    DebugLog("[veh] 崩溃线程TLS: tid=%u index=%u 槽值=%p %s",
                             (unsigned)GetCurrentThreadId(), (unsigned)g_payloadTlsIndex,
                             got,
                             (got == g_payloadTlsData) ? "(主线程)" :
                             (got ? "(独立副本)" : "(槽为null=工作线程未挂TLS!)"));
                }
                // CI 93：fault=-1（取指地址为 -1）是异常中的异常——真实门控取指 AV 的 fault
                // = 页内地址（如 ...9159），fault=-1 只可能是【业务主动 RaiseException(0xC0000005,
                // 0, 2, {0, (ULONG_PTR)-1}) 模拟取指 AV 自杀】或 jmp/ret 到 -1。若 RIP 在镜像内
                // → 主动自杀嫌疑极高（与 CI 77 吞 0xE06D7363 是同类行为，只是换异常码）。
                // CI 93 实证：组合 9（吞掉）存活 20s、窗口正常 → 业务抛完假 AV 后无 ExitProcess，
                // 继续正常跑。CI 96 起【默认吞掉】作为正式防线（业务反加壳检测的最终兜底）；
                // PEARMOR_DISABLE_FAKEAV_SWALLOW=1 可关闭（诊断对照用）。
                // 安全性：jmp -1 的真实取指 AV 其 RIP 会变成 -1（镜像外）→ 不满足「RIP 在镜像内」
                // → 不吞；只有主动 RaiseException 且 RIP 停在镜像内才吞，误吞概率极低。
                {
                    uintptr_t rip3 = reinterpret_cast<uintptr_t>(rec->ExceptionAddress);
                    uintptr_t base3 = self ? reinterpret_cast<uintptr_t>(self->imageBase) : 0;
                    bool ripInImage = (base3 && rip3 >= base3 && rip3 < base3 + self->imageSize);
                    if (fault == (uintptr_t)-1 && ripInImage) {
                        char v3[8] = {0};
                        bool disable =
                            GetEnvironmentVariableA("PEARMOR_DISABLE_FAKEAV_SWALLOW", v3, sizeof(v3)) &&
                            v3[0] == '1';
                        if (!disable) {
                            DebugLog("[veh] 业务主动抛 AV(fault=-1) 模拟取指AV自杀，默认吞掉继续执行"
                                     "（PEARMOR_DISABLE_FAKEAV_SWALLOW=1 可关）");
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                        DebugLog("[veh] 疑似业务主动抛 AV(fault=-1, RIP 在镜像内)——"
                                 "真实门控取指 AV 的 fault 应为页内地址，此形态=主动 RaiseException 模拟");
                    }
                }
                return EXCEPTION_CONTINUE_SEARCH;
            }
            i = (uint32_t)((fault - base) / self->pageSize);
            if (i >= self->pageCount) return EXCEPTION_CONTINUE_SEARCH;
        }

        std::lock_guard<std::mutex> lk(self->mtx);
        if (!self->pages[i].isCode) return EXCEPTION_CONTINUE_SEARCH;

        if (!self->pages[i].decrypted) {
            if (!self->decryptPageLocked(i)) {
                // CI 59 诊断：解密失败静默自毁看不出原因 → 记录页号/CRC/保护状态
                DebugLog("[loader] veh: 解密失败 i=%u fault=0x%llX baseCrc=0x%08X decrypted=%d",
                         i, (unsigned long long)fault,
                         (unsigned)self->pages[i].baseCrc, (int)self->pages[i].decrypted);
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
