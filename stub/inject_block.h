// ============================================================================
// inject_block.h — P3.4 拦截第三方 DLL 注入 & 阻断调试器附加
//
// 手法：inline hook ntdll 的三个关键系统调用导出：
//   * NtMapViewOfSection  —— 拦截把 DLL 节区映射到「其它进程」实现远程注入；
//   * NtCreateThreadEx    —— 拦截在「其它进程」创建远程线程；
//   * NtOpenProcess       —— 拦截外部进程打开「本进程」句柄（便于内存读写/调试）。
//
// 仅提升门槛，无法彻底阻止（攻击者可在内核/驱动层绕过）。钩子本身可被拆除，
// 故提供 VerifyHooks() 供看门狗周期性校验：一旦被还原/篡改 -> 触发自毁。
//
// 所有判定均走原生上下文，handler 不依赖任何被钩函数，避免递归。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "syscall.h"   // 原生 syscall（绕过被钩导出）
#include "guard.h"     // 自毁
#include "obf.h"       // 字符串混淆（P2.2）

namespace pearmor {
namespace InjectBlock {

struct Hook {
    void*   addr = nullptr;                  // ntdll 导出函数入口
    unsigned char patched[14] = {0};         // 我们写入的跳转（14 字节）
    unsigned char orig[32] = {0};            // 原始指令（完整指令边界，≥14 字节）
    void*   trampoline = nullptr;            // 跳回原函数体的执行桩
    bool    active = false;
};

// 单条 x64 指令长度（含前缀+opcode+modrm+sib+disp+imm）；失败返回 0。
// CI 84：hook 前必须找到【完整指令边界】——syscall 包装头 16 字节 =
// mov r10,rcx(3)+mov eax,imm(5)+test [0x7FFE0308],1(8)，固定 14 字节 patch
// 会把 test 指令从中间切断 → trampoline 执行到残指令 → 解码错乱 AV。
static int OneInstLen(const unsigned char* p, int limit)
{
    int i = 0;
    // 前缀（66/67/64/65/F0/F2/F3/段覆盖 2E..3E/REX 40..4F，可重复）
    while (i < limit) {
        unsigned char b = p[i];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x64 || b == 0x65 || (b >= 0x2E && b <= 0x3E) || (b >= 0x40 && b <= 0x4F))
            { i++; continue; }
        break;
    }
    if (i >= limit) return 0;
    unsigned char op = p[i];
    int start = i;
    bool rexW = false;
    for (int k = 0; k < i; k++) if ((p[k] & 0xF8) == 0x48) rexW = true; // REX.W
    bool twoByte = (op == 0x0F);
    i++;
    if (twoByte) {
        if (i >= limit) return 0;
        op = p[i]; i++;
        // 两字节无 modrm：syscall/sysret/sysenter/sysexit/invd/wbinvd/ud2/emms/rdtsc 等
        if (op == 0x05 || op == 0x07 || op == 0x34 || op == 0x35 ||
            (op >= 0x08 && op <= 0x0F) || op == 0x31 || op == 0x32 || op == 0x77)
            return i - start;
        if (op >= 0x80 && op <= 0x8F)          // jcc rel32
            return i + 4 - start;
        // 两字节带 modrm + imm8：0F BA /C2 /C4 /C5 /C6 /A4 /AC
        if (op == 0xBA || op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6 ||
            op == 0xA4 || op == 0xAC) {
            if (i >= limit) return 0;
            unsigned char modrm = p[i];
            i++;
            unsigned mod = modrm >> 6;
            if (mod != 3) {
                unsigned rm = modrm & 7;
                if (rm == 4) { if (i >= limit) return 0; unsigned char sib = p[i]; i++;
                               if (mod == 0 && (sib & 7) == 5) i += 4; }
                else if (mod == 0 && rm == 5) i += 4;
                if (mod == 1) i += 1;
                else if (mod == 2) i += 4;
            }
            return i + 1 - start;
        }
        // 其余两字节：默认带 modrm（落入下方）
    } else {
        // ---- 单字节无 modrm / 特殊 ----
        if ((op >= 0x50 && op <= 0x5F) ||        // push/pop
            op == 0x90 || op == 0x9B || op == 0x98 || op == 0x99 || op == 0x9C ||
            op == 0x9D || op == 0x9E || op == 0x9F || op == 0xC3 || op == 0xC9 ||
            op == 0xCB || op == 0xCC || op == 0xCE || op == 0xCF ||
            op == 0xF8 || op == 0xF9 || op == 0xFA || op == 0xFB || op == 0xFC || op == 0xFD ||
            (op >= 0xAA && op <= 0xAF))         // stos/lods/scas/movs/cmps
            return i - start;
        if ((op >= 0x70 && op <= 0x7F) || op == 0xEB || op == 0xE3)  // jcc/jmp/jrcxz rel8
            return i + 1 - start;
        if (op == 0xE8 || op == 0xE9)            // call/jmp rel32
            return i + 4 - start;
        if (op == 0x9A || op == 0xEA)            // call/jmp far
            return i + 12 - start;
        if (op == 0xA8) return i + 2 - start;    // test al, imm8
        if (op == 0xA9) return i + 5 - start;    // test eax/rax, imm32
        if (op == 0xC2 || op == 0xCA) return i + 2 - start;  // ret imm16
        if (op == 0xC8) return i + 3 - start;    // enter imm16, imm8
        if (op == 0x68) return i + 4 - start;    // push imm32
        if (op == 0x6A) return i + 1 - start;    // push imm8
        if (op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA3)  // mov moffs
            return i + 8 - start;
        if (op >= 0xB8 && op <= 0xBF)            // mov r64, imm64（REX.W）/ mov r32, imm32
            return i + (rexW ? 8 : 4) - start;
        if (op == 0xB0 || op == 0xB1)            // mov al/cl, imm8
            return i + 1 - start;
        if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7)  // in/out imm8
            return i + 1 - start;
        // 带 modrm 的（含 imm 判断），落入下方
    }
    // ---- modrm 解析 ----
    if (i >= limit) return 0;
    unsigned char modrm = p[i];
    i++;
    unsigned mod = modrm >> 6;
    unsigned rm = modrm & 7;
    unsigned reg = (modrm >> 3) & 7;
    if (mod != 3) {
        if (rm == 4) {                           // SIB
            if (i >= limit) return 0;
            unsigned char sib = p[i]; i++;
            if (mod == 0 && (sib & 7) == 5) i += 4;   // disp32
        } else if (mod == 0 && rm == 5) {
            i += 4;                              // rip-rel disp32
        }
        if (mod == 1) i += 1;                    // disp8
        else if (mod == 2) i += 4;               // disp32
    }
    // ---- imm（按 opcode）----
    if (!twoByte) {
        switch (op) {
        case 0x80: case 0x82: case 0x83: case 0xC0: case 0xC1:
            return i + 1 - start;                // imm8
        case 0x81: case 0xC7:
            return i + 4 - start;                // imm32（64 位下符号扩展）
        case 0x69: return i + 4 - start;         // imul r,r/m,imm32
        case 0x6B: return i + 1 - start;         // imul r,r/m,imm8
        case 0xF6: case 0xF7:                    // /0=TEST 带 imm；其余无
            if (reg == 0) return i + (op == 0xF6 ? 1 : 4) - start;
            return i - start;
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
            return i - start;                    // 移位（无 imm；imm8 版本是 C0/C1）
        default:
            return i - start;
        }
    }
    return i - start;
}

// 从 p 开始逐条解码，返回累计到 >= limit 的【完整指令序列】长度。
// 失败返回 0。上限 24 字节防失控。
static int X64InstLen(const unsigned char* p, int limit)
{
    int total = 0;
    while (total < limit) {
        int one = OneInstLen(p + total, 16);   // 单条最多 16 字节（x64 最长 15+前缀，够）
        if (one <= 0) return 0;
        total += one;
        if (total > 24) return 0;              // 保护：找不到边界
    }
    return total;
}

static Hook g_hooks[3];
static DWORD g_selfPid = 0;

// 取某进程句柄对应的 PID（用原生 NtQueryInformationProcess，绕过 Win32 钩子）
// 注意：此函数会在 hook 决策路径（shim -> InjectShouldBlock）里被调用，
// 必须零依赖 kernel32/user32（GetCurrentProcess 等价伪句柄 (HANDLE)-1，直接比较）。
static DWORD PidOfHandle(HANDLE hProc)
{
    if (!hProc || hProc == (HANDLE)-1) return g_selfPid;
    ULONG pid = 0;
    // ProcessBasicInformation(0) 的 UniqueProcessId 在返回结构偏移 8
    struct { ULONG ExitStatus; ULONG_PTR Peb; ULONG_PTR UniqueProcessId; ULONG_PTR Inherited; } info;
    memset(&info, 0, sizeof(info));
    if (NT_SUCCESS(Sys::QueryInformationProcess(hProc, 0, &info, sizeof(info), nullptr)))
        pid = (DWORD)info.UniqueProcessId;
    return pid;
}

// 统一访问策略（C 决策函数，被 hook_shim.asm 的 shim 调用）。
//   which: 0=NtMapViewOfSection 1=NtCreateThreadEx 2=NtOpenProcess
//   arg:   0/1 -> ProcessHandle 句柄值；2 -> PCLIENT_ID 指针
// 返回 1 = 拦截，0 = 放行。
// 实现定义在 stub.cpp（CI 83：extern "C" inline 只生成弱 COMDAT 符号，
// 汇编 obj 引用解析失败 LNK2019，必须移到 .cpp 产生强符号）。
extern "C" int InjectShouldBlock(int which, void* arg);

// ---- hook_shim.asm 导出的 shim 与 trampoline 槽 ----
extern "C" void InjectShim0(void);   // NtMapViewOfSection
extern "C" void InjectShim1(void);   // NtCreateThreadEx
extern "C" void InjectShim2(void);   // NtOpenProcess
extern "C" void* gTramp0;
extern "C" void* gTramp1;
extern "C" void* gTramp2;

// 构造 14 字节绝对跳转到 handler（FF 25 00 00 00 00 + 8 字节绝对地址）
static void BuildJmp(void* from, void* to, unsigned char out[14])
{
    out[0] = 0xFF; out[1] = 0x25; out[2] = 0x00; out[3] = 0x00; out[4] = 0x00; out[5] = 0x00;
    memcpy(out + 6, &to, 8);
}

// 安装单个钩子：patch 跳到对应 shim（shim 内调 InjectShouldBlock 决策，
// 放行时尾跳 trampoline），trampoline 地址写入全局槽供 shim 使用。
// CI 84：hook 前先解码【完整指令边界】len（≥14）——syscall 包装头 16 字节含
// test [0x7FFE0308],1(8B) 指令，固定 14 字节 patch 会从中间截断 → trampoline
// 复制 len 字节完整指令、跳回 addr+len（addr+14..len 段被 patch 覆盖无碍，
// trampoline 不经过该段）。解码失败则放弃 hook 该函数（返回 false）。
static bool PatchOne(Hook& h, const char* name, void* shimAddr, void** trampSlot)
{
    h.addr = peExportAddress(getLoadedModuleBase(L"ntdll.dll"), name);
    if (!h.addr) return false;
    // 完整指令边界：至少 14 字节（patch 覆盖量），最多 20 字节内找边界
    int len = 0;
    for (int trial = 14; trial <= 20; trial++) {
        len = X64InstLen(reinterpret_cast<const unsigned char*>(h.addr), trial);
        if (len >= 14 && len <= 20) break;
        len = 0;
    }
    if (len < 14) {
        DebugLog("[loader] inject hook 解码指令边界失败: %s", name);
        return false;
    }
    memcpy(h.orig, h.addr, len);
    BuildJmp(h.addr, shimAddr, h.patched);

    // 分配 trampoline（len 字节完整原指令 + 跳回原函数体 patch 之后 addr+len）
    void* mem = nullptr; SIZE_T sz = 0x1000;
    if (!NT_SUCCESS(Sys::AllocateVirtualMemory(GetCurrentProcess(), &mem, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
        return false;
    unsigned char* p = reinterpret_cast<unsigned char*>(mem);
    memcpy(p, h.orig, len);                    // 完整原指令（≥14 字节）
    // jmp [rip+0] : FF 25 00 00 00 00 + 8 字节地址（回跳到 addr+len）
    p[len] = 0xFF; p[len+1] = 0x25;
    p[len+2] = 0x00; p[len+3] = 0x00; p[len+4] = 0x00; p[len+5] = 0x00;
    void* resume = (unsigned char*)h.addr + len;
    memcpy(p + len + 6, &resume, 8);
    h.trampoline = mem;
    *trampSlot = mem;   // 通知 shim 尾跳转目标（CI 83）

    // 写跳转（先把页面改可写）
    PVOID base = h.addr; SIZE_T wsz = 14; ULONG old = 0;
    Sys::ProtectVirtualMemory(GetCurrentProcess(), &base, &wsz, PAGE_EXECUTE_READWRITE, &old);
    memcpy(h.addr, h.patched, 14);
    if (old != PAGE_EXECUTE_READWRITE)
        Sys::ProtectVirtualMemory(GetCurrentProcess(), &base, &wsz, old, &old);
    h.active = true;
    return true;
}

// 安装全部钩子。需在 Sys::Init() 之后调用。
// CI 85：NtMapViewOfSection hook 默认【跳过】——组合 1(全开)崩 vs 组合 5(注入关)
// 存活的唯一差异就是 inject hook，而 MapView 被 LoadLibrary/COM 激活(CoCreateInstance
// 延迟加载 DLL)高频调用，hook 出错影响面最大（组合 2 出现 combase.dll 内 AV）。
// 防注入核心能力 = NtCreateThreadEx(拦远程线程) + NtOpenProcess(拦进程打开)，
// 这两个保留；需要 MapView 拦截时设 PEARMOR_ENABLE_MAPVIEW_HOOK=1 恢复。
inline bool Install()
{
    g_selfPid = GetCurrentProcessId();
    char mv[8] = {0};
    bool mapView = GetEnvironmentVariableA("PEARMOR_ENABLE_MAPVIEW_HOOK", mv, sizeof(mv)) && mv[0] == '1';
    const char* names[3] = {
        OBF_STR("NtMapViewOfSection"),
        OBF_STR("NtCreateThreadEx"),
        OBF_STR("NtOpenProcess")
    };
    // shim 地址（.asm 符号）与 trampoline 槽一一对应
    void* shims[3] = { (void*)&InjectShim0, (void*)&InjectShim1, (void*)&InjectShim2 };
    void** slots[3] = { &gTramp0, &gTramp1, &gTramp2 };   // gTrampN 是 void* 变量，取址即 void**
    bool all = true;
    for (int i = 0; i < 3; i++) {
        if (i == 0 && !mapView) continue;   // CI 85：MapView 默认跳过
        if (!PatchOne(g_hooks[i], names[i], shims[i], slots[i])) all = false;
    }
    DebugLog("[stub] P3.4 注入拦截：MapView=%s CreateThreadEx=%d OpenProcess=%d",
             mapView ? "on" : "off(CI 85 默认跳过)", (int)g_hooks[1].active, (int)g_hooks[2].active);
    return all;
}

// 看门狗调用：校验钩子首部仍为我们写入的跳转。被还原/篡改返回 false。
inline bool VerifyHooks()
{
    for (int i = 0; i < 3; i++) {
        if (!g_hooks[i].active) continue;
        if (memcmp(g_hooks[i].addr, g_hooks[i].patched, 14) != 0)
            return false;
    }
    return true;
}

} // namespace InjectBlock
} // namespace pearmor
