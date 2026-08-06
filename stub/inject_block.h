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
    unsigned char orig[14] = {0};            // 原始指令（恢复/校验用）
    void*   trampoline = nullptr;            // 跳回原函数体的执行桩
    bool    active = false;
};

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
// 注意：必须【可重入、无副作用、不调用任何经过 hook 的 API】——
// shim 是在 ntdll 入口被跳转进来的，任何线程都可能随时进入。
extern "C" __declspec(noinline) inline int InjectShouldBlock(int which, void* arg)
{
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
static bool PatchOne(Hook& h, const char* name, void* shimAddr, void** trampSlot)
{
    h.addr = peExportAddress(getLoadedModuleBase(L"ntdll.dll"), name);
    if (!h.addr) return false;
    memcpy(h.orig, h.addr, 14);
    BuildJmp(h.addr, shimAddr, h.patched);

    // 分配 trampoline（原指令 + 跳回原函数体 patch 之后）
    void* mem = nullptr; SIZE_T sz = 0x1000;
    if (!NT_SUCCESS(Sys::AllocateVirtualMemory(GetCurrentProcess(), &mem, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
        return false;
    unsigned char* p = reinterpret_cast<unsigned char*>(mem);
    memcpy(p, h.orig, 14);                 // 原指令
    // jmp [rip+0] : FF 25 00 00 00 00 + 8 字节地址（回跳到 addr+14）
    p[14] = 0xFF; p[15] = 0x25; p[16] = 0x00; p[17] = 0x00; p[18] = 0x00; p[19] = 0x00;
    void* resume = (unsigned char*)h.addr + 14;
    memcpy(p + 20, &resume, 8);
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
inline bool Install()
{
    g_selfPid = GetCurrentProcessId();
    const char* names[3] = {
        OBF_STR("NtMapViewOfSection"),
        OBF_STR("NtCreateThreadEx"),
        OBF_STR("NtOpenProcess")
    };
    // shim 地址（.asm 符号）与 trampoline 槽一一对应
    void* shims[3] = { (void*)&InjectShim0, (void*)&InjectShim1, (void*)&InjectShim2 };
    void** slots[3] = { &gTramp0, &gTramp1, &gTramp2 };   // gTrampN 是 void* 变量，取址即 void**
    bool all = true;
    for (int i = 0; i < 3; i++)
        if (!PatchOne(g_hooks[i], names[i], shims[i], slots[i])) all = false;
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
