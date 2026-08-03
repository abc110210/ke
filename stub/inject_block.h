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
static DWORD PidOfHandle(HANDLE hProc)
{
    if (!hProc || hProc == GetCurrentProcess()) return g_selfPid;
    ULONG pid = 0;
    // ProcessBasicInformation(0) 的 UniqueProcessId 在返回结构偏移 8
    struct { ULONG ExitStatus; ULONG_PTR Peb; ULONG_PTR UniqueProcessId; ULONG_PTR Inherited; } info;
    memset(&info, 0, sizeof(info));
    if (NT_SUCCESS(Sys::QueryInformationProcess(hProc, 0, &info, sizeof(info), nullptr)))
        pid = (DWORD)info.UniqueProcessId;
    return pid;
}

// 统一访问策略：返回 true 表示放行，false 表示拦截。
static bool AllowCall(ULONG ssn, void* a1, void* a2, void* a3, void* a4)
{
    const Sys::Ssn& s = Sys::ssn();
    if (ssn == s.NtOpenProcess) {
        // a4 = CLIENT_ID*（含 UniqueProcess）。外部指定本进程 PID 且非自身伪句柄 -> 拦截。
        if (a4 && g_selfPid) {
            DWORD target = (DWORD)(uintptr_t)*(const ULONG_PTR*)a4; // ClientId.UniqueProcess
            if (target == g_selfPid) return false;   // 阻断外部打开本进程
        }
        return true;
    }
    if (ssn == s.NtCreateThreadEx) {
        // a4 = ProcessHandle（远程线程目标进程）。目标为其它进程 -> 拦截。
        HANDLE hProc = (HANDLE)a4;
        if (hProc && hProc != GetCurrentProcess() && PidOfHandle(hProc) != g_selfPid)
            return false;
        return true;
    }
    if (ssn == s.NtMapViewOfSection) {
        // a2 = ProcessHandle（映射目标进程）。映射到其它进程 -> 拦截（远程 DLL 注入）。
        HANDLE hProc = (HANDLE)a2;
        if (hProc && hProc != GetCurrentProcess() && PidOfHandle(hProc) != g_selfPid)
            return false;
        return true;
    }
    return true;
}

// 全局 handler：RCX=SSN，其余参数按微软 x64 约定落在 rdx/r8/r9/[rsp+0x28..]
extern "C" NTSTATUS NTAPI InjectHandler(ULONG ssn, void* a1, void* a2,
                                        void* a3, void* a4, void* a5, void* a6)
{
    (void)a1; (void)a5; (void)a6;
    if (!AllowCall(ssn, a1, a2, a3, a4))
        return (NTSTATUS)0xC0000022L; // STATUS_ACCESS_DENIED
    // 放行：按 SSN 匹配对应 trampoline 执行原函数体
    const Sys::Ssn& s = Sys::ssn();
    ULONG targets[3] = { s.NtMapViewOfSection, s.NtCreateThreadEx, s.NtOpenProcess };
    for (int i = 0; i < 3; i++) {
        if (g_hooks[i].active && targets[i] == ssn) {
            using Fn = NTSTATUS(NTAPI*)(ULONG, void*, void*, void*, void*, void*, void*);
            return reinterpret_cast<Fn>(g_hooks[i].trampoline)(ssn, a1, a2, a3, a4, a5, a6);
        }
    }
    return (NTSTATUS)0xC0000002L; // STATUS_NOT_IMPLEMENTED（兜底，正常不会到这）
}

// 构造 14 字节绝对跳转到 handler（FF 25 00 00 00 00 + 8 字节绝对地址）
static void BuildJmp(void* from, void* to, unsigned char out[14])
{
    out[0] = 0xFF; out[1] = 0x25; out[2] = 0x00; out[3] = 0x00; out[4] = 0x00; out[5] = 0x00;
    memcpy(out + 6, &to, 8);
}

static bool PatchOne(Hook& h, const char* name, void* handler)
{
    h.addr = peExportAddress(getLoadedModuleBase(L"ntdll.dll"), name);
    if (!h.addr) return false;
    memcpy(h.orig, h.addr, 14);
    BuildJmp(h.addr, handler, h.patched);

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
    bool all = true;
    for (int i = 0; i < 3; i++)
        if (!PatchOne(g_hooks[i], names[i], (void*)&InjectHandler)) all = false;
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
