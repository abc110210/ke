// ============================================================================
// anti_debug.h — 多层反调试检测（本地纯判定，无网络）
// 覆盖：调试端口 / 调试标志 / 调试对象 / 硬件断点(DR) / 时间陷阱
// 检测手段优先走原生 NtQueryInformationProcess（绕过 Win32 钩子）。
// 返回 true 表示发现调试器。
// ============================================================================
#pragma once
#include <windows.h>
#include <intrin.h>

#include "syscall.h"
#include "guard.h"

namespace pearmor {
namespace AntiDebug {

// 1) 调试端口：ProcessDebugPort (0x7) 非零即被调试
inline bool CheckDebugPort()
{
    ULONG port = 0;
    NTSTATUS st = Sys::QueryInformationProcess(GetCurrentProcess(),
        0x7 /*ProcessDebugPort*/, &port, sizeof(port), nullptr);
    return NT_SUCCESS(st) && port != 0;
}

// 2) 调试标志：ProcessDebugFlags (0x1F) 为 0 表示 NoDebugInherit=false（被调试）
inline bool CheckDebugFlags()
{
    ULONG flags = 0;
    NTSTATUS st = Sys::QueryInformationProcess(GetCurrentProcess(),
        0x1F /*ProcessDebugFlags*/, &flags, sizeof(flags), nullptr);
    return NT_SUCCESS(st) && flags == 0;
}

// 3) 调试对象句柄：ProcessDebugObjectHandle (0x1E) 非空即被调试
inline bool CheckDebugObject()
{
    HANDLE h = nullptr;
    NTSTATUS st = Sys::QueryInformationProcess(GetCurrentProcess(),
        0x1E /*ProcessDebugObjectHandle*/, &h, sizeof(h), nullptr);
    return NT_SUCCESS(st) && h != nullptr;
}

// 4) 硬件断点：读取 DR0~DR3，任一非 0 即存在调试寄存器断点
inline bool CheckHardwareBreakpoints()
{
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    // 用原生 NtGetContextThread 读取自身上下文（需先挂起自身线程较稳妥，
    // 这里直接读当前线程，DR 在用户态可读）
    if (Sys::GetContextThread(GetCurrentThread(), &ctx) == 0) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)
            return true;
    }
    // 兜底：直接读 DR 寄存器（要求支持 __readdr）
    if (__readdr(0) || __readdr(1) || __readdr(2) || __readdr(3))
        return true;
    return false;
}

// 5) 时间陷阱：固定工作量下，若耗时异常（被单步拖慢）即判定调试
inline bool CheckTimeTrap()
{
    uint64_t t0 = __rdtsc();
    volatile uint64_t sink = 0;
    for (int i = 0; i < 2000; i++) sink += static_cast<uint64_t>(i * 3 + 1);
    uint64_t t1 = __rdtsc();
    // 正常 CPU 2000 次简单运算远小于该阈值；单步调试下 TSC 暴涨
    return (t1 - t0) > 20000000ULL;
}

// 6) 进程环境块 PEB.BeingDebugged（IsDebuggerPresent 等价，直接读 PEB）
inline bool CheckPebBeingDebugged()
{
    _PEB* peb = reinterpret_cast<_PEB*>(__readgsqword(0x60));
    return peb && peb->BeingDebugged != 0;
}

// 综合检测：任一命中即返回 true
inline bool IsDebugged()
{
    if (CheckPebBeingDebugged()) return true;
    if (CheckDebugPort())         return true;
    if (CheckDebugFlags())        return true;
    if (CheckDebugObject())       return true;
    if (CheckHardwareBreakpoints()) return true;
    if (CheckTimeTrap())          return true;
    return false;
}

} // namespace AntiDebug
} // namespace pearmor
