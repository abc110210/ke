// ============================================================================
// anti_debug.h — 多层反调试检测（本地纯判定，无网络）
// 覆盖：调试端口 / 调试标志 / 调试对象 / 硬件断点(DR) / 时间陷阱
// 检测手段优先走原生 NtQueryInformationProcess（绕过 Win32 钩子）。
// 返回 true 表示发现调试器。
// ============================================================================
#pragma once
#include <windows.h>
#include <intrin.h>
#include <cstring>

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

// 4) 硬件断点：读取 DR0~DR3，任一非 0 即存在调试寄存器断点。
//    实现：NtGetContextThread 直接读**当前线程**上下文。内核允许线程读取自己的
//    上下文（KPCR.CurrentThread==目标时无需挂起），因此**不要**挂起当前线程
//    （SuspendThread(自己) 是死锁/永久挂起，旧版因此被迫 return false 禁用）。
//    读取失败时保守放行（不误杀、不挂起、不崩）。
inline bool CheckHardwareBreakpoints()
{
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!NT_SUCCESS(Sys::GetContextThread(GetCurrentThread(), &ctx)))
        return false;   // 无法读取上下文 → 保守放行
    return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
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
