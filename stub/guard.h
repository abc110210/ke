// ============================================================================
// guard.h — 自毁守卫：检测被攻破时擦除关键内存并直接 syscall 终止进程
// 目的：绕过 ScyllaHide / x64dbg 在 ExitProcess / TerminateProcess 上下的钩子，
//       用原始 NtTerminateProcess 直接结束，确保攻击者无法在退出前 Dump。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstring>

#include "syscall.h"

namespace pearmor {

// 直接 syscall 终止（不经任何 Win32 包装）
inline void RawTerminate(NTSTATUS status = 0xC0000001 /* STATUS_FATAL_APP_EXIT */)
{
    HANDLE self = GetCurrentProcess();
    Sys::TerminateProcess(self, status);
    // 兜底：极少走到
    __fastfail(7);
}

// 自毁：擦除指定内存区域（先改可写，再填充 0x00），随后强制终止
// region 传 nullptr 表示只终止、不擦除
inline void SelfDestruct(const void* region = nullptr, size_t size = 0)
{
    if (region && size) {
        // 尝试改为可写再擦除；失败也无所谓，重点是终止
        PVOID base = const_cast<PVOID>(region);
        SIZE_T sz = size;
        ULONG old = 0;
        Sys::ProtectVirtualMemory(GetCurrentProcess(), &base, &sz,
                                  PAGE_READWRITE, &old);
        volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(base);
        for (size_t i = 0; i < size; i++) p[i] = 0x00;
        // 再填一遍 0xCC 增加不确定性
        for (size_t i = 0; i < size; i++) p[i] = 0xCC;
    }
    RawTerminate();
}

} // namespace pearmor
