// ============================================================================
// syscall.h — 原生系统调用封装（直接 syscall，绕过 Win32 API 钩子）
// 依赖：syscall.asm 提供的 NtRawSyscall 裸桩
//       pe_loader.h 提供的 getLoadedModuleBase / peExportAddress
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "pe_loader.h"   // 复用 PEB 解析工具

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) (((NTSTATUS)(x)) >= 0)
#endif

// 裸系统调用桩（由 syscall.asm 导出）。
// 支持最多 11 个系统调用参数（a1..a11）；a7..a11 带默认 nullptr，
// 旧包装（≤6 参数）无需改动即可继续编译。
extern "C" NTSTATUS NtRawSyscall(ULONG ssn, void* a1, void* a2, void* a3,
                                 void* a4, void* a5, void* a6,
                                 void* a7 = nullptr, void* a8 = nullptr,
                                 void* a9 = nullptr, void* a10 = nullptr,
                                 void* a11 = nullptr);

namespace pearmor {
namespace Sys {

// 从 ntdll 导出函数首部扫描 "mov eax, imm32" (0xB8) 取出系统调用号
inline ULONG getSsn(const char* name)
{
    uintptr_t ntdll = getLoadedModuleBase(L"ntdll.dll");
    if (!ntdll) return 0;
    void* fn = peExportAddress(ntdll, name);
    if (!fn) return 0;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(fn);
    // 扫描前 32 字节寻找 0xB8（部分版本前有 endbr64 F3 0F 1E FA，不影响）
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0xB8) {
            ULONG ssn = *reinterpret_cast<const ULONG*>(p + i + 1);
            return ssn;
        }
    }
    return 0;
}

struct Ssn {
    ULONG NtAllocateVirtualMemory   = 0;
    ULONG NtFreeVirtualMemory      = 0;
    ULONG NtProtectVirtualMemory   = 0;
    ULONG NtQueryInformationProcess= 0;
    ULONG NtReadVirtualMemory      = 0;
    ULONG NtWriteVirtualMemory     = 0;
    ULONG NtGetContextThread       = 0;
    ULONG NtSetInformationThread   = 0;
    ULONG NtTerminateProcess       = 0;
    ULONG NtClose                  = 0;
    ULONG NtQueryInformationThread = 0;
    ULONG NtQuerySystemInformation = 0;
    ULONG NtMapViewOfSection   = 0;   // P3.4：拦截远程 DLL 映射
    ULONG NtCreateThreadEx     = 0;   // P3.4：拦截远程线程创建
    ULONG NtOpenProcess        = 0;   // P3.4：阻断外部打开本进程句柄
};

inline Ssn& ssn()
{
    static Ssn s;
    return s;
}

// 在壳启动早期调用一次：解析所有需要的系统调用号
inline void Init()
{
    Ssn& s = ssn();
    s.NtAllocateVirtualMemory    = getSsn("NtAllocateVirtualMemory");
    s.NtFreeVirtualMemory       = getSsn("NtFreeVirtualMemory");
    s.NtProtectVirtualMemory    = getSsn("NtProtectVirtualMemory");
    s.NtQueryInformationProcess = getSsn("NtQueryInformationProcess");
    s.NtReadVirtualMemory       = getSsn("NtReadVirtualMemory");
    s.NtWriteVirtualMemory      = getSsn("NtWriteVirtualMemory");
    s.NtGetContextThread        = getSsn("NtGetContextThread");
    s.NtSetInformationThread    = getSsn("NtSetInformationThread");
    s.NtTerminateProcess        = getSsn("NtTerminateProcess");
    s.NtClose                   = getSsn("NtClose");
    s.NtQueryInformationThread  = getSsn("NtQueryInformationThread");
    s.NtQuerySystemInformation  = getSsn("NtQuerySystemInformation");
    s.NtMapViewOfSection        = getSsn("NtMapViewOfSection");
    s.NtCreateThreadEx          = getSsn("NtCreateThreadEx");
    s.NtOpenProcess             = getSsn("NtOpenProcess");
    s.NtSetInformationThread    = getSsn("NtSetInformationThread");
}

// ---- 各系统调用的类型化包装（参数布局与官方 Nt* 一致） ----
// 【CI110 健壮性修复】原生 syscall 优先（绕过 Win32 钩子，保生产环境反 hook），
// SSN 未解析(=0)或调用失败则回退 Win32 VirtualAlloc/VirtualProtect/VirtualFree。
// 原因（第四轮.txt）：CI runner 系统更新后 getSsn 扫描 0xB8 解析到的
// NtAllocateVirtualMemory SSN 错位 → 调用落到 NtMapViewOfSection → 返回
// 0xC0000024(STATUS_MAP_TOO_MANY_SECTIONS) → P3.1 自校验 alloc 失败自毁、
// 且 payload 页分配（同函数）也会失败。回退保证所有环境都能加载。

inline NTSTATUS AllocateVirtualMemory(HANDLE hProc, PVOID* base, ULONG_PTR zeroBits,
                                      PSIZE_T size, ULONG type, ULONG prot)
{
    if (ssn().NtAllocateVirtualMemory != 0) {
        NTSTATUS st = NtRawSyscall(ssn().NtAllocateVirtualMemory, hProc, base,
                        (void*)zeroBits, size, (void*)(UINT_PTR)type, (void*)(UINT_PTR)prot);
        if (NT_SUCCESS(st) && *base) return st;
    }
    // 回退：仅支持本进程、zeroBits=0 的情形（加载器/payload 均满足）
    if (hProc == GetCurrentProcess() && zeroBits == 0) {
        *base = VirtualAlloc(nullptr, *size, type, prot);
        if (*base) return 0; // STATUS_SUCCESS
    }
    return (NTSTATUS)0xC0000001; // STATUS_UNSUCCESSFUL
}

// NtFreeVirtualMemory(ProcessHandle, BaseAddress*, Size*, FreeType)
inline NTSTATUS FreeVirtualMemory(HANDLE hProc, PVOID* base, PSIZE_T size)
{
    if (ssn().NtFreeVirtualMemory != 0) {
        NTSTATUS st = NtRawSyscall(ssn().NtFreeVirtualMemory, hProc, base, size,
                        (void*)(UINT_PTR)MEM_RELEASE, nullptr, nullptr);
        if (NT_SUCCESS(st)) return st;
    }
    if (hProc == GetCurrentProcess()) {
        if (VirtualFree(*base, 0, MEM_RELEASE)) return 0;
    }
    return (NTSTATUS)0xC0000001;
}

inline NTSTATUS ProtectVirtualMemory(HANDLE hProc, PVOID* base, PSIZE_T size,
                                     ULONG newProt, PULONG oldProt)
{
    if (ssn().NtProtectVirtualMemory != 0) {
        NTSTATUS st = NtRawSyscall(ssn().NtProtectVirtualMemory, hProc, base, size,
                        (void*)(UINT_PTR)newProt, oldProt, nullptr);
        if (NT_SUCCESS(st)) return st;
    }
    if (hProc == GetCurrentProcess()) {
        DWORD op = 0;
        if (VirtualProtect(*base, *size, newProt, &op)) {
            if (oldProt) *oldProt = op;
            return 0;
        }
    }
    return (NTSTATUS)0xC0000001;
}

inline NTSTATUS QueryInformationProcess(HANDLE hProc, ULONG infoClass,
                                        PVOID buf, ULONG len, PULONG retLen)
{
    return NtRawSyscall(ssn().NtQueryInformationProcess, hProc,
                        (void*)(UINT_PTR)infoClass, buf, (void*)(UINT_PTR)len, retLen, nullptr);
}

inline NTSTATUS ReadVirtualMemory(HANDLE hProc, PVOID base, PVOID buf,
                                  SIZE_T size, PSIZE_T bytesRead)
{
    return NtRawSyscall(ssn().NtReadVirtualMemory, hProc, base, buf,
                        (void*)(UINT_PTR)size, bytesRead, nullptr);
}

inline NTSTATUS WriteVirtualMemory(HANDLE hProc, PVOID base, PVOID buf,
                                   SIZE_T size, PSIZE_T bytesWritten)
{
    return NtRawSyscall(ssn().NtWriteVirtualMemory, hProc, base, buf,
                        (void*)(UINT_PTR)size, bytesWritten, nullptr);
}

inline NTSTATUS GetContextThread(HANDLE hThread, PCONTEXT ctx)
{
    return NtRawSyscall(ssn().NtGetContextThread, hThread, (void*)ctx, nullptr, nullptr, nullptr, nullptr);
}

inline NTSTATUS SetInformationThread(HANDLE hThread, ULONG infoClass,
                                     PVOID buf, ULONG len)
{
    return NtRawSyscall(ssn().NtSetInformationThread, hThread,
                        (void*)(UINT_PTR)infoClass, buf, (void*)(UINT_PTR)len, nullptr, nullptr);
}

inline NTSTATUS TerminateProcess(HANDLE hProc, NTSTATUS status)
{
    return NtRawSyscall(ssn().NtTerminateProcess, hProc, (void*)(UINT_PTR)status, nullptr, nullptr, nullptr, nullptr);
}

inline NTSTATUS CloseHandle(HANDLE h)
{
    return NtRawSyscall(ssn().NtClose, h, nullptr, nullptr, nullptr, nullptr, nullptr);
}

inline NTSTATUS QueryInformationThread(HANDLE hThread, ULONG infoClass,
                                       PVOID buf, ULONG len, PULONG retLen)
{
    return NtRawSyscall(ssn().NtQueryInformationThread, hThread,
                        (void*)(UINT_PTR)infoClass, buf, (void*)(UINT_PTR)len, retLen, nullptr);
}

// NtQuerySystemInformation(SystemInformationClass, Buffer, Length, ReturnLength)
inline NTSTATUS QuerySystemInformation(ULONG infoClass, PVOID buf, ULONG len, PULONG retLen)
{
    return NtRawSyscall(ssn().NtQuerySystemInformation, (void*)(UINT_PTR)infoClass,
                        buf, (void*)(UINT_PTR)len, retLen, nullptr, nullptr);
}

// NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress*, ZeroBits, CommitSize,
//                    SectionOffset*, ViewSize*, InheritDisposition, AllocationType, Win32Protect)
// P3.4：用于拦截远程 DLL 注入（ProcessHandle 指向其它进程时）。
inline NTSTATUS MapViewOfSection(HANDLE section, HANDLE hProc, PVOID* base,
                                 ULONG_PTR zeroBits, SIZE_T commitSize,
                                 PLARGE_INTEGER sectionOffset, PSIZE_T viewSize,
                                 ULONG inheritDisp, ULONG allocType, ULONG win32Protect)
{
    return NtRawSyscall(ssn().NtMapViewOfSection, section, hProc, base,
                        (void*)zeroBits, (void*)commitSize, sectionOffset,
                        viewSize, (void*)(UINT_PTR)inheritDisp,
                        (void*)(UINT_PTR)allocType, (void*)(UINT_PTR)win32Protect);
}

// NtCreateThreadEx(ThreadHandle*, DesiredAccess, ObjectAttributes*, ProcessHandle,
//                  StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaxStackSize, AttributeList)
// P3.4：用于拦截远程线程创建（ProcessHandle 指向其它进程时）。
inline NTSTATUS CreateThreadEx(PHANDLE thread, ULONG access, PVOID objAttr,
                               HANDLE hProc, PVOID start, PVOID arg,
                               ULONG createFlags, ULONG_PTR zeroBits,
                               SIZE_T stackSize, SIZE_T maxStack, PVOID attrList)
{
    return NtRawSyscall(ssn().NtCreateThreadEx, thread, (void*)(UINT_PTR)access,
                        objAttr, hProc, start, arg, (void*)(UINT_PTR)createFlags,
                        (void*)zeroBits, (void*)stackSize, (void*)maxStack, attrList);
}

// NtOpenProcess(ProcessHandle*, DesiredAccess, ObjectAttributes*, ClientId)
// P3.4：阻断外部进程打开本进程句柄（ClientId->UniqueProcess == 本进程时拦截）。
inline NTSTATUS OpenProcess(PHANDLE proc, ULONG access, PVOID objAttr, PVOID clientId)
{
    return NtRawSyscall(ssn().NtOpenProcess, proc, (void*)(UINT_PTR)access,
                        objAttr, clientId, nullptr, nullptr);
}

} // namespace Sys
} // namespace pearmor
