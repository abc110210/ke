// ============================================================================
// proc_env.h — 进程环境检测（P2.6）
//
// 覆盖：
//   1) 原生 NtQuerySystemInformation 枚举进程，比对逆向/沙箱工具进程名
//      （x64dbg / ida / dnSpy / cheatengine / procmon / VMware·VirtualBox·QEMU 工具等）
//   2) 通过 NtQueryInformationProcess(ProcessBasicInformation) 取父 PID，
//      在进程列表中定位父进程名，若父进程是调试工具 → 判定为被调试器拉起。
//
// 全程原生 syscall，绕过 Win32 进程枚举钩子（如 ScyllaHide 对 CreateToolhelp32Snapshot 的钩子）。
// 命中返回 true（由调用方自毁）。CI 环境无这些进程、父进程为测试运行器 → 安全放行。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "syscall.h"

namespace pearmor {
namespace ProcEnv {

// SYSTEM_PROCESS_INFORMATION 在 Win10/11 x64 的关键字段偏移（跨版本稳定）：
//   0x00 NextEntryOffset (ULONG)
//   0x40 ImageName      (UNICODE_STRING: Length(2)+MaximumLength(2)+Buffer(8))
//   0x50 UniqueProcessId (ULONG_PTR)
//   0x58 InheritedFromUniqueProcessId (ULONG_PTR)
static const ULONG OFF_IMAGENAME = 0x40;
static const ULONG OFF_PID       = 0x50;
static const ULONG OFF_PARENTPID = 0x58;

struct PROCESS_BASIC_INFORMATION_LOCAL {
    PVOID  Reserved1;
    PVOID  PebBaseAddress;
    PVOID  Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

// 可疑进程名（宽字符，不区分大小写比对）
static const wchar_t* kSuspicious[] = {
    L"x64dbg.exe", L"x32dbg.exe", L"ida.exe", L"ida64.exe", L"idag.exe",
    L"idaw.exe", L"windbg.exe", L"ollydbg.exe", L"dnSpy.exe", L"dnSpy64.exe",
    L"cheatengine.exe", L"cheatengine-x86_64.exe", L"procmon.exe", L"procexp.exe",
    L"procexp64.exe", L"frida-win-injector.exe", L"frida-helper.exe", L"xhyde.exe",
    L"vmwareuser.exe", L"vmtoolsd.exe", L"VBoxService.exe", L"VBoxTray.exe",
    L"qemu-ga.exe", L"prl_tools.exe", L"prl_tools_service.exe",
    nullptr
};

static bool NameInSuspicious(const UNICODE_STRING* name)
{
    if (!name || !name->Buffer || name->Length == 0) return false;
    // 转小写临时比较：直接用 _wcsnicmp 对宽串前缀比对
    for (int i = 0; kSuspicious[i]; i++) {
        size_t wl = wcslen(kSuspicious[i]);
        if ((size_t)name->Length / 2 >= wl &&
            _wcsnicmp(name->Buffer, kSuspicious[i], wl) == 0)
            return true;
    }
    return false;
}

// 枚举进程：返回 true 表示发现可疑进程
inline bool FindSuspiciousProcess()
{
    ULONG len = 0;
    // 先查询所需长度
    Sys::QuerySystemInformation(5 /*SystemProcessInformation*/, nullptr, 0, &len);
    if (len == 0) len = 0x20000;
    // 多留余量（进程数可能变化）
    SIZE_T cap = (SIZE_T)len + 0x20000;
    std::vector<unsigned char> buf(cap, 0);

    ULONG ret = 0;
    if (!NT_SUCCESS(Sys::QuerySystemInformation(5, buf.data(), (ULONG)cap, &ret)))
        return false;

    char* p = reinterpret_cast<char*>(buf.data());
    for (;;) {
        auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(p);
        auto* name = reinterpret_cast<UNICODE_STRING*>(p + OFF_IMAGENAME);
        if (NameInSuspicious(name)) return true;

        if (spi->NextEntryOffset == 0) break;
        p += spi->NextEntryOffset;
    }
    return false;
}

// 父进程检测：若当前进程的父进程是调试/沙箱工具 → 返回 true
inline bool ParentIsSuspicious()
{
    PROCESS_BASIC_INFORMATION_LOCAL pbi = {0};
    if (!NT_SUCCESS(Sys::QueryInformationProcess(
            GetCurrentProcess(), 0 /*ProcessBasicInformation*/,
            &pbi, sizeof(pbi), nullptr)))
        return false;

    ULONG len = 0;
    Sys::QuerySystemInformation(5, nullptr, 0, &len);
    if (len == 0) len = 0x20000;
    SIZE_T cap = (SIZE_T)len + 0x20000;
    std::vector<unsigned char> buf(cap, 0);
    ULONG ret = 0;
    if (!NT_SUCCESS(Sys::QuerySystemInformation(5, buf.data(), (ULONG)cap, &ret)))
        return false;

    ULONG_PTR parentPid = pbi.InheritedFromUniqueProcessId;
    char* p = reinterpret_cast<char*>(buf.data());
    for (;;) {
        auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(p);
        ULONG_PTR pid  = *reinterpret_cast<ULONG_PTR*>(p + OFF_PID);
        ULONG_PTR ppid = *reinterpret_cast<ULONG_PTR*>(p + OFF_PARENTPID);
        auto* name = reinterpret_cast<UNICODE_STRING*>(p + OFF_IMAGENAME);
        if (pid == parentPid) {
            // 父进程是系统关键进程（explorer/winlogon/services/cmd 等）视为正常
            static const wchar_t* kNormal[] = {
                L"explorer.exe", L"winlogon.exe", L"services.exe", L"cmd.exe",
                L"conhost.exe", L"csrss.exe", L"wininit.exe", L"rundll32.exe",
                L"powershell.exe", L"pwsh.exe", L"devenv.exe", L"msbuild.exe",
                nullptr
            };
            bool normal = false;
            if (name && name->Buffer) {
                for (int i = 0; kNormal[i]; i++) {
                    size_t wl = wcslen(kNormal[i]);
                    if ((size_t)name->Length / 2 >= wl &&
                        _wcsnicmp(name->Buffer, kNormal[i], wl) == 0) { normal = true; break; }
                }
            }
            if (!normal && NameInSuspicious(name)) return true;
            return false; // 父进程非可疑即放行
        }
        (void)ppid;
        if (spi->NextEntryOffset == 0) break;
        p += spi->NextEntryOffset;
    }
    return false;
}

// 综合判定：发现逆向/沙箱进程 或 父进程为调试工具 → true
inline bool IsSuspiciousEnvironment()
{
    if (FindSuspiciousProcess()) return true;
    if (ParentIsSuspicious())     return true;
    return false;
}

} // namespace ProcEnv
} // namespace pearmor
