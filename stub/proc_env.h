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
#include <cwchar>
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

// 可疑进程名（宽字符，不区分大小写比对 basename）
static const wchar_t* kSuspicious[] = {
    L"x64dbg.exe", L"x32dbg.exe", L"ida.exe", L"ida64.exe", L"idag.exe",
    L"idaw.exe", L"windbg.exe", L"ollydbg.exe", L"dnSpy.exe", L"dnSpy64.exe",
    L"cheatengine.exe", L"cheatengine-x86_64.exe", L"procmon.exe", L"procexp.exe",
    L"procexp64.exe", L"frida-win-injector.exe", L"frida-helper.exe", L"xhyde.exe",
    L"vmwareuser.exe", L"vmtoolsd.exe", L"VBoxService.exe", L"VBoxTray.exe",
    L"qemu-ga.exe", L"prl_tools.exe", L"prl_tools_service.exe",
    nullptr
};

// 正常父进程白名单（被这些进程拉起视为合法，不触发自毁）
static const wchar_t* kNormalParent[] = {
    L"explorer.exe", L"winlogon.exe", L"services.exe", L"cmd.exe",
    L"conhost.exe", L"csrss.exe", L"wininit.exe", L"rundll32.exe",
    L"powershell.exe", L"pwsh.exe", L"devenv.exe", L"msbuild.exe",
    L"code.exe", L"svchost.exe", L"RuntimeBroker.exe", nullptr
};

// 比对进程名 basename 是否落入可疑名单
static bool NameInSuspicious(const wchar_t* name)
{
    if (!name || name[0] == 0) return false;
    for (int i = 0; kSuspicious[i]; i++) {
        if (_wcsicmp(name, kSuspicious[i]) == 0) return true;
    }
    return false;
}

// 通过 PID 取进程镜像名 basename（用户态可读，不碰内核地址）
// 方法：NtOpenProcess + NtQueryInformationProcess(ProcessImageFileName=27)
// 返回的用户态 UNICODE_STRING 中的 Buffer 指向我们提供的缓冲区，完全可读。
// 这规避了 SYSTEM_PROCESS_INFORMATION.ImageName.Buffer 在 Win10+ 指向内核地址、
// 用户态直接解引用必 0xC0000005 的老坑。
static bool QueryImageNameByPid(DWORD pid, wchar_t* outName, size_t outCap)
{
    if (pid == 0 || outCap == 0) return false;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, nullptr };
    HANDLE h = nullptr;
    NTSTATUS st = Sys::OpenProcess(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(st) || !h) return false;

    BYTE buf[sizeof(UNICODE_STRING) + 1024] = {0};
    ULONG ret = 0;
    st = Sys::QueryInformationProcess(h, 27 /*ProcessImageFileName*/,
                                      buf, (ULONG)sizeof(buf), &ret);
    bool ok = false;
    if (NT_SUCCESS(st)) {
        auto* us = reinterpret_cast<UNICODE_STRING*>(buf);
        if (us->Buffer && us->Length > 0) {
            const wchar_t* p   = us->Buffer;
            size_t n  = us->Length / 2;   // 字符数
            const wchar_t* base = p;
            for (size_t i = 0; i < n; i++) {
                if (p[i] == L'\\' || p[i] == L'/') base = p + i + 1;
            }
            size_t blen = (size_t)(p + n - base);
            if (blen > 0 && blen + 1 <= outCap) {
                wcsncpy_s(outName, outCap, base, blen);
                outName[blen] = 0;
                ok = true;
            }
        }
    }
    Sys::CloseHandle(h);
    return ok;
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

    // 只读取 PID 整数（OFF_PID=0x50 跨版本稳定），绝不解引用 ImageName.Buffer
    const ULONG OFF_PID = 0x50;
    char* p = reinterpret_cast<char*>(buf.data());
    for (;;) {
        auto* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(p);
        ULONG_PTR pid = *reinterpret_cast<ULONG_PTR*>(p + OFF_PID);
        wchar_t name[256] = {0};
        if (QueryImageNameByPid((DWORD)pid, name, 256) && NameInSuspicious(name))
            return true;
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

    DWORD parentPid = (DWORD)pbi.InheritedFromUniqueProcessId;
    if (parentPid == 0) return false;

    wchar_t name[256] = {0};
    // 取不到父进程镜像名（已退出/无权限）→ 视为安全放行
    if (!QueryImageNameByPid(parentPid, name, 256)) return false;

    // 白名单优先：正常父进程直接放行（修正旧版 normal 变量被忽略的 bug）
    for (int i = 0; kNormalParent[i]; i++) {
        if (_wcsicmp(name, kNormalParent[i]) == 0) return false;
    }
    // 非白名单，再看是否落入可疑名单
    if (NameInSuspicious(name)) return true;
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
