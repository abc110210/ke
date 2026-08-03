// ============================================================================
// vm_detect.h — 虚拟机 & 沙箱本地特征检测（P2.1）
//
// 触发策略（关键）：采用“复合判定”，避免误杀正常云/CI 环境（如 GitHub Actions
// 的 Azure VM 同样带超visor 位，但资源充足且无 VM 工具进程）。仅在以下任一成立
// 时返回 true（由调用方决定是否自毁）：
//   1) 注册表出现明确虚拟机特征串（disk\Enum / BIOS 厂商）
//   2) 存在超visor 位 且 资源严重不足（内存<2GB 或 单核 或 系统盘<30GB）
//
// 这能抓住典型恶意分析沙箱（资源受限 + 注册表有 VM 痕迹），同时放行正规 VM/CI。
// 仅用本地判定，无网络。
// ============================================================================
#pragma once
#include <windows.h>
#include <intrin.h>
#include <cstring>

namespace pearmor {
namespace VmDetect {

// 读取注册表字符串值，若其包含子串 needle（不区分大小写）返回 true
inline bool RegContainsSubstring(const char* subKey, const char* valueName,
                                 const char* needle)
{
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return false;
    char buf[512] = {0};
    DWORD type = 0, sz = sizeof(buf);
    LONG r = RegQueryValueExA(hk, valueName, nullptr, &type, (LPBYTE)buf, &sz);
    RegCloseKey(hk);
    if (r != ERROR_SUCCESS) return false;
    // 去掉可能的尾随 null
    size_t len = strlen(buf);
    size_t nl = strlen(needle);
    if (len < nl) return false;
    for (size_t i = 0; i + nl <= len; i++) {
        if (_strnicmp(buf + i, needle, nl) == 0) return true;
    }
    return false;
}

// 抓 CPUID 厂商串（leaf 0x40000000），与已知虚拟机厂商比对
inline bool CpuidVendorMatches()
{
    int regs[4] = {0};
    __cpuid(regs, 0x40000000);
    char vendor[13] = {0};
    memcpy(vendor + 0, &regs[1], 4); // EBX
    memcpy(vendor + 4, &regs[2], 4); // ECX
    memcpy(vendor + 8, &regs[3], 4); // EDX

    static const char* known[] = {
        "VMwareVMware", "VBoxVBoxVBox", "KVMKVMKVM",
        "Microsoft Hv", "QNXQVMQVM", "VirtualBox", "XenVMMXenVMM", nullptr
    };
    for (int i = 0; known[i]; i++)
        if (strcmp(vendor, known[i]) == 0) return true;
    return false;
}

// 是否存在超visor 位（CPUID leaf 1, ECX bit 31）
inline bool HasHypervisorBit()
{
    int regs[4] = {0};
    __cpuid(regs, 1);
    return (static_cast<unsigned>(regs[2]) >> 31) & 1u;
}

// 资源启发式：内存<2GB 或 单核 或 系统盘<30GB → 视为沙箱嫌疑
inline bool LowResources()
{
    SYSTEM_INFO si = {0};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 1) return true;

    MEMORYSTATUSEX ms = {0};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        if (ms.ullTotalPhys < (ULONGLONG)2 * 1024 * 1024 * 1024) return true;
    }

    ULARGE_INTEGER freeBytes, totalBytes, avail;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &avail)) {
        if (totalBytes.QuadPart < (ULONGLONG)30 * 1024 * 1024 * 1024) return true;
    }
    return false;
}

// 综合判定：发现虚拟机/沙箱特征返回 true
inline bool IsVmOrSandbox()
{
    // 1) 注册表明确特征
    if (RegContainsSubstring("SYSTEM\\CurrentControlSet\\Services\\disk\\Enum",
                              "0", "VMware")) return true;
    if (RegContainsSubstring("SYSTEM\\CurrentControlSet\\Services\\disk\\Enum",
                              "0", "VBOX"))   return true;
    if (RegContainsSubstring("SYSTEM\\CurrentControlSet\\Services\\disk\\Enum",
                              "0", "QEMU"))   return true;
    if (RegContainsSubstring("SYSTEM\\CurrentControlSet\\Services\\disk\\Enum",
                              "0", "VIRTUAL")) return true;

    if (RegContainsSubstring("HARDWARE\\DESCRIPTION\\System\\BIOS",
                              "SystemManufacturer", "VMware")) return true;
    if (RegContainsSubstring("HARDWARE\\DESCRIPTION\\System\\BIOS",
                              "SystemManufacturer", "VirtualBox")) return true;
    if (RegContainsSubstring("HARDWARE\\DESCRIPTION\\System\\BIOS",
                              "SystemManufacturer", "QEMU")) return true;
    if (RegContainsSubstring("HARDWARE\\DESCRIPTION\\System\\BIOS",
                              "SystemManufacturer", "Xen")) return true;

    // 2) 超visor 位 + 资源严重不足（抓住资源受限的纯分析沙箱，放行正规 VM/CI）
    if (HasHypervisorBit() && LowResources()) return true;

    return false;
}

} // namespace VmDetect
} // namespace pearmor
