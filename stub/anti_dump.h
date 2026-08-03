// ============================================================================
// anti_dump.h — 防内存 Dump（基础方案）
// 核心思路：监控 ntdll 中用于读/写/打开进程的关键系统调用首部，
//          若被 jmp 钩子（Scylla / x64dbg 插件常用手法）替换，立即触发自毁，
//          让攻击者无法在进程存活时稳定 Dump 出明文。
// 动态校验：启动期抓取各函数首部作为基准，运行期周期性比对。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "pe_loader.h"   // getLoadedModuleBase / peExportAddress
#include "obf.h"         // 字符串混淆（P2.2）
#include "guard.h"

namespace pearmor {
namespace AntiDump {

struct Monitor {
    uintptr_t ntdllBase = 0;
    uintptr_t ntdllEnd  = 0;
    struct Fn {
        const char* name;
        void*       addr = nullptr;
        unsigned char ref[16] = {0};  // 启动基准首部
    };
    Fn fns[5];

    void Init()
    {
        ntdllBase = getLoadedModuleBase(L"ntdll.dll");
        if (ntdllBase) {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdllBase);
            auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(ntdllBase + dos->e_lfanew);
            ntdllEnd  = ntdllBase + nt->OptionalHeader.SizeOfImage;
        }
        // P2.2：函数名经编译期异或混淆，静态分析看不到明文 "NtReadVirtualMemory"
        const char* names[5] = {
            OBF_STR("NtReadVirtualMemory"),
            OBF_STR("NtWriteVirtualMemory"),
            OBF_STR("NtOpenProcess"),
            OBF_STR("NtProtectVirtualMemory"),
            OBF_STR("NtQueryInformationProcess")
        };
        for (int i = 0; i < 5; i++) {
            fns[i].name = names[i];
            fns[i].addr = peExportAddress(ntdllBase, names[i]);
            if (fns[i].addr)
                memcpy(fns[i].ref, fns[i].addr, 16);
        }
    }

    // 判断地址是否落在 ntdll 模块范围内（落在外面 = 被劫持跳走）
    bool outsideNtdll(uintptr_t addr) const
    {
        return addr < ntdllBase || addr >= ntdllEnd;
    }

    // 解析一条可能的中转 jmp 目标
    bool resolveJmpTarget(const unsigned char* code, uintptr_t* outTarget) const
    {
        // E9 rel32 : target = rip(下条) + rel32
        if (code[0] == 0xE9) {
            int32_t rel = *reinterpret_cast<const int32_t*>(code + 1);
            *outTarget = reinterpret_cast<uintptr_t>(code + 5) + rel;
            return true;
        }
        // FF 25 imm32 : jmp [rip + imm32]，目标在内存中
        if (code[0] == 0xFF && code[1] == 0x25) {
            int32_t disp = *reinterpret_cast<const int32_t*>(code + 2);
            uintptr_t slot = reinterpret_cast<uintptr_t>(code + 6) + disp;
            *outTarget = *reinterpret_cast<const uintptr_t*>(slot);
            return true;
        }
        // EB rel8
        if (code[0] == 0xEB) {
            int8_t rel = *reinterpret_cast<const int8_t*>(code + 1);
            *outTarget = reinterpret_cast<uintptr_t>(code + 2) + rel;
            return true;
        }
        return false;
    }

    // 扫描一次：返回 true 表示发现钩子
    bool Scan()
    {
        if (!ntdllBase) return false;
        for (int i = 0; i < 5; i++) {
            if (!fns[i].addr) continue;
            const unsigned char* cur = reinterpret_cast<const unsigned char*>(fns[i].addr);

            // 1) 首部与基准不一致 → 被篡改
            if (memcmp(cur, fns[i].ref, 16) != 0) {
                // 若只是因为首次基准抓取时本身已被钩（极端情况），仍按“变化”处理
                return true;
            }

            // 2) 入口为 jmp 且跳到 ntdll 外 → 典型 inline hook
            uintptr_t target = 0;
            if (resolveJmpTarget(cur, &target) && outsideNtdll(target))
                return true;
        }
        return false;
    }
};

} // namespace AntiDump
} // namespace pearmor
