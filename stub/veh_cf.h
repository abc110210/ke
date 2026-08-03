// ============================================================================
// veh_cf.h — 基础 VEH 异常调度（控制流混淆）
// 原理：在关键控制转移处放置 INT3(0xCC) / UD2，由向量化异常处理器(VEH)捕获，
//       将 RIP 重定向到真实目标。IDA 静态分析看到的是 0xCC 断点 / 非法指令，
//       无法还原出真实跳转目标，破坏线性流程图。
// 注意：本模块只提供“基础设施 + 演示”，真实地把负载代码全部插桩为异常跳转
//       属于打包器(P2)级的代码变换，这里给出可复用的注册与执行接口。
// ============================================================================
#pragma once
#include <windows.h>
#include <psapi.h>      // GetModuleInformation / MODULEINFO
#include <cstdint>
#pragma comment(lib, "psapi.lib")

#include "pe_loader.h"   // getLoadedModuleBase 等

namespace pearmor {
namespace VehCf {

// 当前模块（壳本体）基址与大小，用于限定 CF 重定向只在壳自身代码内生效
inline void*        g_stubBase  = nullptr;
inline SIZE_T       g_stubSize  = 0;
inline void*        g_cfTarget  = nullptr;   // 待重定向目标（RunObfuscated 设置）

// 初始化：捕获壳自身模块范围（一次性，非热路径）
inline void InitModuleRange()
{
    HMODULE h = nullptr;
    // 从本函数地址反查所属模块
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&InitModuleRange), &h) && h) {
        MODULEINFO mi = {0};
        if (GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) {
            g_stubBase = mi.lpBaseOfDll;
            g_stubSize = mi.SizeOfImage;
        }
    }
}

// VEH 回调：捕获 INT3 / 非法指令，按规则重定向 RIP
inline LONG CALLBACK CfVeh(EXCEPTION_POINTERS* ep)
{
    auto* rec = ep->ExceptionRecord;
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT ||
        rec->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(rec->ExceptionAddress);
        if (g_stubBase && addr >= reinterpret_cast<uintptr_t>(g_stubBase) &&
            addr < reinterpret_cast<uintptr_t>(g_stubBase) + g_stubSize &&
            g_cfTarget) {
            void* t = g_cfTarget;
            g_cfTarget = nullptr;
            ep->ContextRecord->Rip = reinterpret_cast<uintptr_t>(t);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// 安装 CF 异常处理器（低优先级，排在按需解密 VEH 之后）
inline void Install()
{
    InitModuleRange();
    AddVectoredExceptionHandler(0, CfVeh);
}

// 执行一次混淆控制转移：落在一个 INT3 上，由 VEH 重定向到 target
// 这样从静态角度看，调用点之后是 0xCC，真实去向被隐藏。
inline void RunObfuscated(void (*target)())
{
    g_cfTarget = reinterpret_cast<void*>(target);
    __debugbreak();   // 0xCC -> 触发 VehCf::CfVeh -> 跳到 target
}

} // namespace VehCf
} // namespace pearmor
