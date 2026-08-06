// ============================================================================
// watchdog.h — P3.3 看门狗监控线程（多线程防护 + 线程隐藏）
//
// 独立后台线程，周期性执行：
//   1) 调试状态探测（IsDebuggerPresent / 远程调试）—— 命中即自毁；
//   2) 注入拦截钩子完整性校验（P3.4 的 trampoline 被拆 -> 自毁）；
//   3) 已解密代码页 CRC 重校验（防运行时补丁）；
//   4) P3.5 密钥定期轮换（对抗休眠 / 内存快照抓取密钥）。
// 任一项异常立即擦密钥 + 抹内存 + 强制退出。
// 线程自身通过 NtSetInformationThread(ThreadHideFromDebugger) 隐藏，增加被
//   逆向直接 TerminateThread 杀掉的难度。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <atomic>
#include <functional>

#include "syscall.h"       // NtSetInformationThread / 原生查询
#include "anti_debug.h"     // 反调试探测
#include "guard.h"          // 自毁
#include "integrity.h"      // 页面 CRC
#include "inject_block.h"   // P3.4 钩子完整性校验

// 前向声明：避免与 paged_loader.h 形成强耦合
namespace pearmor {
class PagedLoader;
}

namespace pearmor {
namespace Watchdog {

// 隐藏线程（ThreadHideFromDebugger 0x11）：调试器无法 Suspend/枚举该线程
inline void HideThread(HANDLE hThread)
{
    ULONG one = 1;
    Sys::SetInformationThread(hThread, 0x11 /*ThreadHideFromDebugger*/, &one, sizeof(one));
}

class Guard {
public:
    // loader   : 受保护对象的加载器（用于 CRC/密钥轮换/SelfDestruct）
    // selfDestruct : 统一自毁回调（擦内存 + 终止）
    explicit Guard(PagedLoader* loader,
                   std::function<void()> selfDestruct = nullptr)
        : loader_(loader), selfDestruct_(selfDestruct) {}

    ~Guard() { Stop(); }

    void Start()
    {
        if (thread_) return;
        stop_.store(false, std::memory_order_relaxed);
        thread_ = CreateThread(nullptr, 0, &ThreadProc, this, 0, nullptr);
        if (thread_) HideThread(thread_);   // 连看门狗自身也隐藏
    }

    void Stop()
    {
        stop_.store(true, std::memory_order_relaxed);
        if (thread_) {
            WaitForSingleObject(thread_, INFINITE);
            CloseHandle(thread_);
            thread_ = nullptr;
        }
    }

private:
    static DWORD WINAPI ThreadProc(LPVOID lp)
    {
        reinterpret_cast<Guard*>(lp)->Loop();
        return 0;
    }

    void TriggerSelfDestruct(const char* reason)
    {
        (void)reason; // 预留日志位
        if (selfDestruct_) selfDestruct_();
        else pearmor::SelfDestruct();
    }

    void Loop()
    {
        // 调试状态探测用最轻量、不触发自身钩子的 API
        const uint64_t KEY_ROTATE_MS = 60000;   // P3.5：密钥每 60s 轮换一次
        // 【CI 73 根因】lastRotate 必须初始化为“当前时间”，不能是 0！
        // GetTickCount64() 返回系统开机以来的毫秒数（通常几千万），若 lastRotate=0，
        // 第一次循环（启动 250ms 内）就满足 now-0>60000 → 立刻 RotateKey → 密钥轮换后
        // 页面里还是旧密钥密文 → VEH 用新密钥解密 → CRC 失败 → 误自毁 0xC0000001。
        uint64_t lastRotate = GetTickCount64();

        while (!stop_.load(std::memory_order_relaxed)) {
            Sleep(250);

            // ---- 1) 调试状态 ----
            if (IsDebuggerPresent()) { TriggerSelfDestruct("watchdog:debugger"); return; }
            {
                BOOL remote = FALSE;
                if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
                    TriggerSelfDestruct("watchdog:remote-debugger"); return;
                }
            }

            // ---- 2) 注入拦截钩子完整性（被拆除 = 防护失效 -> 自毁） ----
            if (!InjectBlock::VerifyHooks()) { TriggerSelfDestruct("watchdog:hooks-tampered"); return; }

            // ---- 3) 已解密代码页 CRC 重校验（防运行时补丁） ----
            if (loader_ && !loader_->VerifyDecryptedIntegrity()) {
                TriggerSelfDestruct("watchdog:crc-fail"); return;
            }

            // ---- 4) P3.5 密钥轮换（对抗休眠快照） ----
            uint64_t now = GetTickCount64();
            if (loader_ && (now - lastRotate > KEY_ROTATE_MS)) {
                loader_->RotateKey();
                lastRotate = now;
            }
        }
    }

    PagedLoader* loader_;
    std::function<void()> selfDestruct_;
    HANDLE thread_ = nullptr;
    std::atomic<bool> stop_{false};
};

} // namespace Watchdog
} // namespace pearmor
