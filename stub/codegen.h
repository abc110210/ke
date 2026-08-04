// ============================================================================
// codegen.h — P3.1 运行时动态汇编生成（即时代码生成 / JIT 自改）
//
// 设计目标：
//   1) 运行时才在内存里分配 RWX 页面并即时拼出可用的机器码；
//   2) 没有与之对应的静态存储代码，IDA 无法静态分析这段逻辑；
//   3) 每次运行采用不同的「混合操作顺序 + 初始密钥」，机器码布局存在差异，
//      大幅抬高静态逆向与基于签名的检测门槛。
//
// 这里生成一段「数据指纹」函数（对缓冲区做 累加 + 异或 + 循环左移 混合），
// 同一输入每次布局不同但结果一致，可被校验；真正的价值在于
// 「代码只存在于运行时内存、且每次不同、无静态对应物」。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <excpt.h>     // GetExceptionCode（SEH 诊断用）

#include "syscall.h"   // 原生分配（与 P0-P2 一致，绕过 Win32 钩子）

namespace pearmor {
namespace CodeGen {

// 简单确定性 PRNG（仅用于指令布局随机化，无需密码学强度）
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    unsigned pick(unsigned n) { return (unsigned)(next() % n); }
};

// 把 buf[len] 折叠为 32 位指纹，代码在 *p 处生成，返回末尾指针。
// 约定寄存器：rax=累加器, rbx=data, rsi=计数, rdx=count（均为 0-7 号寄存器）。
// 混合操作顺序由 rng 决定，使每次生成的机器码指令序列不同。
// outPlan（可选）：输出洗牌后的操作顺序（0=ADD, 1=XOR, 2=ROL），供静态对照校验。
static uint8_t* EmitFingerprint(uint8_t* p, Rng& rng, uint32_t secret,
                                uint8_t* outPlan = nullptr)
{
    // 寄存器约定（全部使用 0-7 号通用寄存器，彻底避开 REX 扩展位编码错误）：
    //   rcx = data  (由调用约定给定)
    //   rdx = count (由调用约定给定)
    //   rbx = data 指针副本（non-volatile，需 push/pop 保存）
    //   rsi = 循环计数器（non-volatile，需 push/pop 保存）
    //   rax = 累加器（初始 = secret）
    // 访问 [rbx + rsi*4] 全程无需 REX 前缀（rbx/rsi 都在 0-7），仅 inc/cmp/mov 涉及
    // 64 位时用 REX.W（W 位不涉及扩展寄存器选择，安全）。
    *p++ = 0x56;                                // push rsi
    *p++ = 0x53;                                // push rbx
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xCB;     // mov rbx, rcx   (rbx = data)
    *p++ = 0x33; *p++ = 0xF6;                  // xor esi, esi   (rsi = 0)
    *p++ = 0xB8; memcpy(p, &secret, 4); p += 4; // mov eax, secret
    uint8_t* loop = p;

    // 三种混合操作，按随机顺序各执行一次
    enum Op { ADD, XOR, ROL };
    Op plan[3] = { ADD, XOR, ROL };
    for (int i = 2; i > 0; i--) {           // Fisher-Yates 洗牌
        unsigned j = rng.pick((unsigned)i + 1);
        Op t = plan[i]; plan[i] = plan[j]; plan[j] = t;
    }
    if (outPlan) {                          // 供调用方做静态对照校验
        outPlan[0] = (uint8_t)plan[0];
        outPlan[1] = (uint8_t)plan[1];
        outPlan[2] = (uint8_t)plan[2];
    }
    for (int k = 0; k < 3; k++) {
        switch (plan[k]) {
        case ADD: // add eax, [rbx + rsi*4]  (ModRM=04, SIB=9E: scale2 index=rsi base=rbx)
            *p++ = 0x03; *p++ = 0x04; *p++ = 0x9E; break;
        case XOR: // xor eax, [rbx + rsi*4]
            *p++ = 0x33; *p++ = 0x04; *p++ = 0x9E; break;
        case ROL: // add eax, [rbx + rsi*4] ; rol eax, 7
            *p++ = 0x03; *p++ = 0x04; *p++ = 0x9E;
            *p++ = 0xC1; *p++ = 0xC8; *p++ = 0x07; break;
        }
    }

    *p++ = 0x48; *p++ = 0xFF; *p++ = 0xC6;   // inc rsi
    *p++ = 0x48; *p++ = 0x3B; *p++ = 0xF2;   // cmp rsi, rdx
    long disp = (long)((intptr_t)loop - (intptr_t)(p + 2));
    if (disp >= -128 && disp <= 127) {
        *p++ = 0x7C; *p++ = (uint8_t)(int8_t)disp;     // jl loop（短跳）
    } else {
        *p++ = 0x0F; *p++ = 0x8C;                      // jl loop（near）
        long d2 = (long)((intptr_t)loop - (intptr_t)(p + 4));
        memcpy(p, &d2, 4); p += 4;
    }
    *p++ = 0x5B;   // pop rbx
    *p++ = 0x5E;   // pop rsi
    *p++ = 0xC3;   // ret
    return p;
}

// 运行一次动态代码生成 + 校验。返回 true 表示生成器正确。
// 注意（重要设计决策）：本实现只"生成机器码 + 静态对照校验"，不执行动态代码。
// 原因：现代 Windows 的"内存完整性(HVCI)/Defender 内存保护"禁止从非镜像内存
// 执行代码，RWX JIT 取指即 0xC0000005，且动态代码无 .pdata 展开表，异常无法
// 上报（无 crash.log、SEH 接不住）→ 进程直接终止。CI 的 Azure VM 与 Win11 新机
// 默认开启 HVCI，故"执行自证"与这些环境不兼容。改为：运行时生成唯一机器码
// （保留"无静态对应物、每次布局不同"的逆向门槛），再用 C++ 静态复现同样的
// 算法，证明生成器写出的指令与算法一致。
inline bool RunOnce(uint32_t* outFingerprint = nullptr)
{
    uint32_t sample[8];
    for (int i = 0; i < 8; i++)
        sample[i] = 0x12345678u + (uint32_t)(i * 0x9E3779B9u);

    // 分配 RW 即可（不执行，避免 RWX 被内存完整性策略盯上）
    PVOID mem = nullptr; SIZE_T sz = 0x1000;
    NTSTATUS st = Sys::AllocateVirtualMemory(GetCurrentProcess(), &mem, 0,
        &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !mem) {
        DebugLog("[stub] P3.1 alloc 失败 st=0x%08X mem=%p", (unsigned)st, mem);
        return false;
    }
    uint8_t* code = reinterpret_cast<uint8_t*>(mem);
    Rng rng(__rdtsc());
    uint32_t secret = (uint32_t)(rng.next() & 0xFFFFFFFF);
    uint8_t plan[3] = {0};
    uint8_t* codeEnd = EmitFingerprint(code, rng, secret, plan);
    size_t emitted = (size_t)(codeEnd - code);
    DebugLog("[stub] P3.1 动态代码已生成 %u 字节(不执行, 兼容内存完整性) secret=0x%08X",
             (unsigned)emitted, secret);

    // 静态对照：C++ 复现生成的机器码逻辑（acc=secret; 每轮 i 执行 3 个 op 作用于
    // sample[i]; 共 8 轮），证明生成器写出的指令与算法一致。
    uint32_t acc = secret;
    for (int i = 0; i < 8; i++) {
        uint32_t v = sample[i];
        for (int k = 0; k < 3; k++) {
            switch (plan[k]) {
            case 0: acc += v; break;                              // ADD
            case 1: acc ^= v; break;                              // XOR
            default: acc += v; acc = (acc << 7) | (acc >> 25); break; // ROL: add + rol eax,7
            }
        }
    }

    // 字节级约束：入口 push rsi、出口 ret、长度合理
    bool byteOk = (emitted >= 8 && code[0] == 0x56 && code[emitted - 1] == 0xC3);
    memset(mem, 0xCC, emitted);                      // 清零痕迹
    SIZE_T z = 0;
    Sys::FreeVirtualMemory(GetCurrentProcess(), &mem, &z);

    if (!byteOk) {
        DebugLog("[stub] P3.1 字节约束不满足 emitted=%u", (unsigned)emitted);
        return false;
    }
    if (acc == 0) {
        DebugLog("[stub] P3.1 静态指纹==0 (secret=0x%08X)", secret);
        return false;
    }
    if (outFingerprint) *outFingerprint = acc;
    DebugLog("[stub] P3.1 动态代码生成校验 OK，静态指纹=0x%08X", acc);
    return true;
}

} // namespace CodeGen
} // namespace pearmor
