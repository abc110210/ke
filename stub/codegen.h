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
// 约定寄存器：rax=累加器, r8=数据指针, r9=元素个数(=len/4), r10=计数器。
// 混合操作顺序由 rng 决定，使每次生成的机器码指令序列不同。
static uint8_t* EmitFingerprint(uint8_t* p, Rng& rng, uint32_t secret)
{
    // 参数搬运（微软 x64 调用约定：rcx=data, rdx=count）：
    // 循环体用 r8 作数据指针、r9 作元素计数，需先把 rcx/rdx 搬过来，
    // 否则 r8/r9 是调用前的残留垃圾值（从随机地址读取 / 循环上限错乱）。
    *p++ = 0x4C; *p++ = 0x89; *p++ = 0xC8;   // mov r8, rcx
    *p++ = 0x4C; *p++ = 0x89; *p++ = 0xD1;   // mov r9, rdx
    // rax = secret（初始种子）
    *p++ = 0xB8; memcpy(p, &secret, 4); p += 4;
    // r10 = 0（计数器）
    *p++ = 0x41; *p++ = 0xBA; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; // mov r10d,0
    // 循环体起点（用于回填 jmp）
    uint8_t* loop = p;

    // 三种混合操作，按随机顺序各执行一次
    enum Op { ADD, XOR, ROL };
    Op plan[3] = { ADD, XOR, ROL };
    for (int i = 2; i > 0; i--) {           // Fisher-Yates 洗牌
        unsigned j = rng.pick((unsigned)i + 1);
        Op t = plan[i]; plan[i] = plan[j]; plan[j] = t;
    }
    for (int k = 0; k < 3; k++) {
        switch (plan[k]) {
        case ADD: // add eax, [r8 + r10*4]
            *p++ = 0x03; *p++ = 0x04; *p++ = 0x90; break;
        case XOR: // xor eax, [r8 + r10*4]
            *p++ = 0x33; *p++ = 0x04; *p++ = 0x90; break;
        case ROL: // add eax, [r8 + r10*4] ; rol eax, 7
            *p++ = 0x03; *p++ = 0x04; *p++ = 0x90;
            *p++ = 0xC1; *p++ = 0xC8; *p++ = 0x07; break;
        }
    }

    // 计数器++ ; cmp r10, r9 ; jl loop
    *p++ = 0x49; *p++ = 0xFF; *p++ = 0xC2;            // inc r10
    *p++ = 0x4D; *p++ = 0x3B; *p++ = 0xCA;            // cmp r10, r9
    long disp = (long)((intptr_t)loop - (intptr_t)(p + 2));
    if (disp >= -128 && disp <= 127) {
        *p++ = 0x7C; *p++ = (uint8_t)(int8_t)disp;     // jl loop（短跳）
    } else {
        *p++ = 0x0F; *p++ = 0x8C;                      // jl loop（near）
        long d2 = (long)((intptr_t)loop - (intptr_t)(p + 4));
        memcpy(p, &d2, 4); p += 4;
    }
    // 返回 rax（32 位结果即 eax，约定由调用约定返回）
    *p++ = 0xC3;                                       // ret
    return p;
}

// 运行一次动态代码生成 + 校验。返回 true 表示生成/执行/校验均成功。
// 调用时机：壳启动早期（反调试之后），证明「动态代码路径可用」。
inline bool RunOnce(uint32_t* outFingerprint = nullptr)
{
    uint32_t sample[8];
    for (int i = 0; i < 8; i++)
        sample[i] = 0x12345678u + (uint32_t)(i * 0x9E3779B9u);

    PVOID mem = nullptr; SIZE_T sz = 0x1000;
    NTSTATUS st = Sys::AllocateVirtualMemory(GetCurrentProcess(), &mem, 0,
        &sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st) || !mem) return false;
    uint8_t* code = reinterpret_cast<uint8_t*>(mem);
    // 本次运行用随机种子，使指令布局每次不同（抬高逆向门槛）；
    // 校验则对同一份生成的代码执行两次，结果应完全一致（验证执行确定性）。
    Rng rng(__rdtsc());
    uint32_t secret = (uint32_t)(rng.next() & 0xFFFFFFFF);
    EmitFingerprint(code, rng, secret);
    using Fn = uint32_t(*)(const uint32_t*, size_t);
    Fn fn = reinterpret_cast<Fn>(code);
    uint32_t fp1 = fn(sample, 8);
    uint32_t fp2 = fn(sample, 8);
    memset(mem, 0xCC, 0x1000);                     // 用后清零 RWX 页
    SIZE_T z = 0;
    Sys::FreeVirtualMemory(GetCurrentProcess(), &mem, &z);
    if (fp1 == 0 || fp1 != fp2) return false;
    if (outFingerprint) *outFingerprint = fp1;
    return true;
}

} // namespace CodeGen
} // namespace pearmor
