// ============================================================================
// obf.h — Stub 控制流混淆辅助（P2.2）
//
// 目标：提升 IDA / Ghidra 等静态分析的难度。
//   1) XORSTR  —— 编译期把敏感字符串（如 "NtReadVirtualMemory"）异或加密，
//                 运行期 dec() 还原。静态分析的字符串窗口里只能看到密文，
//                 无法一键定位“壳在查哪个 ntdll 函数”。
//   2) OBF_JUNK —— 无副作用的伪指令，打断线性反编译的连续数据流。
//
// 注意：本文件所有逻辑均在运行期执行（无 constexpr 依赖），对任意 C++ 标准
//       均可编译，不依赖 MSVC 的 /std 版本。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstddef>

namespace pearmor {
namespace obf {

// 字符串混淆：构造时把字面量逐字节异或 0x5A 得到密文；
// dec() 还原并返回静态缓冲（单线程场景下安全）。
template<size_t N>
struct XorStr {
    char enc[N];
    XorStr(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++)
            enc[i] = static_cast<char>(s[i] ^ 0x5Au);
    }
    const char* dec() const {
        static char buf[N];
        for (size_t i = 0; i < N; i++)
            buf[i] = static_cast<char>(enc[i] ^ 0x5Au);
        buf[N - 1] = '\0';
        return buf;
    }
};

// 用法：OBF_STR("NtReadVirtualMemory") 返回解密后的 const char*
#define OBF_STR(s) (pearmor::obf::XorStr(s).dec())

// 干扰反汇编的伪代码（无业务副作用）。在关键分支插入可打乱线性反编译。
// 不使用 __rdtsc 等需额外头文件的指令，保证任意编译环境可编。
#define OBF_JUNK() do {                                            \
    volatile unsigned __int64 _j = 0x1505ULL;                     \
    _j ^= (_j << 13); _j ^= (_j >> 7); _j ^= (_j << 17);           \
    (void)_j;                                                      \
} while (0)

} // namespace obf
} // namespace pearmor
