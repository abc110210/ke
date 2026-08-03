// ============================================================================
// kdf.h — 轻量密钥派生（P2.3 / P2.5 共用）
//
// 设计目标（对应需求："密钥不直接写死二进制；基于多因子本地动态派生"）：
//   * 打包阶段：生成随机种子 seed，运行时由 Stub 用 KDF 从 seed 派生出真正的
//     AES 密钥。二进制里只有 seed，没有 32 字节明文密钥常量。
//   * 派生时混入“域标签”，使 innerKey（解密代码）与 outerKey（解密块索引）
//     互不相关 —— 实现“外层密钥 / 内层密钥”分层。
//   * KDF 采用 SHA-256（BCrypt，现代系统原生支持），输入 = seed || 域标签。
//
// 该文件被打包器（packer，链接 bcrypt）与壳（stub，链接 bcrypt）同时包含。
// ============================================================================
#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>

namespace pearmor {

// 单次 SHA-256（BCryptHash 自 Win8 起可用；CI/目标机均为现代 Windows）
inline bool sha256(const unsigned char* in, size_t inLen, unsigned char out[32])
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        ULONG done = 0;
        if (BCryptHash(alg, nullptr, 0,
                       const_cast<PUCHAR>(in), static_cast<ULONG>(inLen),
                       out, 32) == 0)
            ok = true;
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

// 由 32 字节种子派生“内层密钥”（用于分页解密代码块）
inline void derive_inner_key(const unsigned char seed[32], unsigned char out[32])
{
    const char tag[] = "PEARMOR-KDF-INNER-v1";
    unsigned char buf[32 + sizeof(tag) - 1];
    memcpy(buf, seed, 32);
    memcpy(buf + 32, tag, sizeof(tag) - 1);
    if (!sha256(buf, sizeof(buf), out)) memset(out, 0, 32);
}

// 由 32 字节种子派生“外层密钥”（用于解密块索引）
inline void derive_outer_key(const unsigned char seed[32], unsigned char out[32])
{
    const char tag[] = "PEARMOR-KDF-OUTER-v1";
    unsigned char buf[32 + sizeof(tag) - 1];
    memcpy(buf, seed, 32);
    memcpy(buf + 32, tag, sizeof(tag) - 1);
    if (!sha256(buf, sizeof(buf), out)) memset(out, 0, 32);
}

// P3.5：密钥轮换派生 —— seed 叠加“时间盐(8字节)”与新域标签，使每个时间窗的
// 活跃密钥不同。休眠/快照只能抓到某一窗的密钥，无法还原全程明文。
inline void derive_rotated_key(const unsigned char seed[32],
                               const unsigned char salt[8],
                               unsigned char out[32])
{
    const char tag[] = "PEARMOR-KDF-ROTATE-v1";
    unsigned char buf[32 + 8 + sizeof(tag) - 1];
    memcpy(buf, seed, 32);
    memcpy(buf + 32, salt, 8);
    memcpy(buf + 40, tag, sizeof(tag) - 1);
    if (!sha256(buf, sizeof(buf), out)) memset(out, 0, 32);
}

} // namespace pearmor
