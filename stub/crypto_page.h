// ============================================================================
// crypto_page.h — 按页 AES-256-CBC 加解密（加载器侧）
// 关键：每个 4KB 页使用「独立派生 IV」= master_iv XOR (uint128)pageIndex，
//       因此任意单页都能独立解密 / 重加密，无需一次性处理整镜像。
// 该 IV 派生公式必须与 packer 完全一致（见 packer.cpp）。
//
// 实现说明：改用 common/aes256.h 的自带纯 C++ AES（不再依赖 Windows BCrypt），
// 因为 BCrypt 在 VEH 异常处理上下文里重入会崩溃于 bcryptprimitives.dll，
// 而壳的"按需分页解密"正是在 VEH 中调解密。packer 也改用同一份 aes256.h，
// 保证加解密逐字节一致。
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include "aes256.h"

namespace pearmor {

struct AesPageCipher {
    unsigned char key32[32]   = {0};   // 解密密钥（AES-256）
    unsigned char ivMaster[16] = {0};   // IV 母版（= 密钥/外层密钥前 16 字节）
    bool          ok           = false;

    AesPageCipher(const unsigned char* key, const unsigned char* iv16)
    {
        memcpy(key32, key, 32);
        memcpy(ivMaster, iv16, 16);
        ok = true;   // 纯实现无需运行时初始化，恒成功
    }

    ~AesPageCipher() { memset(key32, 0, sizeof(key32)); }

    // IV_i = master_iv XOR (uint128)pageIndex（低 8 字节放页号）
    void deriveIv(uint32_t pageIndex, unsigned char outIv[16]) const
    {
        memcpy(outIv, ivMaster, 16);
        for (int j = 0; j < 8; j++)
            outIv[j] ^= static_cast<unsigned char>((pageIndex >> (j * 8)) & 0xFF);
    }

    // pageBytes 必须为 16 的倍数（4KB 页天然满足）
    bool decryptPage(const unsigned char* cipherPage, uint32_t pageIndex,
                     unsigned char* outPlain, size_t pageBytes) const
    {
        unsigned char iv[16]; deriveIv(pageIndex, iv);
        aes256::cbc_decrypt(key32, iv, cipherPage, pageBytes, outPlain);
        return true;   // 纯实现不失败（输入长度恒为页对齐）
    }

    bool encryptPage(const unsigned char* plainPage, uint32_t pageIndex,
                     unsigned char* outCipher, size_t pageBytes) const
    {
        unsigned char iv[16]; deriveIv(pageIndex, iv);
        aes256::cbc_encrypt(key32, iv, plainPage, pageBytes, outCipher);
        return true;
    }
};

} // namespace pearmor
