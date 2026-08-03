// ============================================================================
// crypto_page.h — 按页 AES-256-CBC 加解密（加载器侧）
// 关键：每个 4KB 页使用「独立派生 IV」= master_iv XOR (uint128)pageIndex，
//       因此任意单页都能独立解密 / 重加密，无需一次性处理整镜像。
// 该 IV 派生公式必须与 packer 完全一致（见 packer.cpp）。
// ============================================================================
#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>

namespace pearmor {

struct AesPageCipher {
    BCRYPT_ALG_HANDLE  alg   = nullptr;
    BCRYPT_KEY_HANDLE  keyH  = nullptr;
    unsigned char      ivMaster[16] = {0};
    bool               ok    = false;

    AesPageCipher(const unsigned char* key32, const unsigned char* iv16)
    {
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
            return;
        if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) {
            BCryptCloseAlgorithmProvider(alg, 0); alg = nullptr; return;
        }
        if (BCryptGenerateSymmetricKey(alg, &keyH, nullptr, 0,
                const_cast<PUCHAR>(key32), 32, 0) != 0) {
            BCryptCloseAlgorithmProvider(alg, 0); alg = nullptr; return;
        }
        memcpy(ivMaster, iv16, 16);
        ok = true;
    }

    ~AesPageCipher()
    {
        if (keyH) BCryptDestroyKey(keyH);
        if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    }

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
        ULONG done = 0;
        NTSTATUS st = BCryptDecrypt(keyH, const_cast<PUCHAR>(cipherPage),
            static_cast<ULONG>(pageBytes), nullptr, iv, 16,
            outPlain, static_cast<ULONG>(pageBytes), &done, 0);
        return BCRYPT_SUCCESS(st);
    }

    bool encryptPage(const unsigned char* plainPage, uint32_t pageIndex,
                     unsigned char* outCipher, size_t pageBytes) const
    {
        unsigned char iv[16]; deriveIv(pageIndex, iv);
        ULONG done = 0;
        NTSTATUS st = BCryptEncrypt(keyH, const_cast<PUCHAR>(plainPage),
            static_cast<ULONG>(pageBytes), nullptr, iv, 16,
            outCipher, static_cast<ULONG>(pageBytes), &done, 0);
        return BCRYPT_SUCCESS(st);
    }
};

} // namespace pearmor
