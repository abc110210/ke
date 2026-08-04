// ============================================================================
// pearmor-packer.cpp
// 本地打包器 (P1)：读取 64 位 PE -> 构建内存镜像 -> 按 4KB 页独立 AES-256-CBC
// 加密（每页派生独立 IV）-> 生成 stub 嵌入头（含代码页标志 + 每页 CRC）。
//
// 关键：每页 IV_i = master_iv XOR (uint128)pageIndex，与 stub/crypto_page.h 完全一致，
//       使得加载器可对任意单页独立解密/重加密，无需一次性处理整镜像。
//
// 用法: pearmor-packer <输入.exe> <输出.h> [--seed-hex <64hex>]
// ============================================================================
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

#include "../common/page_crc.h"   // fnv1a32
#include "../common/kdf.h"        // 密钥派生（P2.3 / P2.5）
#include "../common/aes256.h"     // 纯 C++ AES-256-CBC（与 stub 共用，避免 BCrypt 依赖）

static void die(const char* msg) {
    fprintf(stderr, "[packer] 错误: %s\n", msg);
    exit(1);
}

// --- 读文件 ---
static std::vector<unsigned char> readFile(const char* path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) die("无法打开输入文件");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) die("输入文件为空");
    std::vector<unsigned char> buf((size_t)sz);
    if (fread(buf.data(), 1, buf.size(), f) != buf.size()) die("读取输入文件失败");
    fclose(f);
    return buf;
}

// --- 校验 64 位 PE ---
static void validatePE64(const std::vector<unsigned char>& pe) {
    if (pe.size() < 0x40) die("文件太小，不是合法 PE");
    if (*(WORD*)&pe[0] != 0x5A4D) die("缺少 MZ 头");
    DWORD peOff = *(DWORD*)&pe[0x3C];
    if (peOff + 0x18 > pe.size()) die("PE 头偏移越界");
    if (*(DWORD*)&pe[peOff] != 0x00004550) die("缺少 PE\\0\\0 签名");
    WORD machine = *(WORD*)&pe[peOff + 4];
    if (machine != 0x8664) die("仅支持 x64 (PE32+) 目标");
    WORD magic = *(WORD*)&pe[peOff + 24];
    if (magic != 0x20B) die("目标不是 PE32+ (OptionalHeader.Magic != 0x20B)");
    DWORD sizeOfImage = *(DWORD*)&pe[peOff + 24 + 56];
    if (sizeOfImage == 0) die("SizeOfImage 为 0");
    if (pe.size() > 0x7FFFFFFFULL) die("镜像过大，暂不支持");
}

// --- 十六进制工具 ---
static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool hexToBytes(const char* s, unsigned char* out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int h = hexVal(s[i * 2]);
        int l = hexVal(s[i * 2 + 1]);
        if (h < 0 || l < 0) return false;
        out[i] = (unsigned char)((h << 4) | l);
    }
    return true;
}

// --- 由页号派生独立 IV ---
static void deriveIv(const unsigned char ivMaster[16], uint32_t pageIndex, unsigned char out[16]) {
    memcpy(out, ivMaster, 16);
    for (int j = 0; j < 8; j++)
        out[j] ^= (unsigned char)((pageIndex >> (j * 8)) & 0xFF);
}

// --- 构建内存镜像（headers + 各节按 VirtualAddress 落位） ---
static std::vector<unsigned char> buildImage(const std::vector<unsigned char>& file) {
    DWORD peOff = *(DWORD*)&file[0x3C];
    auto* nt = (IMAGE_NT_HEADERS*)(file.data() + peOff);
    DWORD sizeOfImage = nt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;

    std::vector<unsigned char> img(sizeOfImage, 0);
    memcpy(img.data(), file.data(), sizeOfHeaders < file.size() ? sizeOfHeaders : file.size());

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD va  = sec[i].VirtualAddress;
        DWORD raw = sec[i].PointerToRawData;
        DWORD rsz = sec[i].SizeOfRawData;
        if (va + sec[i].Misc.VirtualSize > sizeOfImage)
            sec[i].Misc.VirtualSize = sizeOfImage - va;
        if (raw + rsz > file.size()) rsz = file.size() > raw ? (DWORD)(file.size() - raw) : 0;
        if (rsz > 0 && raw + rsz <= file.size() && va + rsz <= sizeOfImage)
            memcpy(img.data() + va, file.data() + raw, rsz);
    }
    return img;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf(
            "pearmor-packer — C++ 程序加壳打包器 (P1 分页加密 + P2 密钥分层)\n"
            "用法: pearmor-packer <输入.exe> <输出.h> [--seed-hex <64hex>]\n");
        return 1;
    }
    const char* inPath  = argv[1];
    const char* outPath = argv[2];

    // P2.3 / P2.5：不再写死密钥。生成随机种子 seed，运行时由 Stub 用 KDF 派生
    //   innerKey（解密代码页）与 outerKey（解密块索引）——“外层/内层”分层。
    // 二进制里只剩 seed，无任何 32 字节明文密钥常量。
    unsigned char seed[32];
    bool seedGiven = false;
    for (int i = 3; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--seed-hex") == 0) {
            if (!hexToBytes(argv[i + 1], seed, 32)) die("--seed-hex 应为 64 个 hex 字符");
            seedGiven = true;
        }
        // 旧的 --key-hex / --iv-hex 已废弃，忽略以保持与旧构建脚本兼容
    }
    if (!seedGiven) {
        if (BCryptGenRandom(nullptr, seed, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            die("生成随机种子失败");
    }

    unsigned char innerKey[32], outerKey[32];
    pearmor::derive_inner_key(seed, innerKey);
    pearmor::derive_outer_key(seed, outerKey);

    auto file = readFile(inPath);
    validatePE64(file);
    auto img = buildImage(file);

    const uint32_t PAGE = 4096;
    size_t padded = (img.size() + PAGE - 1) / PAGE * PAGE;
    img.resize(padded, 0);
    uint32_t pageCount = (uint32_t)(padded / PAGE);

    // 解析节，确定每页是否为代码页
    DWORD peOff = *(DWORD*)&file[0x3C];
    auto* nt = (IMAGE_NT_HEADERS*)(file.data() + peOff);
    std::vector<uint8_t> isCode(pageCount, 0);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (uint32_t i = 0; i < pageCount; i++) {
        DWORD va = i * PAGE;
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; s++) {
            DWORD sVa = sec[s].VirtualAddress;
            DWORD sVz = sec[s].Misc.VirtualSize ? sec[s].Misc.VirtualSize : sec[s].SizeOfRawData;
            if (va + PAGE > sVa && va < sVa + sVz) {
                if (sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    isCode[i] = 1;
            }
        }
    }

    // 每页独立加密 + 计算明文 CRC
    std::vector<unsigned char> enc(padded, 0);
    std::vector<uint32_t> crc(pageCount, 0);

    // 逐页 AES-256-CBC 加密（纯 C++ 实现；IV 派生与 stub 的 AesPageCipher(innerKey,innerKey) 一致）
    unsigned char ivPage[16];
    for (uint32_t i = 0; i < pageCount; i++) {
        deriveIv(innerKey, i, ivPage);
        pearmor::aes256::cbc_encrypt(innerKey, ivPage, img.data() + i * PAGE, PAGE, enc.data() + i * PAGE);
        crc[i] = pearmor::fnv1a32(img.data() + i * PAGE, PAGE);
    }

    // ---- 外层加密：块索引(isCode) 用 outerKey 一次性 AES-CBC 加密 ----
    // 运行时 Stub 先用 outerKey 解出 isCode，再用 innerKey 逐页解密代码。
    // 两把密钥由 seed 经 KDF 派生且互不相关 —— 拿到密文也不易反推。
    size_t idxLen = (pageCount + 15) & ~(size_t)15;
    std::vector<uint8_t> idxPlain(idxLen, 0);
    memcpy(idxPlain.data(), isCode.data(), pageCount);
    std::vector<unsigned char> encIndex(idxLen, 0);
    {
        // 外层加密：块索引(isCode) 用 outerKey 一次性 AES-256-CBC（纯 C++ 实现）
        // IV = outerKey 前 16 字节，与 stub 的 AesPageCipher(outerKey, outerKey) 一致
        unsigned char oiv[16];
        memcpy(oiv, outerKey, 16);
        pearmor::aes256::cbc_encrypt(outerKey, oiv, idxPlain.data(), idxLen, encIndex.data());
    }

    // 写头文件
    FILE* f = nullptr;
    if (fopen_s(&f, outPath, "w") != 0 || !f) die("无法写输出头文件");

    fprintf(f, "// 由 pearmor-packer 自动生成，请勿手改。\n");
    fprintf(f, "#pragma once\n\n");
    fprintf(f, "#define PEARMOR_MAGIC 0x524F414D52414550ULL // \"PEARMOR\"\n");
    fprintf(f, "#define PEARMOR_PAGE_SIZE 0x1000\n");
    fprintf(f, "#define PEARMOR_PAGE_COUNT %uU\n", pageCount);
    fprintf(f, "#define PEARMOR_PAYLOAD_LEN %zuULL\n", enc.size());

    fprintf(f, "static const unsigned char PEARMOR_PAYLOAD[] = {\n");
    for (size_t i = 0; i < enc.size(); i++) {
        if (i % 16 == 0) fprintf(f, "    ");
        fprintf(f, "0x%02X", enc[i]);
        if (i + 1 < enc.size()) fprintf(f, ",");
        if ((i + 1) % 16 == 0) fprintf(f, "\n");
    }
    if (enc.size() % 16 != 0) fprintf(f, "\n");
    fprintf(f, "};\n\n");

    fprintf(f, "static const uint32_t PEARMOR_PAGE_CRC[] = {\n");
    for (uint32_t i = 0; i < pageCount; i++) {
        if (i % 8 == 0) fprintf(f, "    ");
        fprintf(f, "0x%08X", crc[i]);
        if (i + 1 < pageCount) fprintf(f, ",");
        if ((i + 1) % 8 == 0) fprintf(f, "\n");
    }
    if (pageCount % 8 != 0) fprintf(f, "\n");
    fprintf(f, "};\n\n");

    fprintf(f, "static const unsigned char PEARMOR_SEED[32] = {\n    ");
    for (int i = 0; i < 32; i++) {
        fprintf(f, "0x%02X", seed[i]);
        if (i < 31) fprintf(f, ",");
    }
    fprintf(f, "\n};\n\n");

    // 外层加密后的块索引（isCode）。Stub 用 outerKey 解密得到每页是否代码页。
    fprintf(f, "static const unsigned char PEARMOR_ENC_INDEX[] = {\n");
    for (size_t i = 0; i < encIndex.size(); i++) {
        if (i % 16 == 0) fprintf(f, "    ");
        fprintf(f, "0x%02X", encIndex[i]);
        if (i + 1 < encIndex.size()) fprintf(f, ",");
        if ((i + 1) % 16 == 0) fprintf(f, "\n");
    }
    if (encIndex.size() % 16 != 0) fprintf(f, "\n");
    fprintf(f, "};\n");
    fclose(f);

    printf("[packer] 完成: %s -> %s (%zu 字节密文, %u 页, AES-256-CBC 分页, 种子派生分层密钥)\n",
        inPath, outPath, enc.size(), pageCount);
    return 0;
}
