// ============================================================================
// pearmor-packer.cpp — C++ 程序加壳器（overlay 拼接版）
// 读取 64 位 PE -> 构建内存镜像 -> 按 4KB 页独立 AES-256-CBC 加密（每页派生
// 独立 IV）-> 把密文负载 + 加密索引 + footer 拼接进预编译的 stub 运行时末尾
// （overlay），产出加壳后的成品 exe。stub 启动时自读自身文件取出负载。
//
// 关键：每页 IV_i = master_iv XOR (uint128)pageIndex，与 stub/crypto_page.h 完全一致，
//       使得加载器可对任意单页独立解密/重加密，无需一次性处理整镜像。
//
// 用法: pearmor-packer <输入.exe> [-o <输出.exe>] [-stub <stub.exe>] [--seed-hex <64hex>]
//       -stub 缺省时在同目录找 pearmor-stub.exe
// ============================================================================
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

#include "../common/page_crc.h"   // fnv1a32
#include "../common/kdf.h"        // 密钥派生（P2.3 / P2.5）
#include "../common/aes256.h"     // 纯 C++ AES-256-CBC（与 stub 共用，避免 BCrypt 依赖）
#include "../stub/overlay.h"      // overlay 拼接格式（Footer 与 stub 字节级一致）

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

// --- 写文件 ---
static void writeFile(const char* path, const std::vector<unsigned char>& data) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0 || !f) die("无法写输出文件");
    if (fwrite(data.data(), 1, data.size(), f) != data.size()) die("写输出文件失败");
    fclose(f);
}

// --- ANSI/UTF-8 多字节路径 → 宽字符（资源 API 用） ---
static std::wstring utf8ToWide(const char* s) {
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    std::wstring w(n ? n - 1 : 0, L'\0');
    if (n) MultiByteToWideChar(CP_ACP, 0, s, -1, &w[0], n);
    return w;
}

// --- 图标搬运上下文（EnumResourceNames 回调用） ---
struct IconCtx {
    const wchar_t* dst;   // 目标文件（带 overlay 的成品副本）
    bool ok = false;
};

// 资源类型常量：RT_GROUP_ICON=14 / RT_ICON=3（显式 W 版。
// 不能直接用宏 RT_GROUP_ICON/RT_ICON——本文件 ANSI 构建下它们展开为 LPSTR，
// 而资源 API 用 W 版（FindResourceW/UpdateResourceW/EnumResourceNamesW）需 LPCWSTR，C2664。）
static const LPCWSTR kRtGroupIcon = (LPCWSTR)(ULONG_PTR)14; // RT_GROUP_ICON
static const LPCWSTR kRtIcon     = (LPCWSTR)(ULONG_PTR)3;   // RT_ICON

// 枚举回调：处理第一个 RT_GROUP_ICON（主图标），把 group + 其引用的全部 RT_ICON
// 用 UpdateResource 注入到 dst（BeginUpdateResource 后逐项写入，再 EndUpdateResource 提交）。
// 若任何一步失败则放弃（不致命，调用方保持成品无图标即可）。
static BOOL CALLBACK enumGroupIcon(HMODULE h, LPCWSTR /*type*/, LPWSTR name, LONG_PTR lp)
{
    auto* ctx = reinterpret_cast<IconCtx*>(lp);
    HRSRC grs = FindResourceW(h, name, kRtGroupIcon);
    HGLOBAL gh = grs ? LoadResource(h, grs) : nullptr;
    DWORD gsz = grs ? SizeofResource(h, grs) : 0;
    void* gdata = gh ? LockResource(gh) : nullptr;
    if (!gdata || gsz < 6) return FALSE; // 无有效 group，放弃

    // 解析 group 内引用的 RT_ICON ID 列表（GRPICONDIRENTRY 14B/个，nID 在 +12）
    std::vector<WORD> ids;
    WORD count = *(WORD*)((BYTE*)gdata + 4);
    for (WORD i = 0; i < count && 6 + (DWORD)i * 14 + 14 <= gsz; i++)
        ids.push_back(*(WORD*)((BYTE*)gdata + 6 + i * 14 + 12));

    HANDLE hu = BeginUpdateResourceW(ctx->dst, FALSE);
    if (!hu) return FALSE;
    bool any = false;
    any |= (UpdateResourceW(hu, kRtGroupIcon, name,
                            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), gdata, gsz) != FALSE);
    for (WORD id : ids) {
        HRSRC irs = FindResourceW(h, MAKEINTRESOURCEW(id), kRtIcon);
        HGLOBAL ih = irs ? LoadResource(h, irs) : nullptr;
        DWORD isz = irs ? SizeofResource(h, irs) : 0;
        void* idata = ih ? LockResource(ih) : nullptr;
        if (!idata) continue;
        any |= (UpdateResourceW(hu, kRtIcon, MAKEINTRESOURCEW(id),
                                MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), idata, isz) != FALSE);
    }
    ctx->ok = (any && EndUpdateResourceW(hu, FALSE) != FALSE);
    return FALSE; // 只处理第一个 group（主图标）
}

// 搬运图标：把 srcPath 的主图标注入 dstPath（dstPath 必须是可写的 PE 文件）。
// 返回 true 表示成功注入（或源无图标返回 false，调用方可忽略）。
static bool copyIconFromSource(const wchar_t* srcPath, const wchar_t* dstPath)
{
    HMODULE h = LoadLibraryExW(srcPath, nullptr, LOAD_LIBRARY_AS_DATAFILE);
    if (!h) return false;
    IconCtx ctx{ dstPath, false };
    EnumResourceNamesW(h, kRtGroupIcon, enumGroupIcon, reinterpret_cast<LONG_PTR>(&ctx));
    FreeLibrary(h);
    return ctx.ok;
}

// 给成品注入原 exe 图标，且【不破坏 overlay】：
// UpdateResource 重写 PE 文件时可能动到文件末尾附加数据（overlay=密文），不能赌系统行为。
// 安全做法：对成品副本注入图标 → 校验副本末尾 overlay footer magic 仍在 → 在才替换成品。
static void attachSourceIcon(const char* inPath, const char* outPath)
{
    std::string tmp = std::string(outPath) + ".icon.tmp";
    if (!CopyFileA(outPath, tmp.c_str(), FALSE)) {
        fprintf(stderr, "[packer] 警告: 图标搬运失败（无法复制副本）\n");
        return;
    }
    std::wstring wSrc = utf8ToWide(inPath), wTmp = utf8ToWide(tmp.c_str());
    bool injected = copyIconFromSource(wSrc.c_str(), wTmp.c_str());
    if (!injected) {
        DeleteFileA(tmp.c_str());
        fprintf(stderr, "[packer] 图标搬运跳过（源无图标资源或注入失败）\n");
        return;
    }
    // 校验副本末尾 overlay footer magic 是否保留（密文不能被 UpdateResource 吃掉）
    FILE* f = nullptr;
    if (fopen_s(&f, tmp.c_str(), "rb") == 0 && f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        unsigned char magic[8] = {0};
        if (sz >= (long)sizeof(pearmor::Overlay::Footer)) {
            fseek(f, sz - (long)sizeof(pearmor::Overlay::Footer), SEEK_SET);
            if (fread(magic, 1, 8, f) == 8) {}
        }
        fclose(f);
        if (*(uint64_t*)magic == pearmor::Overlay::kMagic) {
            // overlay 保留 → 用副本替换成品
            if (CopyFileA(tmp.c_str(), outPath, FALSE))
                printf("[packer] 已搬运原 exe 图标到成品（overlay 校验通过）\n");
            else
                fprintf(stderr, "[packer] 警告: 图标写入成功但替换成品失败\n");
        } else {
            fprintf(stderr, "[packer] 警告: 图标注入破坏了 overlay（密文），已放弃图标，成品保持无图标\n");
        }
    }
    DeleteFileA(tmp.c_str());
}

// --- 校验 stub 是合法 PE64（负载无关的运行时） ---
static void validateStub(const std::vector<unsigned char>& pe) {
    if (pe.size() < 0x40) die("stub 文件太小，不是合法 PE");
    if (*(WORD*)&pe[0] != 0x5A4D) die("stub 缺少 MZ 头");
    DWORD peOff = *(DWORD*)&pe[0x3C];
    if (peOff + 0x18 > pe.size()) die("stub PE 头偏移越界");
    if (*(DWORD*)&pe[peOff] != 0x00004550) die("stub 缺少 PE\\0\\0 签名");
    WORD machine = *(WORD*)&pe[peOff + 4];
    if (machine != 0x8664) die("stub 不是 x64 (PE32+)");
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

int main(int argc, char** argv)
{
    // ---- 参数解析 ----
    const char* inPath   = nullptr;
    const char* outPath  = nullptr;
    const char* stubPath = nullptr;
    unsigned char seed[32];
    bool seedGiven = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) { outPath = argv[++i]; }
        else if (strcmp(argv[i], "-stub") == 0 && i + 1 < argc) { stubPath = argv[++i]; }
        else if (strcmp(argv[i], "--seed-hex") == 0 && i + 1 < argc) {
            if (!hexToBytes(argv[i + 1], seed, 32)) die("--seed-hex 应为 64 个 hex 字符");
            seedGiven = true; i++;
        }
        else if (!inPath) { inPath = argv[i]; }
        else die("未知参数");
    }
    if (!inPath) {
        printf(
            "pearmor-packer — C++ 程序加壳器（overlay 拼接版）\n"
            "用法: pearmor-packer <输入.exe> [-o <输出.exe>] [-stub <stub.exe>]\n"
            "      [-stub] 缺省时在同目录找 pearmor-stub.exe\n");
        return 1;
    }

    // P2.3 / P2.5：随机种子 seed，运行时由 Stub 用 KDF 派生 innerKey/outerKey
    if (!seedGiven) {
        if (BCryptGenRandom(nullptr, seed, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            die("生成随机种子失败");
    }

    // ---- 读取负载无关的 stub 运行时 ----
    if (!stubPath) stubPath = "pearmor-stub.exe";
    // 显式检查 stub 存在性，给清晰错误（避免 readFile 的通用「无法打开输入文件」误导成 target 问题）
    {
        FILE* _cf = nullptr;
        if (fopen_s(&_cf, stubPath, "rb") != 0 || !_cf) {
            if (_cf) fclose(_cf);
            fprintf(stderr, "[packer] 错误: 找不到壳运行时模板: %s\n", stubPath);
            fprintf(stderr, "[packer] 请确认 pearmor-stub.exe 与 pearmor-packer.exe 在同一目录\n");
            return 1;
        }
        fclose(_cf);
    }
    auto stubBytes = readFile(stubPath);
    validateStub(stubBytes);

    // ---- 目标 PE ----
    auto file = readFile(inPath);
    validatePE64(file);
    auto img = buildImage(file);
    DWORD peOff = *(DWORD*)&file[0x3C];
    auto* nt = (IMAGE_NT_HEADERS*)(file.data() + peOff);
    DWORD entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    if (entryRva == 0) die("目标无入口点(AddressOfEntryPoint==0)");

    unsigned char innerKey[32], outerKey[32];
    pearmor::derive_inner_key(seed, innerKey);
    pearmor::derive_outer_key(seed, outerKey);

    const uint32_t PAGE = 4096;
    size_t padded = (img.size() + PAGE - 1) / PAGE * PAGE;
    img.resize(padded, 0);
    uint32_t pageCount = (uint32_t)(padded / PAGE);

    // 解析节，确定每页是否为代码页
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
    unsigned char ivPage[16];
    for (uint32_t i = 0; i < pageCount; i++) {
        deriveIv(innerKey, i, ivPage);
        pearmor::aes256::cbc_encrypt(innerKey, ivPage, img.data() + i * PAGE, PAGE, enc.data() + i * PAGE);
        crc[i] = pearmor::fnv1a32(img.data() + i * PAGE, PAGE);
    }
    (void)crc; // 每页明文 CRC 预留（后续用于运行期解密校验）

    // 外层加密：块索引(isCode) 用 outerKey 一次性 AES-CBC 加密
    size_t idxLen = (pageCount + 15) & ~(size_t)15;
    std::vector<uint8_t> idxPlain(idxLen, 0);
    memcpy(idxPlain.data(), isCode.data(), pageCount);
    std::vector<unsigned char> encIndex(idxLen, 0);
    {
        unsigned char oiv[16];
        memcpy(oiv, outerKey, 16);
        pearmor::aes256::cbc_encrypt(outerKey, oiv, idxPlain.data(), idxLen, encIndex.data());
    }

    // ---- 组装 overlay footer（与 stub/overlay.h 字节级一致） ----
    pearmor::Overlay::Footer footer = {};
    footer.magic       = pearmor::Overlay::kMagic;
    footer.version     = pearmor::Overlay::kVersion;
    footer.pageSize    = PAGE;
    footer.pageCount   = pageCount;
    footer.payloadLen  = (uint32_t)enc.size();
    footer.indexLen    = (uint32_t)encIndex.size();
    memcpy(footer.seed, seed, 32);
    footer.entryRva    = entryRva;
    footer.payloadCrc  = pearmor::fnv1a32(enc.data(), enc.size());

    // ---- 拼接：stub + 密文 + 加密索引 + footer ----
    std::vector<unsigned char> out;
    out.reserve(stubBytes.size() + enc.size() + encIndex.size() + sizeof(footer));
    out.insert(out.end(), stubBytes.begin(), stubBytes.end());
    out.insert(out.end(), enc.begin(), enc.end());
    out.insert(out.end(), encIndex.begin(), encIndex.end());
    const unsigned char* fp = reinterpret_cast<const unsigned char*>(&footer);
    out.insert(out.end(), fp, fp + sizeof(footer));

    if (!outPath) {
        static std::string defOut;
        defOut = std::string(inPath) + "_packed.exe";
        outPath = defOut.c_str();
    }
    writeFile(outPath, out);

    // 搬运原 exe 图标到成品（让加壳后的软件保留原图标，用户无感知）。
    // 只对副本操作 + overlay magic 校验，绝不冒险动密文。
    attachSourceIcon(inPath, outPath);

    printf("[packer] 完成: %s -> %s (%zu 字节密文, %u 页, 入口 RVA=0x%X, overlay 拼接)\n",
        inPath, outPath, enc.size(), pageCount, entryRva);
    return 0;
}
