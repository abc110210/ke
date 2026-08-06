// ============================================================================
// overlay.h — 负载拼接格式（Overlay）
//
// 目标：stub 预编译成"负载无关"的固定运行时，加壳器运行期把密文负载直接
//       拼接进 stub 二进制末尾（overlay，类似 UPX），stub 启动时自读自身
//       文件取出负载。这样最终用户拿到的是"加壳器软件"而非"必须重编译的
//       壳源码"。
//
// 文件布局（加壳后）：
//   [stub exe 原始内容]
//   [payload 密文（逐页 AES-256-CBC，大小 = pageCount * 4096）]
//   [加密索引（isCode 块索引，outerKey 加密，大小 = aligned16(pageCount)）]
//   [Footer（固定 80 字节，写在文件最末尾）]
//
// Footer 是解析的锚点：stub 打开自身文件，读最后 80 字节即可定位负载。
// packer 与 stub 共用本文件，保证结构定义字节级一致。
// ============================================================================
#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>

namespace pearmor {
namespace Overlay {

constexpr uint64_t kMagic   = 0x564F524F4D524145ULL; // "PEARMOROV"（小端）
constexpr uint32_t kVersion = 2;   // v2：Footer 增加 origFileName（CI 74 模块伪装）

#pragma pack(push, 1)
struct Footer {
    uint64_t magic;          // kMagic
    uint32_t version;        // kVersion
    uint32_t pageSize;       // 0x1000
    uint32_t pageCount;      // 页数
    uint32_t payloadLen;     // payload 密文字节数（= pageCount * pageSize）
    uint32_t indexLen;       // 加密索引字节数（16 对齐）
    uint8_t  seed[32];       // 随机种子（KDF 唯一输入）
    uint32_t entryRva;       // 目标入口 RVA
    uint32_t payloadCrc;     // 密文整体 CRC（防篡改，可选校验）
    // CI 74：模块伪装——原版 exe 文件名（宽字符，含扩展名，不含路径）。
    // stub 用它把 GetModuleFileNameW/A 的返回值伪装成原版文件名，
    // 让目标程序认为自己是原版运行（Hanbot 若校验 exe 名/读自身路径会判定异常 → 主动抛 0xE06D7363）。
    wchar_t  origFileName[64];  // 最长 63 个宽字符 + 结尾 NUL
    uint32_t reserved[1];    // 预留（凑整）
};
#pragma pack(pop)
// 原 80 字节中 reserved[3] 占 12；改为 reserved[1](4) + origFileName[64](128) → 80-12+4+128=200
static_assert(sizeof(Footer) == 200, "overlay footer size mismatch");

// 从自身 PE 文件末尾读取 overlay 负载。
// 成功返回 true 并填充 payloadOut / indexOut / footer。
inline bool LoadFromSelf(std::vector<unsigned char>& payloadOut,
                         std::vector<unsigned char>& indexOut,
                         Footer& footer)
{
    wchar_t path[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return false;

    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 5 && h == INVALID_HANDLE_VALUE; attempt++) {
        h = CreateFileW(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) Sleep(100);  // 等待杀软/实时扫描短暂锁释放（CI 实测曾打开失败）
    }
    // 注意：读自身文件必须用最大共享。CI 实测（2026-08-05）：若只用 FILE_SHARE_READ，
    // 与 runner 上杀软/实时扫描以写模式短暂占用冲突 → CreateFileW 失败 → 误报
    // 「未发现 overlay」（PowerShell 校验同文件却通过，印证是打开共享问题而非文件问题）。
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fsz;
    if (!GetFileSizeEx(h, &fsz) || fsz.QuadPart <= 0) { CloseHandle(h); return false; }

    const uint64_t footerSize = sizeof(Footer);
    if ((uint64_t)fsz.QuadPart < footerSize + 64) { CloseHandle(h); return false; }

    // 读末尾 Footer
    LARGE_INTEGER off;
    off.QuadPart = fsz.QuadPart - (LONGLONG)footerSize;
    if (!SetFilePointerEx(h, off, nullptr, FILE_BEGIN)) { CloseHandle(h); return false; }
    DWORD rd = 0;
    if (!ReadFile(h, &footer, (DWORD)footerSize, &rd, nullptr) || rd != footerSize) {
        CloseHandle(h); return false;
    }
    if (footer.magic != kMagic || footer.version != kVersion) { CloseHandle(h); return false; }

    // 布局：payload 在 index 之前，index 在 footer 之前
    uint64_t indexOff   = (uint64_t)fsz.QuadPart - footerSize;
    uint64_t payloadOff = indexOff - (uint64_t)footer.indexLen - (uint64_t)footer.payloadLen;
    if (payloadOff > indexOff) { CloseHandle(h); return false; }

    // 读 payload
    payloadOut.resize(footer.payloadLen);
    off.QuadPart = (LONGLONG)payloadOff;
    if (!SetFilePointerEx(h, off, nullptr, FILE_BEGIN)) { CloseHandle(h); return false; }
    rd = 0;
    if (!ReadFile(h, payloadOut.data(), footer.payloadLen, &rd, nullptr) ||
        rd != footer.payloadLen) {
        CloseHandle(h); return false;
    }

    // 读加密索引
    indexOut.resize(footer.indexLen);
    off.QuadPart = (LONGLONG)indexOff;
    if (!SetFilePointerEx(h, off, nullptr, FILE_BEGIN)) { CloseHandle(h); return false; }
    rd = 0;
    if (!ReadFile(h, indexOut.data(), footer.indexLen, &rd, nullptr) ||
        rd != footer.indexLen) {
        CloseHandle(h); return false;
    }

    CloseHandle(h);
    return true;
}

} // namespace Overlay
} // namespace pearmor
