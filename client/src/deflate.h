#pragma once

// ---------------------------------------------------------------------------
// 极简 DEFLATE 压缩器（RFC 1951），固定哈夫曼编码 + LZ77 哈希链匹配。
// 不依赖 zlib / miniz，纯手写，编译零外部依赖。
// 输出可被任何标准 unzip 工具解压。
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstddef>
#include <vector>

namespace deflate {

// 压缩等级：0 = 只做存储型块（最快），1-9 = 逐级加大匹配搜索深度
std::vector<uint8_t> Compress(const uint8_t* data, size_t len, int level = 6);

// 标准 CRC32（多项式 0xEDB88320），与 ZIP / zlib 一致
uint32_t Crc32(uint32_t crc, const uint8_t* data, size_t len);
inline uint32_t Crc32(const uint8_t* data, size_t len) {
    return Crc32(0, data, len);
}

// 原始 CRC 查表（不做首尾取反）——ZipCrypto 密钥推进需要用到裸表
const uint32_t* Crc32Table();
inline uint32_t Crc32Step(uint32_t crc, uint8_t c) {
    return Crc32Table()[(crc ^ c) & 0xFF] ^ (crc >> 8);
}

} // namespace deflate
