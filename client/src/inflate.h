#pragma once

// ---------------------------------------------------------------------------
// 极简 DEFLATE 解码器（RFC 1951），与 zip_writer 的压缩对称。
//   支持三类块：存储型(BTYPE=00)、固定哈夫曼(BTYPE=01)、动态哈夫曼(BTYPE=02)。
//   位流规则：原始位「低位先出」，哈夫曼码字「高位先出」。
//   纯手写、零依赖，可被任何标准 ZIP 工具生成的流解压。
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstddef>
#include <vector>

namespace inflate {

// 解压单个完整 DEFLATE 数据流（可能包含多个块）。
// 成功返回 true；数据损坏 / 不支持 / 超上限时返回 false，out 不可信。
bool Decompress(const uint8_t* data, size_t len, std::vector<uint8_t>& out);

} // namespace inflate
