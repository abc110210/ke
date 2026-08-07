#include "deflate.h"

#include <cstring>

namespace deflate {

// ===========================================================================
// CRC32（多项式 0xEDB88320）
// ===========================================================================
static uint32_t g_crcTable[256];
static bool     g_crcReady = false;

static void BuildCrcTable() {
    if (g_crcReady) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crcTable[i] = c;
    }
    g_crcReady = true;
}

uint32_t Crc32(uint32_t crc, const uint8_t* data, size_t len) {
    BuildCrcTable();
    crc = ~crc;
    for (size_t i = 0; i < len; ++i)
        crc = g_crcTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

const uint32_t* Crc32Table() {
    BuildCrcTable();
    return g_crcTable;
}

// ===========================================================================
// 固定哈夫曼：长度 / 距离对照表
// ===========================================================================
static const uint16_t kLenBase[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const uint8_t kLenExtra[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const uint16_t kDistBase[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
static const uint8_t kDistExtra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

// ===========================================================================
// 位写入器
//   DEFLATE 的原始位流是「低位先出」；
//   而哈夫曼码本身规定「高位先出」，所以写码字时要先做位翻转。
// ===========================================================================
class BitWriter {
public:
    explicit BitWriter(std::vector<uint8_t>& out) : out_(out) {}

    void PutBits(uint32_t value, int count) {
        if (count <= 0) return;
        bitBuf_ |= (uint64_t)(value & ((count >= 32) ? 0xFFFFFFFFu : ((1u << count) - 1u))) << bitCnt_;
        bitCnt_ += count;
        while (bitCnt_ >= 8) {
            out_.push_back((uint8_t)(bitBuf_ & 0xFF));
            bitBuf_ >>= 8;
            bitCnt_ -= 8;
        }
    }

    void PutCode(uint32_t code, int len) {
        uint32_t v = 0;
        for (int i = 0; i < len; ++i)
            v |= ((code >> (len - 1 - i)) & 1u) << i;
        PutBits(v, len);
    }

    void Flush() {
        if (bitCnt_ > 0) {
            out_.push_back((uint8_t)(bitBuf_ & 0xFF));
            bitBuf_ = 0;
            bitCnt_ = 0;
        }
    }

private:
    std::vector<uint8_t>& out_;
    uint64_t bitBuf_ = 0;
    int      bitCnt_ = 0;
};

static void PutLitLen(BitWriter& bw, unsigned sym) {
    if (sym <= 143)      bw.PutCode(0x30u + sym, 8);
    else if (sym <= 255) bw.PutCode(0x190u + (sym - 144), 9);
    else if (sym <= 279) bw.PutCode(sym - 256, 7);
    else                 bw.PutCode(0xC0u + (sym - 280), 8);
}

// ===========================================================================
// 存储型块（BTYPE=00），永远安全的兜底方案
// ===========================================================================
static std::vector<uint8_t> StoredOnly(const uint8_t* data, size_t len) {
    std::vector<uint8_t> out;
    out.reserve(len + (len / 65535 + 1) * 5 + 8);

    if (len == 0) {
        out.push_back(0x01);
        out.push_back(0x00); out.push_back(0x00);
        out.push_back(0xFF); out.push_back(0xFF);
        return out;
    }

    size_t pos = 0;
    while (pos < len) {
        size_t chunk = len - pos;
        if (chunk > 65535) chunk = 65535;
        const bool final = (pos + chunk >= len);

        out.push_back(final ? 0x01 : 0x00);      // BFINAL + BTYPE=00，其余位补零即字节对齐
        out.push_back((uint8_t)(chunk & 0xFF));
        out.push_back((uint8_t)((chunk >> 8) & 0xFF));
        const uint16_t nlen = (uint16_t)(~(uint16_t)chunk);
        out.push_back((uint8_t)(nlen & 0xFF));
        out.push_back((uint8_t)((nlen >> 8) & 0xFF));
        out.insert(out.end(), data + pos, data + pos + chunk);
        pos += chunk;
    }
    return out;
}

// ===========================================================================
// LZ77 哈希链匹配
// ===========================================================================
static const size_t kWindowSize = 32768;
static const size_t kWindowMask = kWindowSize - 1;
static const size_t kHashSize   = 1u << 15;
static const size_t kMinMatch   = 3;
static const size_t kMaxMatch   = 258;

class Matcher {
public:
    Matcher(const uint8_t* d, size_t l, int level)
        : data_(d), len_(l), head_(kHashSize, -1), prev_(kWindowSize, -1) {
        static const int kChain[10] = { 0, 4, 8, 16, 32, 64, 128, 256, 1024, 4096 };
        static const int kGood[10]  = { 0, 8, 16, 24, 32, 48, 64, 96, 160, 258 };
        if (level < 1) level = 1;
        if (level > 9) level = 9;
        maxChain_   = kChain[level];
        goodLength_ = (size_t)kGood[level];
    }

    void Insert(size_t p) {
        if (p + kMinMatch > len_) return;
        const uint32_t h = Hash(p);
        prev_[p & kWindowMask] = head_[h];
        head_[h] = (int32_t)p;
    }

    size_t Find(size_t pos, size_t& dist) const {
        dist = 0;
        if (pos + kMinMatch > len_) return 0;

        size_t maxLen = len_ - pos;
        if (maxLen > kMaxMatch) maxLen = kMaxMatch;
        if (maxLen < kMinMatch) return 0;

        int32_t cur       = head_[Hash(pos)];
        size_t  best      = 0;
        int     chainLeft = maxChain_;

        while (cur >= 0 && chainLeft-- > 0) {
            const size_t cand = (size_t)cur;
            if (cand >= pos) break;
            const size_t d = pos - cand;
            if (d > kWindowSize) break;

            if (best >= kMinMatch && data_[cand + best] != data_[pos + best]) {
                cur = prev_[cand & kWindowMask];
                continue;
            }

            size_t l = 0;
            while (l < maxLen && data_[cand + l] == data_[pos + l]) ++l;

            if (l > best) {
                best = l;
                dist = d;
                if (best >= maxLen || best >= goodLength_) break;
            }
            cur = prev_[cand & kWindowMask];
        }

        if (best < kMinMatch) { dist = 0; return 0; }
        return best;
    }

private:
    uint32_t Hash(size_t p) const {
        return (uint32_t)(((uint32_t)data_[p] << 10) ^
                          ((uint32_t)data_[p + 1] << 5) ^
                           (uint32_t)data_[p + 2]) & (uint32_t)(kHashSize - 1);
    }

    const uint8_t*       data_;
    size_t               len_;
    std::vector<int32_t> head_;
    std::vector<int32_t> prev_;
    int                  maxChain_   = 32;
    size_t               goodLength_ = 32;
};

static int LenCodeIndex(size_t length) {
    for (int i = 28; i >= 0; --i)
        if (length >= kLenBase[i]) return i;
    return 0;
}

static int DistCodeIndex(size_t dist) {
    for (int i = 29; i >= 0; --i)
        if (dist >= kDistBase[i]) return i;
    return 0;
}

// ===========================================================================
// 主入口
// ===========================================================================
std::vector<uint8_t> Compress(const uint8_t* data, size_t len, int level) {
    if (len == 0)  return StoredOnly(data, 0);
    if (level <= 0) return StoredOnly(data, len);

    std::vector<uint8_t> out;
    out.reserve(len / 2 + 128);

    {
        BitWriter bw(out);
        bw.PutBits(1, 1);   // BFINAL = 1
        bw.PutBits(1, 2);   // BTYPE  = 01（固定哈夫曼）

        Matcher m(data, len, level);

        auto emitMatch = [&](size_t mlen, size_t mdist) {
            const int li = LenCodeIndex(mlen);
            PutLitLen(bw, (unsigned)(257 + li));
            if (kLenExtra[li])
                bw.PutBits((uint32_t)(mlen - kLenBase[li]), kLenExtra[li]);

            const int di = DistCodeIndex(mdist);
            bw.PutCode((uint32_t)di, 5);
            if (kDistExtra[di])
                bw.PutBits((uint32_t)(mdist - kDistBase[di]), kDistExtra[di]);
        };

        const bool lazy = (level >= 4);

        // 惰性匹配的挂起状态：pending 位置上已找到一个长度为 pendLen 的匹配，
        // 但还没决定是采用它，还是把该位置降级成字面量。
        bool   pending  = false;
        size_t pendPos  = 0, pendLen = 0, pendDist = 0;

        size_t pos = 0;
        while (pos < len) {
            size_t dist = 0;
            size_t mlen = m.Find(pos, dist);

            if (!lazy) {
                if (mlen >= kMinMatch) {
                    emitMatch(mlen, dist);
                    const size_t end = pos + mlen;
                    for (size_t k = pos; k < end; ++k) m.Insert(k);
                    pos = end;
                } else {
                    PutLitLen(bw, data[pos]);
                    m.Insert(pos);
                    ++pos;
                }
                continue;
            }

            if (pending) {
                if (mlen > pendLen) {
                    // 下一位置能匹配得更长 -> 原位置输出为字面量
                    PutLitLen(bw, data[pendPos]);
                    m.Insert(pos);
                    pendPos = pos; pendLen = mlen; pendDist = dist;
                    ++pos;
                } else {
                    // 采用挂起的匹配
                    emitMatch(pendLen, pendDist);
                    const size_t end = pendPos + pendLen;   // end <= len，Find 已做边界约束
                    for (size_t k = pos; k < end; ++k) m.Insert(k);
                    pos     = end;
                    pending = false;
                }
                continue;
            }

            if (mlen >= kMinMatch) {
                m.Insert(pos);
                pendPos = pos; pendLen = mlen; pendDist = dist;
                pending = true;
                ++pos;
            } else {
                PutLitLen(bw, data[pos]);
                m.Insert(pos);
                ++pos;
            }
        }

        // 收尾：pos 已到达 len。若仍有挂起匹配，说明它覆盖的区间恰好延伸到结尾之外
        // （理论上不会发生，因为匹配长度受 len-pos 约束），这里做保险处理：
        // 把挂起位置及其后所有未输出字节按字面量补齐。
        if (pending) {
            for (size_t k = pendPos; k < len; ++k)
                PutLitLen(bw, data[k]);
        }

        PutLitLen(bw, 256);   // 块结束符 EOB
        bw.Flush();
    }

    // 压不动就退回存储型，保证输出永远不大于「原始大小 + 少量块头」
    if (out.size() >= len)
        return StoredOnly(data, len);

    return out;
}

} // namespace deflate
