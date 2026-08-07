#include "inflate.h"

#include <algorithm>
#include <cstring>

namespace inflate {

namespace {

// 单次解压输出上限，防止恶意/损坏数据把内存吃爆（2 GB）
static const size_t kMaxOut = 2ull * 1024 * 1024 * 1024;

// ---- 长度 / 距离基值与附加位数（RFC 1951，与 zip_writer 对称）----
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

// ---------------------------------------------------------------------------
// 位读取器（低位先出）
// ---------------------------------------------------------------------------
struct BitReader {
    const uint8_t* p = nullptr;
    size_t len = 0;
    size_t bytePos = 0;
    int    bitPos = 0;   // 下一比特在字节中的位序（0=LSB）
    bool   error = false;

    BitReader(const uint8_t* d, size_t n) : p(d), len(n) {}

    int ReadBit() {
        if (bytePos >= len) { error = true; return 0; }
        int bit = (p[bytePos] >> bitPos) & 1;
        if (++bitPos == 8) { bitPos = 0; ++bytePos; }
        return bit;
    }

    uint32_t ReadBits(int count) {
        uint32_t v = 0;
        for (int i = 0; i < count; ++i)
            v |= ((uint32_t)ReadBit()) << i;
        return v;
    }

    void SkipToByteBoundary() {
        if (bitPos != 0) { bitPos = 0; ++bytePos; }
    }
};

// ---------------------------------------------------------------------------
// 规范哈夫曼解码（参考 zlib puff.c 思路）
// ---------------------------------------------------------------------------
static const int kMaxBits = 15;

struct Huff {
    uint16_t count[kMaxBits + 1];
    uint16_t symbol[288];
};

static int Construct(Huff* h, const uint8_t* lengths, int n) {
    for (int i = 0; i <= kMaxBits; ++i) h->count[i] = 0;
    for (int s = 0; s < n; ++s) h->count[lengths[s]]++;

    // 0 长度的码不参与编码（未使用）
    if (h->count[0] == n) return 0;   // 无任何码

    int left = 1;
    for (int len = 1; len <= kMaxBits; ++len) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return left;    // 超额订阅，非法
    }

    uint16_t offs[kMaxBits + 1];
    offs[1] = 0;
    for (int len = 1; len < kMaxBits; ++len)
        offs[len + 1] = offs[len] + h->count[len];

    for (int s = 0; s < n; ++s)
        if (lengths[s] != 0)
            h->symbol[offs[lengths[s]]++] = (uint16_t)s;

    return left;   // 0=完整；>0=不完整（对 DEFLATE 不会由本程序产生）
}

static int Decode(Huff* h, BitReader& br) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= kMaxBits; ++len) {
        code |= br.ReadBit();
        const int count = h->count[len];
        if (code - count < first)
            return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// 固定哈夫曼码长表
// ---------------------------------------------------------------------------
static void FixedLitLenLengths(uint8_t* L) {
    for (int i = 0;   i <= 143; ++i) L[i] = 8;
    for (int i = 144; i <= 255; ++i) L[i] = 9;
    for (int i = 256; i <= 279; ++i) L[i] = 7;
    for (int i = 280; i <= 287; ++i) L[i] = 8;
}
static void FixedDistLengths(uint8_t* D) {
    for (int i = 0; i < 32; ++i) D[i] = 5;   // 30/31 为无效码，仅占位
}

// ---------------------------------------------------------------------------
// 解压一个压缩块到 out
// ---------------------------------------------------------------------------
bool InflateBlock(BitReader& br, Huff& ll, Huff& dist, std::vector<uint8_t>& out) {
    for (;;) {
        const int sym = Decode(&ll, br);
        if (sym < 0) return false;
        if (sym == 256) return true;          // 块结束 EOB

        if (sym < 256) {
            if (out.size() >= kMaxOut) return false;
            out.push_back((uint8_t)sym);
            continue;
        }

        const int li = sym - 257;
        if (li >= 29) return false;           // 285 为最大长度码
        if (out.size() + (size_t)kLenBase[li] + kLenExtra[li] > kMaxOut) return false;

        const int length = kLenBase[li] + (int)br.ReadBits(kLenExtra[li]);

        const int dsym = Decode(&dist, br);
        if (dsym < 0 || dsym >= 30) return false;
        const int distance = kDistBase[dsym] + (int)br.ReadBits(kDistExtra[dsym]);

        if ((size_t)distance > out.size()) return false;   // 回指超出已输出范围

        for (int i = 0; i < length; ++i)
            out.push_back(out[out.size() - (size_t)distance]);
    }
}

} // namespace

// ===========================================================================
// 公开入口
// ===========================================================================
bool Decompress(const uint8_t* data, size_t len, std::vector<uint8_t>& out) {
    out.clear();
    if (!data || len == 0) return false;

    BitReader br(data, len);

    uint8_t fixedLL[288]; FixedLitLenLengths(fixedLL);
    uint8_t fixedDist[32]; FixedDistLengths(fixedDist);
    Huff llFixed, distFixed;
    if (Construct(&llFixed,  fixedLL,   288) < 0) return false;
    if (Construct(&distFixed, fixedDist, 32) < 0) return false;

    bool final = false;
    do {
        final = br.ReadBits(1) != 0;
        const int type = (int)br.ReadBits(2);

        if (type == 0) {
            // 存储型块：跳到字节边界，读 LEN / NLEN，再复制 LEN 字节
            br.SkipToByteBoundary();
            if (br.bytePos + 4 > br.len) { br.error = true; return false; }
            const uint32_t LEN  = (uint32_t)br.p[br.bytePos]     | ((uint32_t)br.p[br.bytePos + 1] << 8);
            const uint32_t NLEN = (uint32_t)br.p[br.bytePos + 2] | ((uint32_t)br.p[br.bytePos + 3] << 8);
            br.bytePos += 4;
            if (LEN != (~NLEN & 0xFFFFu)) { br.error = true; return false; }
            if (br.bytePos + (size_t)LEN > br.len) { br.error = true; return false; }
            if (out.size() + (size_t)LEN > kMaxOut) return false;
            out.insert(out.end(), br.p + br.bytePos, br.p + br.bytePos + LEN);
            br.bytePos += LEN;

        } else if (type == 1) {
            if (!InflateBlock(br, llFixed, distFixed, out)) return false;

        } else if (type == 2) {
            const int hlit  = (int)br.ReadBits(5) + 257;
            const int hdist = (int)br.ReadBits(5) + 1;
            const int hclen = (int)br.ReadBits(4) + 4;
            if (hlit > 286 || hdist > 30) return false;

            static const int order[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
            uint8_t clLengths[19] = {0};
            for (int i = 0; i < hclen; ++i)
                clLengths[order[i]] = (uint8_t)br.ReadBits(3);

            Huff clH;
            if (Construct(&clH, clLengths, 19) < 0) return false;

            std::vector<uint8_t> lengths((size_t)hlit + (size_t)hdist);
            int idx = 0;
            while (idx < hlit + hdist) {
                const int s = Decode(&clH, br);
                if (s < 0) return false;
                if (s < 16) {
                    lengths[idx++] = (uint8_t)s;
                } else if (s == 16) {
                    if (idx == 0) return false;
                    int rep = 3 + (int)br.ReadBits(2);
                    const uint8_t prev = lengths[idx - 1];
                    while (rep-- > 0 && idx < hlit + hdist) lengths[idx++] = prev;
                } else if (s == 17) {
                    int rep = 3 + (int)br.ReadBits(3);
                    while (rep-- > 0 && idx < hlit + hdist) lengths[idx++] = 0;
                } else if (s == 18) {
                    int rep = 11 + (int)br.ReadBits(7);
                    while (rep-- > 0 && idx < hlit + hdist) lengths[idx++] = 0;
                } else {
                    return false;
                }
            }
            if (idx != hlit + hdist) return false;

            Huff llH, distH;
            if (Construct(&llH,  lengths.data(),            hlit)  < 0) return false;
            if (Construct(&distH, lengths.data() + hlit,    hdist) < 0) return false;

            if (!InflateBlock(br, llH, distH, out)) return false;

        } else {
            return false;   // type == 3 非法
        }
    } while (!final);

    return !br.error;
}

} // namespace inflate
