#include "zip_reader.h"
#include "deflate.h"
#include "util.h"
#include "inflate.h"   // inflate::Decompress —— DEFLATE 解压

#include <algorithm>
#include <vector>
#include <cstdint>

namespace zipr {

namespace {

// ===========================================================================
// ZipCrypto 解密（与 zip_writer 写端对称）
// ===========================================================================
class ZipCrypto {
public:
    void Init(const std::string& password) {
        k0_ = 0x12345678u;
        k1_ = 0x23456789u;
        k2_ = 0x34567890u;
        for (unsigned char c : password) UpdateKeys(c);
    }

    // 原地解密：cipher -> plain，并推进密钥状态（与写端顺序一致）
    void Decrypt(uint8_t* buf, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            const uint8_t plain = (uint8_t)(buf[i] ^ StreamByte());
            UpdateKeys(plain);
            buf[i] = plain;
        }
    }

    uint8_t StreamByte() const {
        const uint16_t t = (uint16_t)((k2_ & 0xFFFFu) | 2u);
        return (uint8_t)(((t * (t ^ 1u)) >> 8) & 0xFFu);
    }

private:
    void UpdateKeys(uint8_t c) {
        k0_ = deflate::Crc32Step(k0_, c);
        k1_ = k1_ + (k0_ & 0xFFu);
        k1_ = k1_ * 134775813u + 1u;
        k2_ = deflate::Crc32Step(k2_, (uint8_t)(k1_ >> 24));
    }

    uint32_t k0_ = 0, k1_ = 0, k2_ = 0;
};

// ===========================================================================
// 小工具
// ===========================================================================
inline uint16_t LE16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t LE32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool SeekTo(HANDLE h, unsigned long long off) {
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
    return ::SetFilePointerEx(h, li, nullptr, FILE_BEGIN) != 0;
}

bool ReadExact(HANDLE h, void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf;
    while (n > 0) {
        DWORD want = (DWORD)(n > 0x100000 ? 0x100000 : n);
        DWORD got = 0;
        if (!::ReadFile(h, p, want, &got, nullptr) || got == 0) return false;
        p += got; n -= got;
    }
    return true;
}

// 逐层创建目录（已存在则忽略）。支持带 `\\?\` 前缀的长路径：
// 前缀部分（\\?\ 或 \\?\UNC\）不当作分隔符拆分，从其后开始逐级 CreateDirectoryW。
bool EnsureDirExists(const std::wstring& dir) {
    // 2026-08-06 防回归：早期版本用 prefixLen+substr 拼路径，一旦 \\?\ 前缀没生效
    // （prefixLen=0），卷根 D: 被跳过，后面组件变成相对路径，落到当前工作目录，
    // 在 D 盘根并列建出 DJ暴力版本/league of legends 这类空文件夹（用户实测 08:27）。
    // 本版做法：先把「前缀」(\\?\X:\ 或 \\?\UNC\server\share\ 或 X:\ 或 \\server\share\) 摘出来，
    // 后续每个待建目录都拼回 prefix → 【永远是绝对路径】，绝不可能产生相对路径。
    if (dir.empty()) return true;

    std::wstring prefix;  // 前缀（含末尾分隔符），如 "\\?\D:\"
    std::wstring body;    // 去掉前缀后的剩余部分

    if (dir.size() >= 4 && dir[0] == L'\\' && dir[1] == L'\\' &&
        dir[2] == L'?' && dir[3] == L'\\') {
        // 长路径前缀 \\?\...
        if (dir.size() >= 8 && dir.compare(0, 8, L"\\\\?\\UNC\\") == 0) {
            size_t p = dir.find(L'\\', 8);
            if (p == std::wstring::npos) return true;
            size_t q = dir.find(L'\\', p + 1);
            if (q == std::wstring::npos) return true;
            prefix = dir.substr(0, q + 1);          // \\?\UNC\server\share\
            body = dir.substr(q + 1);
        } else if (dir.size() >= 7 && dir[5] == L':' && dir[6] == L'\\') {
            prefix = dir.substr(0, 7);              // \\?\X:\
            body = dir.substr(7);
        } else if (dir.size() >= 6 && dir[5] == L':') {
            prefix = dir.substr(0, 6) + L"\\";      // \\?\X: -> \\?\X:\
            body = dir.substr(6);
        } else {
            prefix = dir.substr(0, 4);              // \\?\
            body = dir.substr(4);
        }
    } else if (dir.size() >= 2 && dir[0] == L'\\' && dir[1] == L'\\') {
        // 普通 UNC \\server\share\...
        size_t p = dir.find(L'\\', 2);
        if (p == std::wstring::npos) return true;
        size_t q = dir.find(L'\\', p + 1);
        if (q == std::wstring::npos) return true;
        prefix = dir.substr(0, q + 1);
        body = dir.substr(q + 1);
    } else if (dir.size() >= 3 && dir[1] == L':' && (dir[2] == L'\\' || dir[2] == L'/')) {
        prefix = dir.substr(0, 3);                  // X:\
        body = dir.substr(3);
    } else {
        // 相对路径兜底（调用方应保证传绝对路径）；prefix 为空，full 可能相对
        prefix = L"";
        body = dir;
    }

    // 逐段拼回 prefix 建目录：full 始终为绝对路径（含盘符或 UNC 根）
    std::wstring cur;
    for (size_t i = 0; i < body.size(); ++i) {
        wchar_t c = body[i];
        if (c == L'\\' || c == L'/') {
            if (!cur.empty()) {
                std::wstring full = prefix + cur;
                if (::CreateDirectoryW(full.c_str(), nullptr) == 0) {
                    const DWORD e = ::GetLastError();
                    if (e != ERROR_ALREADY_EXISTS) return false;
                }
            }
            cur.push_back(L'\\');
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) {
        std::wstring full = prefix + cur;
        if (::CreateDirectoryW(full.c_str(), nullptr) == 0) {
            const DWORD e = ::GetLastError();
            if (e != ERROR_ALREADY_EXISTS) return false;
        }
    }
    return true;
}

// 创建文件父目录
bool CreateParentDirs(const std::wstring& filePath) {
    std::wstring d = filePath;
    while (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
    const size_t slash = d.find_last_of(OBFW("XC8="));
    if (slash == std::wstring::npos) return true;
    return EnsureDirExists(util::LongPath(d.substr(0, slash)));
}

// 把内部条目名映射到目标目录；剥离前缀 "saves/" 或 "saves\\"
// 拒绝「..」以防穿越。isRoot = 内部名就是被剥离后的根（如 "saves/"）。
bool MapTarget(const std::wstring& targetDir, const std::string& nameUtf8,
               std::wstring& outPath, bool& isRoot) {
    std::wstring w = util::Utf8ToWide(nameUtf8);
    for (auto& c : w) if (c == L'/') c = L'\\';

    const std::wstring prefix = OBFW("c2F2ZXNc");
    if (w.size() >= prefix.size() && _wcsnicmp(w.c_str(), prefix.c_str(), prefix.size()) == 0)
        w = w.substr(prefix.size());

    isRoot = false;
    if (w.empty()) { isRoot = true; outPath = targetDir; return true; }

    std::vector<std::wstring> parts;
    size_t pos = 0;
    while (pos < w.size()) {
        const size_t slash = w.find_first_of(OBFW("XC8="), pos);
        const size_t end = (slash == std::wstring::npos) ? w.size() : slash;
        const std::wstring comp = w.substr(pos, end - pos);
        if (comp == OBFW("Li4=")) return false;            // 路径穿越，拒绝
        if (!comp.empty() && comp != OBFW("Lg==")) parts.push_back(comp);
        if (slash == std::wstring::npos) break;
        pos = slash + 1;
    }

    std::wstring base = targetDir;
    while (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) base.pop_back();

    std::wstring full = base;
    for (const auto& p : parts) { full += OBFW("XA=="); full += p; }
    outPath = full;
    return true;
}

// ===========================================================================
// 定位 EOCD
// ===========================================================================
bool FindEocd(HANDLE h, unsigned long long fileSize,
              uint32_t& cdOffset, uint32_t& cdSize, uint16_t& entryCount) {
    if (fileSize < 22) return false;
    const size_t tailCap = (size_t)std::min<unsigned long long>(fileSize, (unsigned long long)(22 + 65535));
    std::vector<uint8_t> tail(tailCap);
    if (!SeekTo(h, fileSize - tailCap)) return false;
    if (!ReadExact(h, tail.data(), tailCap)) return false;

    // 从尾部往前搜签名 0x06054B50（字节序 50 4B 05 06）
    for (size_t i = tailCap; i >= 4; --i) {
        const size_t p = i - 4;
        if (tail[p] == 0x50 && tail[p + 1] == 0x4B && tail[p + 2] == 0x05 && tail[p + 3] == 0x06) {
            const uint32_t csize  = LE32(&tail[p + 12]);
            const uint32_t coff   = LE32(&tail[p + 16]);
            const uint16_t ecnt   = LE16(&tail[p + 10]);
            if ((unsigned long long)coff + csize <= fileSize) {
                cdOffset = coff; cdSize = csize; entryCount = ecnt;
                return true;
            }
        }
    }
    return false;
}

struct CentEntry {
    uint16_t flags = 0;
    uint16_t method = 0;
    uint32_t crc = 0;
    uint32_t csize = 0;
    uint32_t usize = 0;
    uint32_t localOffset = 0;
    std::string nameUtf8;
};

} // namespace

// ===========================================================================
// 解压主流程
// ===========================================================================
ExtractResult ExtractEncryptedZip(const std::wstring& zipPath,
                                  const std::wstring& targetDir,
                                  const std::string& password) {
    ExtractResult res;

    HANDLE h = ::CreateFileW(util::LongPath(zipPath).c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        res.error = OBFW("5peg5rOV5omT5byA5Y6L57yp5YyF77ya") + zipPath;
        return res;
    }

    auto closeFile = [&]() { ::CloseHandle(h); };

    // ---- 文件大小 ----
    LARGE_INTEGER fsz{};
    if (!::GetFileSizeEx(h, &fsz)) { res.error = OBFW("6K+75Y+W5Y6L57yp5YyF5aSn5bCP5aSx6LSl"); closeFile(); return res; }
    const unsigned long long fileSize = (unsigned long long)fsz.QuadPart;

    // ---- 定位 EOCD ----
    uint32_t cdOffset = 0, cdSize = 0;
    uint16_t entryCount = 0;
    if (!FindEocd(h, fileSize, cdOffset, cdSize, entryCount)) {
        res.error = OBFW("5LiN5piv5pyJ5pWI55qEIFpJUCDmlofku7bvvIjmib7kuI3liLDnu5PlsL7orrDlvZXvvIk=");
        closeFile(); return res;
    }

    // ---- 读中央目录 ----
    if ((unsigned long long)cdOffset + cdSize > fileSize) {
        res.error = OBFW("5Y6L57yp5YyF57Si5byV6LaK55WM77yM5Y+v6IO95bey5o2f5Z2P");
        closeFile(); return res;
    }
    std::vector<uint8_t> cd(cdSize);
    if (!SeekTo(h, cdOffset) || !ReadExact(h, cd.data(), cdSize)) {
        res.error = OBFW("6K+75Y+W5Y6L57yp5YyF57Si5byV5aSx6LSl");
        closeFile(); return res;
    }

    // ---- 解析中央目录条目 ----
    std::vector<CentEntry> entries;
    entries.reserve(entryCount ? entryCount : 64);
    size_t pos = 0;
    while (pos + 46 <= cd.size()) {
        if (LE32(&cd[pos]) != 0x02014B50u) break;   // 中央目录头签名
        CentEntry e;
        e.flags       = LE16(&cd[pos + 8]);
        e.method      = LE16(&cd[pos + 10]);
        e.crc         = LE32(&cd[pos + 16]);
        e.csize       = LE32(&cd[pos + 20]);
        e.usize       = LE32(&cd[pos + 24]);
        const uint16_t nameLen  = LE16(&cd[pos + 28]);
        const uint16_t extraLen = LE16(&cd[pos + 30]);
        const uint16_t commLen  = LE16(&cd[pos + 32]);
        e.localOffset = LE32(&cd[pos + 42]);
        e.nameUtf8.assign((const char*)&cd[pos + 46], nameLen);

        entries.push_back(std::move(e));
        const size_t adv = 46u + (size_t)nameLen + extraLen + commLen;
        if (adv < 46) break;            // 防止回绕
        pos += adv;
    }

    // ---- 逐个条目解压 ----
    for (const auto& e : entries) {
        const bool isDir = (!e.nameUtf8.empty() && e.nameUtf8.back() == '/') ||
                           (e.csize == 0 && e.method == 0 && (e.flags & 0x0001) == 0);

        std::wstring outPath;
        bool isRoot = false;
        if (!MapTarget(targetDir, e.nameUtf8, outPath, isRoot)) {
            res.error = OBFW("5Y6L57yp5YyF5YaF5ZCr5pyJ6Z2e5rOV6Lev5b6E77yI55aR5Ly86Lev5b6E56m/6LaK77yJ77yM5bey5Lit5q2i6Kej5Y6L");
            closeFile(); return res;
        }

        if (isDir || isRoot) {
            if (outPath.empty()) outPath = targetDir;
            EnsureDirExists(util::LongPath(outPath));
            res.dirCount++;
            continue;
        }

        // ---- 文件条目：读本地文件头，定位数据起点 ----
        if ((unsigned long long)e.localOffset + 30 > fileSize) {
            res.error = OBFW("5pys5Zyw5paH5Lu25aS06LaK55WM77ya") + util::Utf8ToWide(e.nameUtf8);
            closeFile(); return res;
        }
        uint8_t lh[30];
        if (!SeekTo(h, e.localOffset) || !ReadExact(h, lh, 30)) {
            res.error = OBFW("6K+75Y+W5pys5Zyw5paH5Lu25aS05aSx6LSl77ya") + util::Utf8ToWide(e.nameUtf8);
            closeFile(); return res;
        }
        if (LE32(lh) != 0x04034B50u) {
            res.error = OBFW("5pys5Zyw5paH5Lu25aS0562+5ZCN6ZSZ6K+v77ya") + util::Utf8ToWide(e.nameUtf8);
            closeFile(); return res;
        }
        const uint16_t lNameLen  = LE16(&lh[26]);
        const uint16_t lExtraLen = LE16(&lh[28]);
        const unsigned long long dataStart = (unsigned long long)e.localOffset + 30 +
                                             (unsigned long long)lNameLen + (unsigned long long)lExtraLen;
        if (dataStart + e.csize > fileSize) {
            res.error = OBFW("5paH5Lu25pWw5o2u6LaK55WM77ya") + util::Utf8ToWide(e.nameUtf8);
            closeFile(); return res;
        }

        const bool encrypted = (e.flags & 0x0001) != 0;
        ZipCrypto crypto;
        if (encrypted) crypto.Init(password);

        if (e.method == 8) {
            // DEFLATE：整体读入再解密再解压
            std::vector<uint8_t> comp(e.csize);
            if (!SeekTo(h, dataStart) || !ReadExact(h, comp.data(), e.csize)) {
                res.error = OBFW("6K+75Y+W5Y6L57yp5pWw5o2u5aSx6LSl77ya") + util::Utf8ToWide(e.nameUtf8);
                closeFile(); return res;
            }
            if (encrypted) {
                crypto.Decrypt(comp.data(), e.csize);
                if (e.csize < 12 || comp[11] != (uint8_t)((e.crc >> 24) & 0xFF)) {
                    res.passwordWrong = true;
                    res.error = OBFW("5a+G56CB5LiN5q2j56Gu77yM5peg5rOV6Kej5a+G6K+l5Y6L57yp5YyF");
                    closeFile(); return res;
                }
            }
            const size_t off = encrypted ? 12 : 0;
            std::vector<uint8_t> plain;
            if (!inflate::Decompress(comp.data() + off, e.csize - off, plain)) {
                res.error = OBFW("6Kej5Y6L5aSx6LSl77yI5pWw5o2u5Y+v6IO95bey5o2f5Z2P77yJ77ya") + util::Utf8ToWide(e.nameUtf8);
                closeFile(); return res;
            }
            // 2026-08-06 修复：父目录创建与写文件分开判定。旧写法用 || 短路，父目录
            // 失败时 WriteWholeFile 根本不执行、werr 保持 0，误报「err=0 未知错误」
            // （实际是父目录创建被长路径前缀误伤，与真实写入错误无关）。
            if (!CreateParentDirs(outPath)) {
                res.error = OBFW("5Yib5bu655uu5b2V5aSx6LSl77ya") + outPath;
                closeFile(); return res;
            }
            DWORD werr = 0;
            if (!util::WriteWholeFile(outPath, plain.data(), plain.size(), &werr)) {
                wchar_t lenBuf[40]{};
                ::swprintf(lenBuf, 40, L" [路径长度=%llu]", (unsigned long long)outPath.size());
                res.error = OBFW("5YaZ5YWl5paH5Lu25aSx6LSl77ya") + outPath +
                            L" (err=" + std::to_wstring(werr) + L" " +
                            util::LastErrorText(werr) + L")" + lenBuf;
                closeFile(); return res;
            }
            res.writtenBytes += plain.size();
            res.fileCount++;

        } else if (e.method == 0) {
            // 存储型：流式读 + 解密 + 写
            if (!CreateParentDirs(outPath)) {
                res.error = OBFW("5Yib5bu655uu5b2V5aSx6LSl77ya") + outPath;
                closeFile(); return res;
            }
            // 2026-08-06 修复：目标文件若带「只读」属性（LoL 生成的缓存数据常如此），
            // CREATE_ALWAYS 会直接失败（err=5 拒绝访问）；且共享模式 0（独占）在文件被
            // 其它进程以共享方式打开时也会失败。这里写前先清掉只读等属性，并放宽共享
            // 模式（允许其它进程读/写/删本文件，对游戏缓存数据安全），从根上避免
            // 「解压写入失败」。2026-08-06 再修：路径走 LongPath 突破 260 上限（长路径是
            // 「手动能、程序不能」的根因），并把每次失败的 GetLastError 记录到 lastErr。
            const std::wstring lpOut = util::LongPath(outPath);
            ::SetFileAttributesW(lpOut.c_str(), FILE_ATTRIBUTE_NORMAL);
            HANDLE out = INVALID_HANDLE_VALUE;
            DWORD lastErr = 0;
            for (int attempt = 0; attempt < 4 && out == INVALID_HANDLE_VALUE; ++attempt) {
                if (attempt > 0) ::Sleep(300);   // 瞬时占用（杀毒/索引）等待后重试
                out = ::CreateFileW(lpOut.c_str(), GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                if (out == INVALID_HANDLE_VALUE) lastErr = ::GetLastError();
            }
            if (out == INVALID_HANDLE_VALUE) {
                // 5=拒绝访问(权限/只读)，32=被独占占用，112=磁盘满，206=路径超长
                wchar_t lenBuf[40]{};
                ::swprintf(lenBuf, 40, L" [路径长度=%llu]", (unsigned long long)outPath.size());
                res.error = OBFW("5YaZ5YWl5paH5Lu25aSx6LSl77ya") + outPath +
                            L" (err=" + std::to_wstring(lastErr) + L" " +
                            util::LastErrorText(lastErr) + L")" + lenBuf;
                closeFile(); return res;
            }

            bool ioOk = true;
            auto failWrite = [&]() {
                ioOk = false;
                res.error = OBFW("5YaZ5YWl5paH5Lu25aSx6LSl77ya") + outPath +
                            L" (err=" + std::to_wstring(::GetLastError()) + L")";
            };

            if (!SeekTo(h, dataStart)) { ::CloseHandle(out); closeFile(); return res; }

            if (encrypted) {
                uint8_t hdr[12];
                if (!ReadExact(h, hdr, 12)) { failWrite(); }
                else {
                    crypto.Decrypt(hdr, 12);
                    if (hdr[11] != (uint8_t)((e.crc >> 24) & 0xFF)) {
                        res.passwordWrong = true;
                        res.error = OBFW("5a+G56CB5LiN5q2j56Gu77yM5peg5rOV6Kej5a+G6K+l5Y6L57yp5YyF");
                        ioOk = false;
                    }
                }
            }

            unsigned long long remaining = e.csize - (encrypted ? 12 : 0);
            std::vector<uint8_t> buf(256 * 1024);
            while (ioOk && remaining > 0) {
                DWORD want = (DWORD)std::min<unsigned long long>(remaining, buf.size());
                if (!ReadExact(h, buf.data(), want)) { failWrite(); break; }
                if (encrypted) crypto.Decrypt(buf.data(), want);
                DWORD wrote = 0;
                if (!::WriteFile(out, buf.data(), want, &wrote, nullptr) || wrote != want) { failWrite(); break; }
                remaining -= wrote;
                res.writtenBytes += wrote;
            }
            ::CloseHandle(out);
            if (!ioOk) { closeFile(); return res; }
            res.fileCount++;

        } else {
            res.error = OBFW("5LiN5pSv5oyB55qE5Y6L57yp5pa55byP77yIbWV0aG9kPQ==") + std::to_wstring(e.method) + OBFW("77yJ77ya") +
                        util::Utf8ToWide(e.nameUtf8);
            closeFile(); return res;
        }
    }

    closeFile();
    res.ok = true;
    return res;
}

} // namespace zipr
