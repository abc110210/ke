#include "zip_writer.h"
#include "deflate.h"
#include "util.h"

#include <algorithm>

namespace zipw {

// ===========================================================================
// ZipCrypto（传统 PKWARE 加密）
// ===========================================================================
class ZipCrypto {
public:
    void Init(const std::string& password) {
        k0_ = 0x12345678u;
        k1_ = 0x23456789u;
        k2_ = 0x34567890u;
        for (unsigned char c : password) UpdateKeys(c);
    }

    // 就地加密：buf 传入明文，返回时变为密文
    void Encrypt(uint8_t* buf, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            const uint8_t plain = buf[i];
            buf[i] = (uint8_t)(plain ^ StreamByte());
            UpdateKeys(plain);
        }
    }

private:
    void UpdateKeys(uint8_t c) {
        k0_ = deflate::Crc32Step(k0_, c);
        k1_ = k1_ + (k0_ & 0xFFu);
        k1_ = k1_ * 134775813u + 1u;
        k2_ = deflate::Crc32Step(k2_, (uint8_t)(k1_ >> 24));
    }

    uint8_t StreamByte() const {
        const uint16_t t = (uint16_t)((k2_ & 0xFFFFu) | 2u);
        return (uint8_t)(((t * (t ^ 1u)) >> 8) & 0xFFu);
    }

    uint32_t k0_ = 0, k1_ = 0, k2_ = 0;
};

// ===========================================================================
// 小工具
// ===========================================================================
static void PutU16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((uint8_t)(x & 0xFF));
    v.push_back((uint8_t)((x >> 8) & 0xFF));
}
static void PutU32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((uint8_t)(x & 0xFF));
    v.push_back((uint8_t)((x >> 8) & 0xFF));
    v.push_back((uint8_t)((x >> 16) & 0xFF));
    v.push_back((uint8_t)((x >> 24) & 0xFF));
}

static void FileTimeToDos(const FILETIME& ft, uint16_t& dosDate, uint16_t& dosTime) {
    FILETIME local{};
    WORD d = 0, t = 0;
    if (::FileTimeToLocalFileTime(&ft, &local) && ::FileTimeToDosDateTime(&local, &d, &t)) {
        dosDate = d;
        dosTime = t;
        return;
    }
    // 兜底：1980-01-01 00:00:00
    dosDate = 0x0021;
    dosTime = 0x0000;
}

class FileWriter {
public:
    bool Open(const std::wstring& path) {
        h_ = ::CreateFileW(util::LongPath(path).c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        return h_ != INVALID_HANDLE_VALUE;
    }
    void Close() {
        if (h_ != INVALID_HANDLE_VALUE) { ::CloseHandle(h_); h_ = INVALID_HANDLE_VALUE; }
    }
    ~FileWriter() { Close(); }

    bool Write(const void* data, size_t len) {
        const uint8_t* p = (const uint8_t*)data;
        size_t left = len;
        while (left > 0) {
            DWORD chunk = (DWORD)(left > (1u << 20) ? (1u << 20) : left);
            DWORD wrote = 0;
            if (!::WriteFile(h_, p, chunk, &wrote, nullptr) || wrote == 0) return false;
            p += wrote; left -= wrote; pos_ += wrote;
        }
        return true;
    }
    bool Write(const std::vector<uint8_t>& v) { return v.empty() ? true : Write(v.data(), v.size()); }

    unsigned long long Pos() const { return pos_; }

private:
    HANDLE             h_ = INVALID_HANDLE_VALUE;
    unsigned long long pos_ = 0;
};

// ===========================================================================
// 目录扫描
// ===========================================================================
static void ScanRecursive(const std::wstring& dirAbs,
                          const std::wstring& relInZip,
                          std::vector<Entry>& out,
                          ScanResult& res,
                          const std::atomic<bool>* cancel,
                          int depth) {
    if (depth > 32) return;
    if (cancel && cancel->load()) return;

    // 使用 \\?\ 前缀突破 260 字符路径限制
    std::wstring pattern = dirAbs;
    if (!pattern.empty() && pattern.back() != L'\\') pattern += L'\\';
    pattern += L'*';

    WIN32_FIND_DATAW fd{};
    HANDLE h = ::FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd,
                                  FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (cancel && cancel->load()) break;

        const std::wstring name = fd.cFileName;
        if (name == OBFW("Lg==") || name == OBFW("Li4=")) continue;

        // 跳过重解析点（符号链接 / junction），避免死循环
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        const std::wstring childAbs = util::JoinPath(dirAbs, name);
        const std::wstring childRel = relInZip.empty() ? name : (relInZip + OBFW("Lw==") + name);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            Entry e;
            e.fullPath  = childAbs;
            e.nameInZip = childRel + OBFW("Lw==");
            e.isDir     = true;
            e.mtime     = fd.ftLastWriteTime;
            e.attrs     = fd.dwFileAttributes;
            out.push_back(e);
            res.dirCount++;
            ScanRecursive(childAbs, childRel, out, res, cancel, depth + 1);
        } else {
            ULARGE_INTEGER sz{};
            sz.LowPart  = fd.nFileSizeLow;
            sz.HighPart = fd.nFileSizeHigh;

            Entry e;
            e.fullPath  = childAbs;
            e.nameInZip = childRel;
            e.size      = sz.QuadPart;
            e.isDir     = false;
            e.mtime     = fd.ftLastWriteTime;
            e.attrs     = fd.dwFileAttributes;
            out.push_back(e);
            res.fileCount++;
            res.totalBytes += sz.QuadPart;
        }
    } while (::FindNextFileW(h, &fd));

    ::FindClose(h);
}

ScanResult ScanDirectory(const std::wstring& root,
                         const std::wstring& rootAliasInZip,
                         std::vector<Entry>& out,
                         const std::atomic<bool>* cancel) {
    ScanResult res;
    out.clear();

    // 长路径：扫描源头目录若本身很长（深层子目录），FindFirstFileExW 会受 260 限制漏文件。
    // 统一加 \\?\ 前缀，让扫描也支持长路径（与解压端一致）。
    const std::wstring rootLP = util::LongPath(root);
    if (!util::DirectoryExists(rootLP)) {
        res.error = OBFW("55uu5b2V5LiN5a2Y5Zyo77ya") + root;
        return res;
    }

    // 顶层目录项
    if (!rootAliasInZip.empty()) {
        Entry e;
            e.fullPath  = rootLP;
            e.nameInZip = rootAliasInZip + OBFW("Lw==");
        e.isDir     = true;
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (::GetFileAttributesExW(root.c_str(), GetFileExInfoStandard, &fad))
            e.mtime = fad.ftLastWriteTime;
        out.push_back(e);
        res.dirCount++;
    }

    ScanRecursive(rootLP, rootAliasInZip, out, res, cancel, 0);

    if (cancel && cancel->load()) {
        res.error = OBFW("5bey5Y+W5raI");
        return res;
    }

    res.ok = true;
    return res;
}

// ===========================================================================
// 打包
// ===========================================================================
static const size_t kInMemoryLimit = 32u * 1024 * 1024;   // 超过则改用「存储+两遍扫描」

struct CentralRecord {
    std::string        nameUtf8;
    uint16_t           flags = 0;
    uint16_t           method = 0;
    uint16_t           dosTime = 0, dosDate = 0;
    uint32_t           crc = 0;
    uint32_t           csize = 0;
    uint32_t           usize = 0;
    uint32_t           attrs = 0;
    unsigned long long localOffset = 0;
};

// 读取整个文件（小文件路径）
static bool ReadAll(const std::wstring& path, std::vector<uint8_t>& buf) {
    return util::ReadWholeFile(path, buf);
}

// 大文件：先算 CRC
static bool ComputeCrcStreaming(const std::wstring& path, uint32_t& crcOut,
                                unsigned long long& sizeOut,
                                const std::atomic<bool>* cancel) {
    HANDLE h = ::CreateFileW(util::LongPath(path).c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    std::vector<uint8_t> buf(1u << 20);
    uint32_t crc = 0;
    unsigned long long total = 0;
    for (;;) {
        if (cancel && cancel->load()) { ::CloseHandle(h); return false; }
        DWORD got = 0;
        if (!::ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr)) { ::CloseHandle(h); return false; }
        if (got == 0) break;
        crc = deflate::Crc32(crc, buf.data(), got);
        total += got;
    }
    ::CloseHandle(h);
    crcOut  = crc;
    sizeOut = total;
    return true;
}

PackResult CreateEncryptedZip(const std::wstring& outPath,
                              const std::vector<Entry>& entries,
                              const std::string& password,
                              const ProgressFn& progress,
                              const std::atomic<bool>* cancel) {
    PackResult res;

    if (password.empty()) { res.error = OBFW("5Y6L57yp5a+G56CB5Li656m6"); return res; }
    if (entries.empty())  { res.error = OBFW("5rKh5pyJ6ZyA6KaB5omT5YyF55qE5YaF5a65"); return res; }
    if (entries.size() > 65000) {
        res.error = OBFW("5paH5Lu25pWw6YeP6LaF6L+HIDY1MDAw77yM6LaF5Ye65Lyg57ufIFpJUCDkuIrpmZA=");
        return res;
    }

    unsigned long long totalRaw = 0;
    for (const auto& e : entries) if (!e.isDir) totalRaw += e.size;

    FileWriter fw;
    if (!fw.Open(outPath)) {
        res.error = OBFW("5peg5rOV5Yib5bu65Li05pe25Y6L57yp5YyF77ya") + util::LastErrorText(::GetLastError());
        return res;
    }

    std::vector<CentralRecord> central;
    central.reserve(entries.size());

    unsigned long long done = 0;
    auto report = [&](const std::wstring& cur) -> bool {
        if (cancel && cancel->load()) return false;
        if (progress) return progress(done, totalRaw, cur);
        return true;
    };

    std::vector<uint8_t> header;   // 复用缓冲，减少分配

    for (const auto& e : entries) {
        if (!report(e.nameInZip)) { res.error = OBFW("5bey5Y+W5raI"); return res; }

        const std::string nameUtf8 = util::WideToUtf8(e.nameInZip);
        if (nameUtf8.size() > 60000) { res.skipped++; continue; }

        uint16_t dosDate = 0, dosTime = 0;
        FileTimeToDos(e.mtime, dosDate, dosTime);

        CentralRecord cr;
        cr.nameUtf8    = nameUtf8;
        cr.dosDate     = dosDate;
        cr.dosTime     = dosTime;
        cr.attrs       = e.attrs;
        cr.localOffset = fw.Pos();

        if (cr.localOffset > 0xFFFFFFF0ull) {
            res.error = OBFW("5Y6L57yp5YyF6LaF6L+HIDRHQu+8jOS8oOe7nyBaSVAg5peg5rOV5om/6L2977yM6K+35YeP5bCR5omT5YyF5YaF5a65");
            return res;
        }

        // ---------------- 目录项：不加密、不压缩、长度 0 ----------------
        if (e.isDir) {
            cr.flags  = 0x0800;      // 仅标记文件名为 UTF-8
            cr.method = 0;
            cr.crc = 0; cr.csize = 0; cr.usize = 0;

            header.clear();
            PutU32(header, 0x04034B50u);
            PutU16(header, 20);
            PutU16(header, cr.flags);
            PutU16(header, cr.method);
            PutU16(header, cr.dosTime);
            PutU16(header, cr.dosDate);
            PutU32(header, 0);
            PutU32(header, 0);
            PutU32(header, 0);
            PutU16(header, (uint16_t)nameUtf8.size());
            PutU16(header, 0);
            header.insert(header.end(), nameUtf8.begin(), nameUtf8.end());
            if (!fw.Write(header)) { res.error = OBFW("5YaZ5YWl5Y6L57yp5YyF5aSx6LSl"); return res; }

            central.push_back(cr);
            continue;
        }

        // ---------------- 文件项 ----------------
        cr.flags = 0x0001 | 0x0800;   // bit0 = 已加密，bit11 = 文件名 UTF-8

        if (e.size > 0xFFFFFFF0ull) {
            res.error = OBFW("5a2Y5Zyo6LaF6L+HIDRHQiDnmoTljZXkuKrmlofku7bvvIzml6Dms5XmiZPljIXvvJo=") + e.nameInZip;
            return res;
        }

        std::vector<uint8_t> raw;
        std::vector<uint8_t> comp;
        uint32_t crc = 0;
        bool     useStreaming = (e.size > kInMemoryLimit);
        unsigned long long realSize = e.size;

        if (!useStreaming) {
            if (!ReadAll(e.fullPath, raw)) {
                res.skipped++;
                continue;                       // 文件被占用/无权限 -> 跳过，不中断整体流程
            }
            realSize = raw.size();
            crc      = deflate::Crc32(raw.data(), raw.size());
            comp     = deflate::Compress(raw.data(), raw.size(), 6);

            // 若 deflate 结果反而更大，退回存储
            if (comp.size() >= raw.size() + 8) {
                cr.method = 0;
                comp      = raw;
            } else {
                cr.method = 8;
            }
        } else {
            if (!ComputeCrcStreaming(e.fullPath, crc, realSize, cancel)) {
                if (cancel && cancel->load()) { res.error = OBFW("5bey5Y+W5raI"); return res; }
                res.skipped++;
                continue;
            }
            cr.method = 0;   // 大文件直接存储，避免占用大量内存
        }

        cr.crc   = crc;
        cr.usize = (uint32_t)realSize;

        const uint32_t payload = useStreaming ? (uint32_t)realSize : (uint32_t)comp.size();
        cr.csize = payload + 12;    // 12 字节加密头

        // 本地文件头
        header.clear();
        PutU32(header, 0x04034B50u);
        PutU16(header, 20);
        PutU16(header, cr.flags);
        PutU16(header, cr.method);
        PutU16(header, cr.dosTime);
        PutU16(header, cr.dosDate);
        PutU32(header, cr.crc);
        PutU32(header, cr.csize);
        PutU32(header, cr.usize);
        PutU16(header, (uint16_t)nameUtf8.size());
        PutU16(header, 0);
        header.insert(header.end(), nameUtf8.begin(), nameUtf8.end());
        if (!fw.Write(header)) { res.error = OBFW("5YaZ5YWl5Y6L57yp5YyF5aSx6LSl"); return res; }

        // 加密头：11 字节随机 + 1 字节校验（取 CRC 最高字节）
        ZipCrypto cipher;
        cipher.Init(password);

        uint8_t encHeader[12];
        util::RandomBytes(encHeader, 11);
        encHeader[11] = (uint8_t)((crc >> 24) & 0xFF);
        cipher.Encrypt(encHeader, 12);
        if (!fw.Write(encHeader, 12)) { res.error = OBFW("5YaZ5YWl5Y6L57yp5YyF5aSx6LSl"); return res; }

        if (!useStreaming) {
            if (!comp.empty()) {
                cipher.Encrypt(comp.data(), comp.size());
                if (!fw.Write(comp.data(), comp.size())) { res.error = OBFW("5YaZ5YWl5Y6L57yp5YyF5aSx6LSl"); return res; }
            }
            done += realSize;
        } else {
            HANDLE h = ::CreateFileW(util::LongPath(e.fullPath).c_str(), GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     nullptr, OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h == INVALID_HANDLE_VALUE) { res.error = OBFW("6K+75Y+W5paH5Lu25aSx6LSl77ya") + e.nameInZip; return res; }

            std::vector<uint8_t> buf(1u << 20);
            unsigned long long wrote = 0;
            bool ioOk = true;
            while (wrote < realSize) {
                if (!report(e.nameInZip)) { ::CloseHandle(h); res.error = OBFW("5bey5Y+W5raI"); return res; }
                DWORD got = 0;
                if (!::ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr) || got == 0) { ioOk = false; break; }
                if (wrote + got > realSize) got = (DWORD)(realSize - wrote);
                cipher.Encrypt(buf.data(), got);
                if (!fw.Write(buf.data(), got)) { ioOk = false; break; }
                wrote += got;
                done  += got;
            }
            ::CloseHandle(h);
            if (!ioOk || wrote != realSize) { res.error = OBFW("6K+75Y+W5paH5Lu25Lit6YCU5aSx6LSl77ya") + e.nameInZip; return res; }
        }

        central.push_back(cr);
        res.fileCount++;
    }

    if (!report(OBFW("5q2j5Zyo55Sf5oiQ57Si5byV"))) { res.error = OBFW("5bey5Y+W5raI"); return res; }

    // ---------------- 中央目录 ----------------
    const unsigned long long cdOffset = fw.Pos();
    std::vector<uint8_t> cd;
    cd.reserve(central.size() * 64);

    for (const auto& cr : central) {
        PutU32(cd, 0x02014B50u);
        PutU16(cd, 20);                    // version made by（MS-DOS/FAT）
        PutU16(cd, 20);                    // version needed
        PutU16(cd, cr.flags);
        PutU16(cd, cr.method);
        PutU16(cd, cr.dosTime);
        PutU16(cd, cr.dosDate);
        PutU32(cd, cr.crc);
        PutU32(cd, cr.csize);
        PutU32(cd, cr.usize);
        PutU16(cd, (uint16_t)cr.nameUtf8.size());
        PutU16(cd, 0);                     // extra len
        PutU16(cd, 0);                     // comment len
        PutU16(cd, 0);                     // disk number
        PutU16(cd, 0);                     // internal attrs
        PutU32(cd, cr.attrs);              // external attrs
        PutU32(cd, (uint32_t)cr.localOffset);
        cd.insert(cd.end(), cr.nameUtf8.begin(), cr.nameUtf8.end());
    }
    if (!fw.Write(cd)) { res.error = OBFW("5YaZ5YWl5Lit5aSu55uu5b2V5aSx6LSl"); return res; }

    const unsigned long long cdSize = cd.size();
    if (cdOffset > 0xFFFFFFF0ull) {
        res.error = OBFW("5Y6L57yp5YyF6LaF6L+HIDRHQu+8jOaXoOazleeUn+aIkOacieaViOe0ouW8lQ==");
        return res;
    }

    std::vector<uint8_t> eocd;
    PutU32(eocd, 0x06054B50u);
    PutU16(eocd, 0);
    PutU16(eocd, 0);
    PutU16(eocd, (uint16_t)central.size());
    PutU16(eocd, (uint16_t)central.size());
    PutU32(eocd, (uint32_t)cdSize);
    PutU32(eocd, (uint32_t)cdOffset);
    PutU16(eocd, 0);
    if (!fw.Write(eocd)) { res.error = OBFW("5YaZ5YWl57uT5bC+6K6w5b2V5aSx6LSl"); return res; }

    res.zipBytes = fw.Pos();
    res.rawBytes = totalRaw;
    fw.Close();

    res.ok = true;
    return res;
}

} // namespace zipw
