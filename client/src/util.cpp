#include "util.h"

#include <bcrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>   // 必须在 winsock2.h 之后，否则 IP_ADAPTER_ADDRESSES 等类型未定义
#include <cwctype>
#include <cstdio>
#include <ctime>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace util {

// ===========================================================================
// 编码
// ===========================================================================
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int need = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (need <= 0) return std::wstring();
    std::wstring out((size_t)need, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], need);
    return out;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return std::string();
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(),
                                           nullptr, 0, nullptr, nullptr);
    if (need <= 0) return std::string();
    std::string out((size_t)need, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], need, nullptr, nullptr);
    return out;
}

// ===========================================================================
// 字符串
// ===========================================================================
std::wstring Trim(const std::wstring& s) {
    size_t b = 0, e = s.size();
    auto isSpace = [](wchar_t c) {
        return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n' ||
               c == L'\v' || c == L'\f' || c == 0xFEFF /* BOM */;
    };
    while (b < e && isSpace(s[b])) ++b;
    while (e > b && isSpace(s[e - 1])) --e;
    return s.substr(b, e - b);
}

std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    for (auto& c : out) {
        if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
    }
    return out;
}

std::string ToLowerA(const std::string& s) {
    std::string out = s;
    for (auto& c : out) {
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    }
    return out;
}

bool EndsWithNoCase(const std::wstring& s, const std::wstring& suffix) {
    if (suffix.size() > s.size()) return false;
    const std::wstring tail = ToLower(s.substr(s.size() - suffix.size()));
    return tail == ToLower(suffix);
}

// ===========================================================================
// 路径 / 文件
// ===========================================================================
bool FileExists(const std::wstring& path) {
    if (path.empty()) return false;
    const DWORD a = ::GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool DirectoryExists(const std::wstring& path) {
    if (path.empty()) return false;
    const DWORD a = ::GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::wstring JoinPath(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;

    std::wstring left = a;
    while (!left.empty() && (left.back() == L'\\' || left.back() == L'/')) left.pop_back();

    size_t i = 0;
    while (i < b.size() && (b[i] == L'\\' || b[i] == L'/')) ++i;

    return left + OBFW("XA==") + b.substr(i);
}

std::wstring GetExeDir() {
    std::vector<wchar_t> buf(1024);
    for (;;) {
        const DWORD n = ::GetModuleFileNameW(nullptr, buf.data(), (DWORD)buf.size());
        if (n == 0) return std::wstring();
        if (n < buf.size() - 1) break;
        buf.resize(buf.size() * 2);
        if (buf.size() > 65536) return std::wstring();
    }
    std::wstring p(buf.data());
    const size_t pos = p.find_last_of(OBFW("XC8="));
    return pos == std::wstring::npos ? std::wstring() : p.substr(0, pos);
}

std::wstring GetTempDir() {
    wchar_t buf[MAX_PATH + 2]{};
    const DWORD n = ::GetTempPathW(MAX_PATH + 1, buf);
    if (n == 0 || n > MAX_PATH + 1) return OBFW("QzpcV2luZG93c1xUZW1w");
    std::wstring p(buf, n);
    while (!p.empty() && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
    return p.empty() ? std::wstring(OBFW("QzpcV2luZG93c1xUZW1w")) : p;
}

std::wstring NormalizePath(const std::wstring& path) {
    if (path.empty()) return path;
    wchar_t buf[4096]{};
    const DWORD n = ::GetFullPathNameW(path.c_str(), 4096, buf, nullptr);
    std::wstring p = (n > 0 && n < 4096) ? std::wstring(buf, n) : path;
    while (p.size() > 3 && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
    return p;
}

std::wstring LongPath(const std::wstring& path) {
    if (path.empty()) return path;
    // 已带 \\?\ 或 \\?\UNC\ 前缀：原样返回
    if (path.size() >= 4 && path[0] == L'\\' && path[1] == L'\\' &&
        path[2] == L'?' && path[3] == L'\\') {
        return path;
    }
    if (path.size() >= 8 && path.compare(0, 8, L"\\\\?\\UNC\\") == 0) return path;
    // UNC \\server\share -> \\?\UNC\server\share
    if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\') {
        return L"\\\\?\\UNC\\" + path.substr(2);
    }
    // 绝对路径 X:\... -> \\?\X:\...（仅当后面跟分隔符，避免误伤单字母文件名）
    if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
        return L"\\\\?\\" + path;
    }
    // 相对路径：保持原样（调用方应保证传绝对路径）
    return path;
}

bool ReadWholeFile(const std::wstring& path, std::vector<uint8_t>& out) {
    out.clear();

    HANDLE h = ::CreateFileW(util::LongPath(path).c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h, &size) || size.QuadPart < 0) {
        ::CloseHandle(h);
        return false;
    }
    // 单文件读取上限 64 MB，防止误读超大文件把内存吃光
    if (size.QuadPart > 64ll * 1024 * 1024) {
        ::CloseHandle(h);
        return false;
    }

    out.resize((size_t)size.QuadPart);
    size_t done = 0;
    bool ok = true;
    while (done < out.size()) {
        const DWORD want = (DWORD)((out.size() - done) > 0x100000 ? 0x100000 : (out.size() - done));
        DWORD got = 0;
        if (!::ReadFile(h, out.data() + done, want, &got, nullptr) || got == 0) {
            ok = (done == out.size());
            break;
        }
        done += got;
    }
    ::CloseHandle(h);
    if (!ok) out.clear();
    return ok;
}

bool WriteWholeFile(const std::wstring& path, const void* data, size_t bytes, DWORD* outErr) {
    // 2026-08-06 修复：目标文件若带「只读」属性（LoL 生成的缓存数据常如此），
    // CREATE_ALWAYS 会直接失败（err=5 拒绝访问）→ 解压报「写入文件失败」。
    // 写前清掉只读等属性，并放宽共享模式（允许其它进程读/写/删本文件）。
    // 另加 3 次重试：文件被瞬时占用（杀毒/索引/短锁）时自动重试自愈。
    // 2026-08-06 再修：路径走 LongPath 突破 260 上限（长路径是「手动能、程序不能」的根因），
    // 并把最后失败的 GetLastError 通过 outErr 返回，让上层错误文案带真实系统错误码。
    const std::wstring lp = util::LongPath(path);
    ::SetFileAttributesW(lp.c_str(), FILE_ATTRIBUTE_NORMAL);
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD lastErr = 0;
    for (int attempt = 0; attempt < 4 && h == INVALID_HANDLE_VALUE; ++attempt) {
        if (attempt > 0) ::Sleep(300);   // 瞬时占用（杀毒/索引）等待后重试
        h = ::CreateFileW(lp.c_str(), GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) lastErr = ::GetLastError();
    }
    if (h == INVALID_HANDLE_VALUE) {
        if (outErr) *outErr = lastErr;
        return false;
    }

    const uint8_t* p = (const uint8_t*)data;
    size_t done = 0;
    bool ok = true;
    while (done < bytes) {
        const DWORD want = (DWORD)((bytes - done) > 0x100000 ? 0x100000 : (bytes - done));
        DWORD wrote = 0;
        if (!::WriteFile(h, p + done, want, &wrote, nullptr) || wrote == 0) { ok = false; break; }
        done += wrote;
    }
    ::CloseHandle(h);
    return ok;
}

// ===========================================================================
// 随机
// ===========================================================================
void RandomBytes(void* buf, size_t n) {
    if (!buf || n == 0) return;

    const NTSTATUS st = ::BCryptGenRandom(nullptr, (PUCHAR)buf, (ULONG)n,
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st == STATUS_SUCCESS) return;

    // 退化方案：多源混合，够用即可（仅在系统 RNG 不可用时触发）
    uint8_t* p = (uint8_t*)buf;
    uint64_t s = 0;
    LARGE_INTEGER qpc{};
    ::QueryPerformanceCounter(&qpc);
    s ^= (uint64_t)qpc.QuadPart;
    s ^= (uint64_t)::GetTickCount64() << 17;
    s ^= (uint64_t)::GetCurrentProcessId() << 33;
    s ^= (uint64_t)::GetCurrentThreadId() << 7;
    s ^= (uint64_t)(uintptr_t)buf;
    if (s == 0) s = 0x9E3779B97F4A7C15ull;

    for (size_t i = 0; i < n; ++i) {
        // xorshift64*
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        const uint64_t v = s * 0x2545F4914F6CDD1Dull;
        p[i] = (uint8_t)(v >> 33);
    }
}

std::string GenerateRandomPassword(size_t length) {
    // 去掉 0 O o 1 l I 等易混淆字符，避免用户手抄出错
    static const char kAlphabet[] =
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "abcdefghijkmnpqrstuvwxyz"
        "23456789"
        "!@#%^&*-_=+";
    const size_t alphaLen = sizeof(kAlphabet) - 1;

    if (length < 8)  length = 8;
    if (length > 64) length = 64;

    std::vector<uint8_t> raw(length * 2);
    RandomBytes(raw.data(), raw.size());

    std::string out;
    out.reserve(length);

    // 拒绝采样，消除取模偏置
    const size_t limit = 256 - (256 % alphaLen);
    size_t idx = 0;
    while (out.size() < length) {
        if (idx >= raw.size()) {
            raw.resize(raw.size() + length);
            RandomBytes(raw.data() + idx, raw.size() - idx);
        }
        const uint8_t v = raw[idx++];
        if (v >= limit) continue;
        out.push_back(kAlphabet[v % alphaLen]);
    }
    return out;
}

// ===========================================================================
// 校验 / 网络
// ===========================================================================
bool IsValidPassword(const std::wstring& pwd) {
    const size_t n = pwd.size();
    if (n < 4 || n > 24) return false;
    for (wchar_t c : pwd) {
        const bool ok = (c >= L'A' && c <= L'Z') ||
                        (c >= L'a' && c <= L'z') ||
                        (c >= L'0' && c <= L'9');
        if (!ok) return false;
    }
    return true;
}

bool IsValidDownloadPassword(const std::wstring& pwd) {
    // 取回密码格式：SK- 开头 + 20 位字母数字（大小写 + 数字），合计 23 位。
    // 大小写均可识别：S 或 s、K 或 k，第 3 位必须是连字符（客户端已规范为大写，这里做兜底）。
    // 注意：上传密码规则（4-24 字母数字、不含连字符）天然与取回密码不重叠，
    // 因此即使不在这里显式拒绝 SK- 开头也能正确区分，但显式校验更稳妥。
    const size_t n = pwd.size();
    if (n != 23) return false;
    if ((pwd[0] != L'S' && pwd[0] != L's') ||
        (pwd[1] != L'K' && pwd[1] != L'k') ||
        (pwd[2] != L'-')) return false;
    for (size_t i = 3; i < n; ++i) {
        const wchar_t c = pwd[i];
        const bool ok = (c >= L'A' && c <= L'Z') ||
                        (c >= L'a' && c <= L'z') ||
                        (c >= L'0' && c <= L'9');
        if (!ok) return false;
    }
    return true;
}

std::wstring GetMachineIp() {
    // 优先取非回环、已连接的 IPv4；失败退回回环/未知
    std::wstring best;

    ULONG bufLen = 16384;
    std::vector<uint8_t> buf(bufLen);
    ULONG ret = ::GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &bufLen);

    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        ret = ::GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &bufLen);
    }

    if (ret == NO_ERROR) {
        for (auto* a = (IP_ADAPTER_ADDRESSES*)buf.data(); a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp) continue;
            for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                const auto* sa = (sockaddr_in*)ua->Address.lpSockaddr;
                const uint32_t ip = ntohl(sa->sin_addr.S_un.S_addr);
                // 跳过回环 127.* 和链路本地 169.254.*
                const uint8_t b0 = (uint8_t)(ip >> 24);
                if (b0 == 127 || b0 == 169) continue;
                wchar_t s[64]{};
                ::swprintf(s, 64, OBFW("JXUuJXUuJXUuJXU="),
                           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                           (ip >> 8) & 0xFF, ip & 0xFF);
                return std::wstring(s);
            }
        }
    }

    // 兜底：解析本机名
    wchar_t name[256]{};
    DWORD n = 256;
    if (::GetComputerNameW(name, &n)) {
        addrinfoW hints{};
        hints.ai_family = AF_INET;
        addrinfoW* res = nullptr;
        if (::GetAddrInfoW(name, nullptr, &hints, &res) == 0) {
            if (res) {
                const auto* sa = (sockaddr_in*)res->ai_addr;
                const uint32_t ip = ntohl(sa->sin_addr.S_un.S_addr);
                wchar_t s[64]{};
                ::swprintf(s, 64, OBFW("JXUuJXUuJXUuJXU="),
                           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                           (ip >> 8) & 0xFF, ip & 0xFF);
                best = s;
                ::FreeAddrInfoW(res);
            }
        }
    }
    return best.empty() ? OBFW("dW5rbm93bg==") : best;
}

// ===========================================================================
// 格式化
// ===========================================================================
std::wstring FormatSize(unsigned long long bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    double v = (double)bytes;
    int u = 0;
    while (v >= 1024.0 && u < 4) { v /= 1024.0; ++u; }

    wchar_t buf[64]{};
    if (u == 0) ::swprintf(buf, 64, OBFW("JWxsdSBC"), bytes);
    else        ::swprintf(buf, 64, OBFW("JS4yZiAlcw=="), v, units[u]);
    return buf;
}

std::wstring TimestampCompact() {
    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    wchar_t buf[32]{};
    ::swprintf(buf, 32, OBFW("JTA0dSUwMnUlMDJ1XyUwMnUlMDJ1JTAydQ=="),
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring MachineId() {
    // 机器名 + 用户名做 FNV-1a，只用于区分不同机器的上传，不含隐私信息
    wchar_t name[256]{};
    DWORD n = 256;
    if (!::GetComputerNameW(name, &n)) { wcscpy_s(name, OBFW("dW5rbm93bg==")); }

    wchar_t user[256]{};
    DWORD un = 256;
    if (!::GetUserNameW(user, &un)) { wcscpy_s(user, OBFW("dXNlcg==")); }

    std::wstring src = std::wstring(name) + OBFW("fA==") + user;

    uint32_t h = 2166136261u;
    for (wchar_t c : src) {
        h ^= (uint32_t)(c & 0xFF);
        h *= 16777619u;
        h ^= (uint32_t)((c >> 8) & 0xFF);
        h *= 16777619u;
    }

    wchar_t buf[16]{};
    ::swprintf(buf, 16, OBFW("JTA4eA=="), h);
    return buf;
}

// ===========================================================================
// 系统
// ===========================================================================
std::wstring LastErrorText(DWORD code) {
    if (code == 0) return OBFW("5pyq55+l6ZSZ6K+v");

    LPWSTR msg = nullptr;
    const DWORD n = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&msg, 0, nullptr);

    std::wstring text;
    if (n && msg) {
        text = util::Trim(std::wstring(msg, n));
    }
    if (msg) ::LocalFree(msg);

    wchar_t code_s[32]{};
    ::swprintf(code_s, 32, OBFW("KDB4JTA4WCk="), (unsigned)code);

    if (text.empty()) return std::wstring(OBFW("57O757uf6ZSZ6K+vIA==")) + code_s;
    return text + OBFW("IA==") + code_s;
}

bool CopyTextToClipboard(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) return false;

    bool ok = false;
    if (::EmptyClipboard()) {
        const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
        HGLOBAL mem = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (mem) {
            void* p = ::GlobalLock(mem);
            if (p) {
                ::memcpy(p, text.c_str(), bytes);
                ::GlobalUnlock(mem);
                if (::SetClipboardData(CF_UNICODETEXT, mem)) {
                    ok = true;          // 所有权已交给系统，不能再 Free
                } else {
                    ::GlobalFree(mem);
                }
            } else {
                ::GlobalFree(mem);
            }
        }
    }
    ::CloseClipboard();
    return ok;
}

} // namespace util

// ===========================================================================
// 轻量字符串混淆运行库（obf）—— base64 解码，纯数据解密，非 SMC
// ===========================================================================
namespace obf {

// 标准 base64 解码表（遇 '=' 或非法字符停止）
static const int kB64Inv[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static void DecodeB64(const char* s, std::string& out) {
    out.clear();
    int acc = 0, bits = 0;
    for (const char* p = s; *p; ++p) {
        const int v = (unsigned char)(*p) < 256 ? kB64Inv[(unsigned char)(*p)] : -1;
        if (v < 0) {
            if (*p == '=') break;
            continue;   // 跳过空白等无关字符
        }
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((acc >> bits) & 0xFF));
        }
    }
}

// 旋转缓冲，避免同一表达式里连续 OBFW/OBFA 互相覆盖。
// 2026-08-06 关键：槽数从 8 扩到 32——BuildDone 连续 ~26 次 obf 调用会覆盖 8 槽导致
// JSON 字段错位/重复/缺失（槽 0 第 1 次 WBool=true 被第 9 次 OBFW 覆盖）。32 槽足够
// 任何长 + 链（且 `+` 求值时立即复制当前指针到临时 wstring，槽覆盖后复制的内容已在
// 临时对象里，不影响最终结果——前提是当前指针被读时还没被覆盖）。
static thread_local std::string  g_bufA[32];
static thread_local std::wstring g_bufW[32];
static thread_local unsigned     g_idx = 0;

const char* a(const char* b64) {
    std::string& buf = g_bufA[(g_idx++) & 31];
    DecodeB64(b64, buf);
    return buf.c_str();
}

const wchar_t* w(const char* b64) {
    std::wstring& buf = g_bufW[(g_idx++) & 31];
    std::string bytes;
    DecodeB64(b64, bytes);
    if (bytes.empty()) { buf.clear(); return buf.c_str(); }
    const int need = ::MultiByteToWideChar(CP_UTF8, 0, bytes.data(), (int)bytes.size(),
                                           nullptr, 0);
    buf.resize(need > 0 ? (size_t)need : 0);
    if (need > 0) {
        ::MultiByteToWideChar(CP_UTF8, 0, bytes.data(), (int)bytes.size(),
                               &buf[0], need);
    }
    return buf.c_str();
}

} // namespace obf
