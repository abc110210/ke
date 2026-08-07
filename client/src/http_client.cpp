#include "http_client.h"
#include "config.h"
#include "util.h"

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

// 部分旧 Windows SDK 的 winhttp.h 没暴露这两个 HTTP 协议协商常量，这里兜底定义。
// WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL 取值 0x0058，WINHTTP_PROTOCOL_FLAG_HTTP1 = 0x1。
#ifndef WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
#define WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL 0x0058
#endif
#ifndef WINHTTP_PROTOCOL_FLAG_HTTP1
#define WINHTTP_PROTOCOL_FLAG_HTTP1 0x00000001
#endif

namespace http {

// ===========================================================================
// RAII 句柄
// ===========================================================================
namespace {

class WinHttpHandle {
public:
    WinHttpHandle() = default;
    explicit WinHttpHandle(HINTERNET h) : h_(h) {}
    ~WinHttpHandle() { if (h_) ::WinHttpCloseHandle(h_); }

    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;

    WinHttpHandle& operator=(HINTERNET h) {
        if (h_) ::WinHttpCloseHandle(h_);
        h_ = h;
        return *this;
    }
    operator HINTERNET() const { return h_; }
    bool Valid() const { return h_ != nullptr; }

private:
    HINTERNET h_ = nullptr;
};

struct UrlParts {
    std::wstring host;
    INTERNET_PORT port = 80;
    std::wstring pathWithQuery;
    bool secure = false;
    bool ok = false;
};

UrlParts CrackUrl(const std::wstring& url) {
    UrlParts p;

    URL_COMPONENTS uc{};
    uc.dwStructSize      = sizeof(uc);
    uc.dwSchemeLength    = (DWORD)-1;
    uc.dwHostNameLength  = (DWORD)-1;
    uc.dwUrlPathLength   = (DWORD)-1;
    uc.dwExtraInfoLength = (DWORD)-1;

    if (!::WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) return p;

    p.host   = std::wstring(uc.lpszHostName, uc.dwHostNameLength);
    p.port   = uc.nPort;
    p.secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);

    std::wstring path  = uc.dwUrlPathLength   ? std::wstring(uc.lpszUrlPath, uc.dwUrlPathLength)     : OBFW("Lw==");
    std::wstring extra = uc.dwExtraInfoLength ? std::wstring(uc.lpszExtraInfo, uc.dwExtraInfoLength) : L"";
    if (path.empty()) path = OBFW("Lw==");
    p.pathWithQuery = path + extra;
    p.ok = true;
    return p;
}

std::wstring BuildHeaderBlock(const std::vector<Header>& headers) {
    std::wstring out;
    for (const auto& h : headers) {
        if (h.first.empty()) continue;
        out += h.first;
        out += OBFW("OiA=");
        out += h.second;
        out += OBFW("DQo=");
    }
    return out;
}

bool ReadResponseBody(HINTERNET hRequest, std::string& body, std::wstring& err) {
    body.clear();
    for (;;) {
        DWORD avail = 0;
        if (!::WinHttpQueryDataAvailable(hRequest, &avail)) {
            err = OBFW("6K+75Y+W5ZON5bqU5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
            return false;
        }
        if (avail == 0) break;
        if (body.size() + avail > (32u * 1024 * 1024)) {
            err = OBFW("5ZON5bqU5YaF5a656L+H5aSn");
            return false;
        }

        const size_t old = body.size();
        body.resize(old + avail);
        DWORD read = 0;
        if (!::WinHttpReadData(hRequest, &body[old], avail, &read)) {
            err = OBFW("6K+75Y+W5ZON5bqU5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
            return false;
        }
        body.resize(old + read);
        if (read == 0) break;
    }
    return true;
}

int QueryStatus(HINTERNET hRequest) {
    DWORD status = 0;
    DWORD sz = sizeof(status);
    if (::WinHttpQueryHeaders(hRequest,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz,
                              WINHTTP_NO_HEADER_INDEX)) {
        return (int)status;
    }
    return 0;
}

// 打开 session / connect / request 三件套
bool OpenChain(const UrlParts& parts,
               const std::wstring& method,
               const Timeouts& to,
               WinHttpHandle& session,
               WinHttpHandle& connect,
               WinHttpHandle& request,
               std::wstring& err) {
    session = ::WinHttpOpen(secrets::app_ua().c_str(),
                            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session.Valid()) {
        // 老系统不支持 AUTOMATIC_PROXY，退回默认代理配置
        session = ::WinHttpOpen(secrets::app_ua().c_str(),
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!session.Valid()) {
        err = OBFW("5Yid5aeL5YyW572R57uc5Lya6K+d5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return false;
    }

    ::WinHttpSetTimeouts(session, to.connectMs, to.connectMs, to.sendMs, to.recvMs);

    connect = ::WinHttpConnect(session, parts.host.c_str(), parts.port, 0);
    if (!connect.Valid()) {
        err = OBFW("6L+e5o6l5pyN5Yqh5Zmo5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return false;
    }

    const DWORD flags = parts.secure ? WINHTTP_FLAG_SECURE : 0;
    request = ::WinHttpOpenRequest(connect, method.c_str(), parts.pathWithQuery.c_str(),
                                   nullptr, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request.Valid()) {
        err = OBFW("5Yib5bu66K+35rGC5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return false;
    }

    // 禁用 keep-alive：每次请求都新建连接，避免「重新上传时偶发 multipart
    // 截断 / NextPart: EOF」。长连接复用遇到上一次中断的半截响应时会把连接搞脏，
    // 七牛按 Content-Length 读完却发现 body 提前 EOF，直接 400 拒绝。
    // 本应用请求频率极低，新建连接的握手开销可忽略。
    DWORD disableFeature = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_KEEP_ALIVE;
    ::WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disableFeature, sizeof(disableFeature));

    // 强制走 HTTP/1.1：CF 隧道「客户端↔边缘」常为 HTTP/2，而上面禁用了 keep-alive、
    // 发了 Connection: close。HTTP/2 下 Connection 头无意义、响应流不会因 close 结束，
    // 会和 WinHTTP 的收包循环冲突，偶发丢掉前几个响应——表现就是 /api/report 收不到、
    // 20s 超时后重试、再超时（重复登记）。退回 HTTP/1.1 后每条请求独立连接，响应随连接
    // 关闭自然结束，收包稳定。实测 upload-token 能收到、report 收不到，正是这种「同隧道
    // 前几个流被丢」的特征（第 3 次撞 429 反而秒回，因为那是独立的新流）。
    DWORD httpProto = WINHTTP_PROTOCOL_FLAG_HTTP1;
    ::WinHttpSetOption(request, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &httpProto, sizeof(httpProto));

    return true;
}

} // namespace

// ===========================================================================
// 普通请求
// ===========================================================================
Response Request(const std::wstring& method,
                 const std::wstring& url,
                 const std::string&  body,
                 const std::vector<Header>& headers,
                 const Timeouts& to) {
    Response res;

    const UrlParts parts = CrackUrl(url);
    if (!parts.ok) {
        // 不回显 url：错误信息会显示到界面日志里，避免暴露服务端地址。
        res.error = OBFW("6K+35rGC5Zyw5Z2A5qC85byP5LiN5q2j56Gu");
        return res;
    }

    WinHttpHandle session, connect, request;
    if (!OpenChain(parts, method, to, session, connect, request, res.error)) return res;

    const std::wstring hdr = BuildHeaderBlock(headers);

    BOOL sent = ::WinHttpSendRequest(
        request,
        hdr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdr.c_str(),
        hdr.empty() ? 0 : (DWORD)-1,
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
        (DWORD)body.size(),
        (DWORD)body.size(),
        0);

    if (!sent) {
        res.error = OBFW("5Y+R6YCB6K+35rGC5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return res;
    }

    if (!::WinHttpReceiveResponse(request, nullptr)) {
        res.error = OBFW("5o6l5pS25ZON5bqU5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return res;
    }

    res.status = QueryStatus(request);
    if (!ReadResponseBody(request, res.body, res.error)) return res;

    res.ok = true;
    return res;
}

// ===========================================================================
// multipart 上传
// ===========================================================================
Response UploadMultipartFile(const std::wstring& url,
                             const std::vector<std::pair<std::string, std::string>>& fields,
                             const std::string& fileFieldName,
                             const std::string& fileNameInForm,
                             const std::wstring& localFilePath,
                             const std::vector<Header>& headers,
                             const Timeouts& to,
                             const UploadProgressFn& progress,
                             const std::atomic<bool>* cancel) {
    Response res;

    // ---- 文件大小 ----
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!::GetFileAttributesExW(localFilePath.c_str(), GetFileExInfoStandard, &fad)) {
        res.error = OBFW("5b6F5LiK5Lyg5paH5Lu25LiN5a2Y5Zyo");
        return res;
    }
    ULARGE_INTEGER fileSize{};
    fileSize.LowPart  = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;

    // ---- 生成 boundary ----
    uint8_t rnd[16]{};
    util::RandomBytes(rnd, sizeof(rnd));
    std::string boundary = OBFA("LS0tLUhhbmJvdFVwbG9hZGVy");
    {
        static const char* hex = OBFA("MDEyMzQ1Njc4OWFiY2RlZg==");
        for (unsigned char c : rnd) {
            boundary.push_back(hex[(c >> 4) & 0xF]);
            boundary.push_back(hex[c & 0xF]);
        }
    }

    // ---- 拼装前后段 ----
    std::string prologue;
    for (const auto& kv : fields) {
        prologue += OBFA("LS0=") + boundary + OBFA("DQo=");
        prologue += OBFA("Q29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSI=") + kv.first + OBFA("Ig0KDQo=");
        prologue += kv.second + OBFA("DQo=");
    }
    prologue += OBFA("LS0=") + boundary + OBFA("DQo=");
    prologue += OBFA("Q29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSI=") + fileFieldName +
                OBFA("IjsgZmlsZW5hbWU9Ig==") + fileNameInForm + OBFA("Ig0K");
    prologue += OBFA("Q29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0NCg0K");

    const std::string epilogue = OBFA("DQotLQ==") + boundary + OBFA("LS0NCg==");

    const unsigned long long totalLen =
        (unsigned long long)prologue.size() + fileSize.QuadPart + epilogue.size();

    if (totalLen > 0xFFFFFFFFull) {
        res.error = OBFW("5paH5Lu26L+H5aSn77yM6LaF5Ye65Y2V5qyh5LiK5Lyg5LiK6ZmQ77yINEdC77yJ");
        return res;
    }

    // ---- 建立连接 ----
    const UrlParts parts = CrackUrl(url);
    if (!parts.ok) {
        res.error = OBFW("5LiK5Lyg5Zyw5Z2A5qC85byP5LiN5q2j56Gu");
        return res;
    }

    WinHttpHandle session, connect, request;
    if (!OpenChain(parts, OBFW("UE9TVA=="), to, session, connect, request, res.error)) return res;

    std::vector<Header> hs = headers;
    hs.emplace_back(OBFW("Q29udGVudC1UeXBl"),
                    OBFW("bXVsdGlwYXJ0L2Zvcm0tZGF0YTsgYm91bmRhcnk9") + util::Utf8ToWide(boundary));
    const std::wstring hdr = BuildHeaderBlock(hs);

    if (!::WinHttpSendRequest(request,
                              hdr.c_str(), (DWORD)-1,
                              WINHTTP_NO_REQUEST_DATA, 0,
                              (DWORD)totalLen, 0)) {
        res.error = OBFW("5Y+R6LW35LiK5Lyg5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return res;
    }

    unsigned long long sentBytes = 0;
    auto writeChunk = [&](const void* data, DWORD len) -> bool {
        const uint8_t* p = (const uint8_t*)data;
        DWORD left = len;
        while (left > 0) {
            DWORD wrote = 0;
            if (!::WinHttpWriteData(request, p, left, &wrote) || wrote == 0) return false;
            p += wrote;
            left -= wrote;
            sentBytes += wrote;
        }
        return true;
    };

    // 前段
    if (!writeChunk(prologue.data(), (DWORD)prologue.size())) {
        res.error = OBFW("5LiK5Lyg5Lit5pat77ya") + util::LastErrorText(::GetLastError());
        return res;
    }

    // 文件体
    {
        HANDLE hf = ::CreateFileW(localFilePath.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hf == INVALID_HANDLE_VALUE) {
            res.error = OBFW("5peg5rOV6K+75Y+W5b6F5LiK5Lyg5paH5Lu2");
            return res;
        }

        std::vector<uint8_t> buf(256 * 1024);
        unsigned long long fileSent = 0;
        bool ioOk = true;

        while (fileSent < fileSize.QuadPart) {
            if (cancel && cancel->load()) { ioOk = false; res.error = OBFW("5bey5Y+W5raI"); break; }

            DWORD got = 0;
            if (!::ReadFile(hf, buf.data(), (DWORD)buf.size(), &got, nullptr) || got == 0) {
                ioOk = false;
                if (res.error.empty()) res.error = OBFW("6K+75Y+W5b6F5LiK5Lyg5paH5Lu25aSx6LSl");
                break;
            }
            if (fileSent + got > fileSize.QuadPart)
                got = (DWORD)(fileSize.QuadPart - fileSent);

            if (!writeChunk(buf.data(), got)) {
                ioOk = false;
                res.error = OBFW("5LiK5Lyg5Lit5pat77ya") + util::LastErrorText(::GetLastError());
                break;
            }
            fileSent += got;

            if (progress && !progress(sentBytes, totalLen)) {
                ioOk = false;
                res.error = OBFW("5bey5Y+W5raI");
                break;
            }
        }
        ::CloseHandle(hf);
        if (!ioOk) return res;
    }

    // 后段
    if (!writeChunk(epilogue.data(), (DWORD)epilogue.size())) {
        res.error = OBFW("5LiK5Lyg5pS25bC+5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return res;
    }
    if (progress) progress(totalLen, totalLen);

    if (!::WinHttpReceiveResponse(request, nullptr)) {
        res.error = OBFW("562J5b6F5pyN5Yqh5Zmo5ZON5bqU5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return res;
    }

    res.status = QueryStatus(request);
    if (!ReadResponseBody(request, res.body, res.error)) return res;

    res.ok = true;
    return res;
}

// ===========================================================================
// 下载到文件
// ===========================================================================
Response DownloadToFile(const std::wstring& url,
                        const std::wstring& localPath,
                        const std::vector<Header>& headers,
                        const Timeouts& to,
                        const DownloadProgressFn& progress,
                        const std::atomic<bool>* cancel) {
    Response res;

    const UrlParts parts = CrackUrl(url);
    if (!parts.ok) {
        res.error = OBFW("5LiL6L295Zyw5Z2A5qC85byP5LiN5q2j56Gu");
        return res;
    }

    WinHttpHandle session, connect, request;
    if (!OpenChain(parts, OBFW("R0VU"), to, session, connect, request, res.error)) return res;

    const std::wstring hdr = BuildHeaderBlock(headers);
    if (!::WinHttpSendRequest(request,
                               hdr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdr.c_str(),
                               hdr.empty() ? 0 : (DWORD)-1,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        res.error = OBFW("5Y+R6LW35LiL6L295aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return res;
    }

    if (!::WinHttpReceiveResponse(request, nullptr)) {
        res.error = OBFW("5o6l5pS25LiL6L295ZON5bqU5aSx6LSl77ya") + util::LastErrorText(::GetLastError());
        return res;
    }

    res.status = QueryStatus(request);
    if (res.status != 200) {
        // 防盗链 403 / 404 等：尽量读一点错误体，方便 UI 提示
        ReadResponseBody(request, res.body, res.error);
        return res;
    }

    HANDLE hf = ::CreateFileW(localPath.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        res.error = OBFW("5peg5rOV5Yib5bu65LiL6L295paH5Lu277ya") + localPath;
        return res;
    }

    unsigned long long total = 0;
    {
        DWORD cl = 0, sz = sizeof(cl);
        if (::WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                                  WINHTTP_HEADER_NAME_BY_INDEX, &cl, &sz, WINHTTP_NO_HEADER_INDEX))
            total = cl;
    }

    unsigned long long received = 0;
    bool ioOk = true;
    std::vector<uint8_t> buf(256 * 1024);

    for (;;) {
        if (cancel && cancel->load()) { ioOk = false; res.error = OBFW("5bey5Y+W5raI"); break; }

        DWORD avail = 0;
        if (!::WinHttpQueryDataAvailable(request, &avail)) {
            ioOk = false; res.error = OBFW("5LiL6L295Lit5pat77ya") + util::LastErrorText(::GetLastError()); break;
        }
        if (avail == 0) break;
        if (avail > (DWORD)buf.size()) avail = (DWORD)buf.size();

        DWORD got = 0;
        if (!::WinHttpReadData(request, buf.data(), avail, &got) || got == 0) {
            ioOk = false; res.error = OBFW("6K+75Y+W5LiL6L295pWw5o2u5aSx6LSl77ya") + util::LastErrorText(::GetLastError()); break;
        }

        DWORD wrote = 0;
        if (!::WriteFile(hf, buf.data(), got, &wrote, nullptr) || wrote != got) {
            ioOk = false; res.error = OBFW("5YaZ5YWl5LiL6L295paH5Lu25aSx6LSl"); break;
        }
        received += got;

        if (progress && !progress(received, total)) {
            ioOk = false; res.error = OBFW("5bey5Y+W5raI"); break;
        }
    }
    ::CloseHandle(hf);
    if (!ioOk) return res;

    res.ok = true;
    return res;
}

// ===========================================================================
std::string UrlEncode(const std::string& s) {
    static const char* hex = OBFA("MDEyMzQ1Njc4OUFCQ0RFRg==");
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back((char)c);
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

} // namespace http
