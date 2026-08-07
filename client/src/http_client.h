#pragma once

// ---------------------------------------------------------------------------
// 基于 WinHTTP 的极简 HTTP 客户端
//   - 系统自带，不需要 libcurl / OpenSSL，编译产物零依赖
//   - 支持 http 与 https；本项目实际只用 http
//   - multipart 上传采用分块写入，大文件不会把内存吃爆
// ---------------------------------------------------------------------------

#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <atomic>
#include "util.h"

namespace http {

struct Response {
    bool         ok = false;      // 网络层是否成功（不代表 HTTP 状态码是 2xx）
    int          status = 0;
    std::string  body;
    std::wstring error;

    bool Is2xx() const { return status >= 200 && status < 300; }
};

using Header = std::pair<std::wstring, std::wstring>;

// 上传进度回调；返回 false 表示取消
using UploadProgressFn = std::function<bool(unsigned long long sent,
                                            unsigned long long total)>;

struct Timeouts {
    int connectMs = 15000;
    int sendMs    = 120000;
    int recvMs    = 120000;
};

// 发送 JSON 请求（method 一般为 L"POST" 或 L"GET"）
Response Request(const std::wstring& method,
                 const std::wstring& url,
                 const std::string&  body,
                 const std::vector<Header>& headers,
                 const Timeouts& to);

inline Response PostJson(const std::wstring& url,
                         const std::string& jsonBody,
                         const std::vector<Header>& headers,
                         const Timeouts& to) {
    std::vector<Header> h = headers;
    h.emplace_back(OBFW("Q29udGVudC1UeXBl"), OBFW("YXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOA=="));
    return Request(OBFW("UE9TVA=="), url, jsonBody, h, to);
}

inline Response Get(const std::wstring& url,
                    const std::vector<Header>& headers,
                    const Timeouts& to) {
    return Request(OBFW("R0VU"), url, std::string(), headers, to);
}

// multipart/form-data 上传单个文件
Response UploadMultipartFile(const std::wstring& url,
                             const std::vector<std::pair<std::string, std::string>>& fields,
                             const std::string& fileFieldName,
                             const std::string& fileNameInForm,
                             const std::wstring& localFilePath,
                             const std::vector<Header>& headers,
                             const Timeouts& to,
                             const UploadProgressFn& progress,
                             const std::atomic<bool>* cancel);

// 下载到本地文件（带进度回调），UA 已在 WinHttpOpen 中统一设置
using DownloadProgressFn = std::function<bool(unsigned long long received,
                                              unsigned long long total)>;
Response DownloadToFile(const std::wstring& url,
                        const std::wstring& localPath,
                        const std::vector<Header>& headers,
                        const Timeouts& to,
                        const DownloadProgressFn& progress,
                        const std::atomic<bool>* cancel);

// URL 编码（用于查询串）
std::string UrlEncode(const std::string& s);

} // namespace http
