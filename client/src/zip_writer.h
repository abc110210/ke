#pragma once

// ---------------------------------------------------------------------------
// 带密码的 ZIP 打包器
//   - 压缩算法：DEFLATE（自研，见 deflate.h）
//   - 加密算法：ZipCrypto（传统 PKWARE 加密）
//   - 兼容性：7-Zip / WinRAR / Bandizip / Python zipfile 均可用密码正常解开
// ---------------------------------------------------------------------------

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <cstdint>

namespace zipw {

struct Entry {
    std::wstring       fullPath;     // 磁盘绝对路径（目录项可为空）
    std::wstring       nameInZip;    // 包内相对路径，使用 '/' 分隔
    unsigned long long size = 0;
    FILETIME           mtime{};
    DWORD              attrs = 0;
    bool               isDir = false;
};

struct ScanResult {
    bool               ok = false;
    std::wstring       error;
    unsigned long long totalBytes = 0;
    size_t             fileCount = 0;
    size_t             dirCount = 0;
};

struct PackResult {
    bool               ok = false;
    std::wstring       error;
    unsigned long long rawBytes = 0;
    unsigned long long zipBytes = 0;
    size_t             fileCount = 0;
    size_t             skipped = 0;
};

// 进度回调：返回 false 表示请求取消
using ProgressFn = std::function<bool(unsigned long long done,
                                      unsigned long long total,
                                      const std::wstring& currentFile)>;

// 递归枚举目录，rootAliasInZip 为包内的顶层文件夹名（如 L"saves"）
ScanResult ScanDirectory(const std::wstring& root,
                         const std::wstring& rootAliasInZip,
                         std::vector<Entry>& out,
                         const std::atomic<bool>* cancel);

// 生成加密压缩包
PackResult CreateEncryptedZip(const std::wstring& outPath,
                              const std::vector<Entry>& entries,
                              const std::string& password,
                              const ProgressFn& progress,
                              const std::atomic<bool>* cancel);

} // namespace zipw
