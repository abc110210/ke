#pragma once

// ---------------------------------------------------------------------------
// 加密 ZIP 解包器（读取端）
//   - 解析本地文件头 + 中央目录
//   - ZipCrypto 解密（与 zip_writer 写端 k0/k1/k2 完全一致）
//   - 用 12 字节加密头校验密码对错
//   - 内部条目路径若以「saves/」开头则剥除，再解压到目标目录并覆盖
//   - 含路径穿越防护，绝不写出目标目录之外
// ---------------------------------------------------------------------------

#include <windows.h>
#include <string>

namespace zipr {

struct ExtractResult {
    bool               ok = false;
    std::wstring       error;
    size_t             fileCount = 0;
    size_t             dirCount = 0;
    bool               passwordWrong = false;     // 密码错误（解密头校验失败）
    unsigned long long writtenBytes = 0;
};

// 把加密 zip 解压到 targetDir（覆盖已存在文件）。
// password 为压缩时使用的密码（4-24 位字母/数字）。
ExtractResult ExtractEncryptedZip(const std::wstring& zipPath,
                                  const std::wstring& targetDir,
                                  const std::string& password);

} // namespace zipr
