#pragma once

// ---------------------------------------------------------------------------
// 客户端敏感常量（混淆集中区）
//   CLIENT_API_KEY / UA 原本是 config.h 里的明文宏，但 config.h/config.cpp
//   因编译期字符串拼接（MARKER_FILE_W 等）在混淆脚本 EXCLUDE_FILES 中整体
//   跳过。为把这些串也纳入源码混淆（OBFW 运行时解码），统一抽到本文件：
//   - secrets.cpp 里的字面量由混淆脚本编码成 OBFW("base64")，二进制里不再
//     有明文，`strings exe` 直接搜不到。
//   - config.h / config.cpp 保持排除（宏拼接不能动），只引用本文件接口。
// ---------------------------------------------------------------------------

#include <string>

namespace secrets {

// 客户端密钥（对应服务端 server.conf 的 CLIENT_API_KEY，两端必须一致，
// 不一致则后端 check_client_key 拒绝请求 403）
std::wstring client_key();

// 客户端 User-Agent（与 CDN 防盗链白名单要求的值一致）
std::wstring app_ua();

} // namespace secrets
