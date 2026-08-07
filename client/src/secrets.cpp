#include "secrets.h"
#include "util.h"

// 注意：本文件已按混淆脚本产出格式手写（字面量 → OBFW("base64")）。
// 若将来改了密钥/UA，用 obfuscate_client.py 重新编码，或按
// base64(UTF-8(原文)) 重新生成下面两行即可；本文件含 OBFW，脚本重跑会幂等跳过。

namespace secrets {

std::wstring client_key() { return OBFW("MTA1ODgyMzUxM1dBb09aNi1uJURMTVBSYUk="); }
std::wstring app_ua()     { return OBFW("eGxpbmdyYW4vaGFuYm90LzEuMQ=="); }

} // namespace secrets
