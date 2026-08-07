#pragma once

// ---------------------------------------------------------------------------
// 通用工具：编码转换、文件、随机数、格式化
//   全部基于 Win32 API 与标准库，无第三方依赖
// ---------------------------------------------------------------------------

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace util {

// ---- 编码 ----
std::wstring Utf8ToWide(const std::string& s);
std::string  WideToUtf8(const std::wstring& s);

// ---- 字符串 ----
std::wstring Trim(const std::wstring& s);
std::wstring ToLower(const std::wstring& s);
std::string  ToLowerA(const std::string& s);
bool         EndsWithNoCase(const std::wstring& s, const std::wstring& suffix);

// ---- 路径 / 文件 ----
bool         FileExists(const std::wstring& path);
bool         DirectoryExists(const std::wstring& path);
std::wstring JoinPath(const std::wstring& a, const std::wstring& b);
std::wstring GetExeDir();
std::wstring GetTempDir();
std::wstring NormalizePath(const std::wstring& path);

// 把绝对路径转成 `\\?\` 前缀形式，突破 Windows 260 字符（MAX_PATH）限制。
// 这是「手动解压正常、程序解压报写入失败」的根因之一：解压目标路径
// （saves + 深层子目录 + 文件名）常超过 260 字符，普通 CreateFileW/CreateDirectoryW
// 会失败，而 7zip/WinRAR/资源管理器默认走长路径。outErr 方式见 WriteWholeFile。
// 已带 `\\?\` / `\\?\UNC\` 前缀则原样返回；UNC 路径转为 `\\?\UNC\`；相对路径不动。
std::wstring LongPath(const std::wstring& path);

// outErr 可选：写文件失败时把最后一次 CreateFileW 的 GetLastError 写入 *outErr，
// 便于上层在错误文案里带上真实系统错误码（之前 DEFLATE 分支没带，导致一直误判「占用」）。
bool ReadWholeFile(const std::wstring& path, std::vector<uint8_t>& out);
bool WriteWholeFile(const std::wstring& path, const void* data, size_t bytes, DWORD* outErr = nullptr);

// ---- 随机 ----
// 优先使用 BCryptGenRandom，失败则退回到时间 + 进程信息混合的伪随机
void        RandomBytes(void* buf, size_t n);
// 生成不含易混淆字符（0/O/1/l/I）的随机密码
std::string GenerateRandomPassword(size_t length);

// ---- 校验 / 网络 ----
// 密码规则：4-24 位，仅允许字母（A-Z a-z）和数字（0-9）
bool        IsValidPassword(const std::wstring& pwd);
// 取回密码规则：SK- 开头 + 20 位字母数字（大小写 + 数字），共 23 位
bool        IsValidDownloadPassword(const std::wstring& pwd);
// 获取本机首个非回环 IPv4 地址（用于向后端登记，便于排查）
std::wstring GetMachineIp();

// ---- 格式化 ----
std::wstring FormatSize(unsigned long long bytes);   // 1.23 MB
std::wstring TimestampCompact();                     // 20260802_134501
std::wstring MachineId();                            // 8 位十六进制，机器指纹

// ---- 系统 ----
std::wstring LastErrorText(DWORD code);
bool         CopyTextToClipboard(HWND owner, const std::wstring& text);

} // namespace util

// ---------------------------------------------------------------------------
// 轻量字符串混淆运行库（obf）
//   编译期由混淆脚本把字面量转成 base64（UTF-8）存入源码，运行时这里解回。
//   注意：这只是【数据解密】，不改写 .text、不动内存页属性，绝不是 SMC。
//   解密结果放在 thread_local 缓冲，调用点用完即弃，不跨表达式长期持有。
// ---------------------------------------------------------------------------
namespace obf {

// 宽字符串字面量解密：base64 -> UTF-8 字节 -> wchar_t*
const wchar_t* w(const char* b64);
// 窄字符串字面量解密：base64 -> 原始字节
const char*    a(const char* b64);

} // namespace obf

// 混淆脚本生成：OBFW(L"原文") 由脚本替换为 OBFW("base64...")，此处仅作宏外壳
#define OBFW(s) obf::w(s)
#define OBFA(s) obf::a(s)
