#include "config.h"
#include "util.h"

#include <windows.h>
#include <vector>

namespace config {

// 后端地址（编译期硬编码；端口以部署为准，这里用 20333）
std::wstring BackendBaseUrl   = BACKEND_BASE_URL_W;

// 客户端密钥（来自 secrets，运行时 OBFW 解码；与 server.py 的 CLIENT_API_KEY 保持一致）
std::string  ClientKey        = util::WideToUtf8(secrets::client_key());

// 网络超时（毫秒，硬编码）
int          ConnectTimeoutMs = 15000;
int          SendTimeoutMs    = 120000;
int          RecvTimeoutMs    = 120000;

static std::wstring IniPath() {
    return util::JoinPath(util::GetExeDir(), L"uploader.ini");
}

void Load() {
    // 重要参数均已编译期硬编码，不再从 uploader.ini 读取，
    // 避免密钥 / 地址等敏感信息落到配置文件里。本函数保留仅为兼容调用点。
}

void WriteTemplateIfMissing() {
    const std::wstring ini = IniPath();
    if (util::FileExists(ini)) return;

    // 统一 UTF-8 编码（现代记事本默认，中文正常显示）。
    // 地址 / 密钥 / 超时 / 体积上限等敏感项不在此模板里，它们全部编译进 exe。
    // 运行后程序会在末尾追加 [State] 段，记录本机记住的 saves 目录与密码（明文，仅本机便利）。
    std::wstring content;
    content += L"; " APP_TITLE_W L" 配置文件\r\n";
    content += L"; 服务器地址、客户端密钥、网络超时、体积上限等都已内置在程序中，\r\n";
    content += L"; 不在此文件填写。运行后程序会自动追加 [State] 段，记录本机记住的目录与密码。\r\n";

    std::string u8 = util::WideToUtf8(content);
    util::WriteWholeFile(ini, u8.data(), u8.size());
}

// ---------------------------------------------------------------------------
// 本地记住的状态：直接写入 uploader.ini 的 [State] 段
// 2026-08-06 重构：不再用 Get/WritePrivateProfileStringW——那个 Windows API
// 只认 UTF-16，用户手动用记事本（默认 UTF-8）编辑/创建 ini 后，中文路径会被
// 它读成乱码（实测 "DJ暴力版本" → "DJ鏆村姏鐗堟湰"），目录校验失败 →
// 「重开软件不回填」。改为自解析：
//   - 读取：检测 BOM（FF FE=UTF-16LE / EF BB BF=UTF-8 / 无 BOM 按 UTF-8）
//   - 写入：统一 UTF-8（无 BOM），与手动编辑的编码一致
// 无论 ini 是旧客户端的 UTF-16 产物还是用户手改的 UTF-8，都能正确读写。
// ---------------------------------------------------------------------------
static std::wstring StateIniPath() {
    return IniPath();   // uploader.ini 同目录同文件，[State] 段
}

// 读取 ini 文件并解码成 wstring（自动识别 UTF-8 / UTF-16LE BOM）
static bool ReadIniText(const std::wstring& path, std::wstring& out) {
    std::vector<uint8_t> raw;
    if (!util::ReadWholeFile(path, raw) || raw.empty()) return false;
    if (raw.size() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) {
        // UTF-16 LE（带 BOM）：跳过 BOM，按 wchar_t 解码
        size_t n = (raw.size() - 2) / 2;
        out.assign(reinterpret_cast<const wchar_t*>(raw.data() + 2), n);
        return true;
    }
    // UTF-8（有 BOM 则跳过）；无 BOM 也按 UTF-8 处理
    size_t off = (raw.size() >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF) ? 3 : 0;
    std::string u8(reinterpret_cast<const char*>(raw.data()) + off, raw.size() - off);
    out = util::Utf8ToWide(u8);
    return true;
}

// 从 ini 文本的 [State] 段提取 key 的值（跳过注释/空行）
static std::wstring IniGet(const std::wstring& text, const wchar_t* key) {
    size_t sec = text.find(L"[State]");
    if (sec == std::wstring::npos) return L"";
    size_t secEnd = text.find(L'[', sec + 1);
    if (secEnd == std::wstring::npos) secEnd = text.size();
    std::wstring body = text.substr(sec + 7, secEnd - sec - 7);
    size_t pos = 0;
    while (pos < body.size()) {
        size_t eol = body.find(L'\n', pos);
        if (eol == std::wstring::npos) eol = body.size();
        std::wstring line = body.substr(pos, eol - pos);
        pos = eol + 1;
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        size_t st = line.find_first_not_of(L" \t");
        if (st == std::wstring::npos || line[st] == L';') continue;   // 空行/注释
        line = line.substr(st);
        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        std::wstring k = line.substr(0, eq);
        while (!k.empty() && (k.back() == L' ' || k.back() == L'\t')) k.pop_back();
        if (k != key) continue;
        std::wstring v = line.substr(eq + 1);
        while (!v.empty() && (v.back() == L'\r' || v.back() == L' ' || v.back() == L'\t')) v.pop_back();
        return v;
    }
    return L"";
}

void LoadState(AppState& s) {
    const std::wstring ini = StateIniPath();
    if (!util::FileExists(ini)) return;
    std::wstring text;
    if (!ReadIniText(ini, text)) return;
    std::wstring v;
    v = IniGet(text, L"SavesDir");         if (!v.empty()) s.savesDir = v;
    v = IniGet(text, L"Password");         if (!v.empty()) s.password = v;
    v = IniGet(text, L"DownloadPassword"); if (!v.empty()) s.downloadPassword = v;
}

void SaveState(const std::wstring& savesDir,
               const std::wstring& password,
               const std::wstring& downloadPassword) {
    const std::wstring ini = StateIniPath();
    // 保留原文件 [State] 段之前的注释/模板内容（若有），替换/追加 [State] 段
    std::wstring head;
    {
        std::wstring old;
        if (ReadIniText(ini, old)) {
            size_t sec = old.find(L"[State]");
            head = (sec == std::wstring::npos) ? old : old.substr(0, sec);
        }
    }
    // 规整 head 结尾：去掉多余空行/空白，保证 [State] 前干净
    while (!head.empty() && (head.back() == L'\r' || head.back() == L'\n' || head.back() == L' '))
        head.pop_back();
    if (!head.empty()) head += L"\r\n";

    std::wstring text = head;
    text += L"[State]\r\n";
    text += L"SavesDir=" + savesDir + L"\r\n";
    text += L"Password=" + password + L"\r\n";
    text += L"DownloadPassword=" + downloadPassword + L"\r\n";
    // 统一 UTF-8 写回（无 BOM）：记事本/编辑器均正常显示中文
    std::string u8 = util::WideToUtf8(text);
    util::WriteWholeFile(ini, u8.data(), u8.size());
}

} // namespace config
