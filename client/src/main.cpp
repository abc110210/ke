// ---------------------------------------------------------------------------
// Hanbot 存档打包上传器 —— 主程序（WebView2 宿主 + native↔JS 桥接）
//
//   形态：无边框圆角窗口 + DWM 阴影，WebView2 铺满客户区渲染 webui/index.html
//         （以资源形式内嵌），通过 WebMessage 与页面双向通信。
//   说明：所有上传/下载/检测/连通性逻辑均复用原有模块（uploader / lolfind /
//         util / config），本文件只替换“UI 渲染层”——把 Win32 控件更新改为
//         向页面 PostWebMessageAsString 推 JSON。
// ---------------------------------------------------------------------------

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <dwmapi.h>

#include <wrl.h>
#include <WebView2.h>

#include <string>
#include <vector>
#include <atomic>
#include <thread>

#include "resource.h"
#include "config.h"
#include "util.h"
#include "lol_finder.h"
#include "uploader.h"
#include "json_mini.h"

using namespace Microsoft::WRL;

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "WebView2LoaderStatic.lib")

// ===========================================================================
// 全局状态
// ===========================================================================
namespace {

HINSTANCE g_hInst = nullptr;
HWND      g_hMain = nullptr;

ComPtr<ICoreWebView2Controller> g_controller;
ComPtr<ICoreWebView2>           g_webview;

bool g_pageReady = false;                 // 页面是否已发来 ready（可收消息）
std::vector<std::wstring> g_pending;      // 页面就绪前缓冲的待发 JSON

int  g_dpi = 96;
int  g_titleH = 42;
bool g_useRgn = true;                      // Win11 用 DWM 原生圆角；否则用 rgn

std::atomic<bool> g_busy{ false };
std::atomic<bool> g_cancel{ false };
std::atomic<bool> g_uploadDone{ false };

std::wstring g_lastResultText;            // 关闭前密码警告用
std::wstring g_lastDir;                   // 最近一次操作的目录（结果文案用）
std::wstring g_currentPwd;                 // 页面「上传密码」框内容（关闭时写入 uploader.ini）
std::wstring g_currentDlPwd;                // 页面「取回密码」框内容（关闭时写入 uploader.ini）
std::wstring g_appIconB64;                // 启动期从资源读取的软件图标（base64，供页面头部注入）

inline int S(int v) { return ::MulDiv(v, g_dpi, 96); }

// GetDpiForWindow 是 Win10 1607+ 才有的，动态解析避免链接/运行期报错
int QueryWindowDpi(HWND hwnd) {
    HMODULE user32 = ::GetModuleHandleW(OBFW("dXNlcjMyLmRsbA=="));
    if (user32) {
        using GetDpiFn = UINT (WINAPI*)(HWND);
        auto fn = (GetDpiFn)::GetProcAddress(user32, OBFA("R2V0RHBpRm9yV2luZG93"));
        if (fn) {
            const UINT d = fn(hwnd);
            if (d >= 72 && d <= 480) return (int)d;
        }
    }
    HDC dc = ::GetDC(hwnd);
    int dpi = 96;
    if (dc) {
        const int d = ::GetDeviceCaps(dc, LOGPIXELSX);
        if (d >= 72 && d <= 480) dpi = d;
        ::ReleaseDC(hwnd, dc);
    }
    return dpi;
}

// ---------------------------------------------------------------------------
// JSON 构建（native -> page）
// ---------------------------------------------------------------------------
std::wstring JStr(const std::wstring& s) {
    std::string u8 = util::WideToUtf8(s);
    std::string esc = json::EscapeString(u8);
    return OBFW("Ig==") + util::Utf8ToWide(esc) + OBFW("Ig==");
}
std::wstring WBool(bool b) { return b ? OBFW("dHJ1ZQ==") : OBFW("ZmFsc2U="); }

// BuildDone 里的临时诊断要调 PostLog（其定义在本文件更后面），前置声明一下。
void PostLog(const std::wstring& text);


void PostJson(const std::wstring& json) {
    if (g_webview && g_pageReady)
        g_webview->PostWebMessageAsString(json.c_str());
    else
        g_pending.push_back(json);
}

std::wstring BuildInit(const std::wstring& password = L"",
                       const std::wstring& downloadPassword = L"") {
    // 刻意不下发后端地址：页面日志对用户可见，地址一旦落到界面上就等于公开了服务端。
    std::wstring s = std::wstring(L"{\"type\":\"init\",\"app\":") + JStr(APP_TITLE_W) +
                     OBFW("LCJ2ZXJzaW9uIjoiMS4wLjAi");
    if (!password.empty()) s += OBFW("LCJwYXNzd29yZCI6") + JStr(password);
    // ⚠️ 此前的 "LCJkb3dubG9hZFBhc3N3b3JkIjoi" 解码为 ,"downloadPassword":"（末尾带开引号），
    // 再拼 JStr() 的自带引号 → 双引号嵌套 → 非法 JSON → init 消息被整体丢弃 →
    // 密码/取回密码不回填（目录走独立消息所以正常）。正确应为 ,"downloadPassword":（Ijo=）。
    if (!downloadPassword.empty()) s += OBFW("LCJkb3dubG9hZFBhc3N3b3JkIjo=") + JStr(downloadPassword);
    s += OBFW("fQ==");
    return s;
}

// 当前本地时间字符串（YYYY-MM-DD HH:MM），用于上传结果里的「完成时间」
std::wstring NowString() {
    SYSTEMTIME st; ::GetLocalTime(&st);
    wchar_t buf[64]{};
    ::swprintf(buf, 64, OBFW("JTA0ZC0lMDJkLSUwMmQgJTAyZDolMDJk"),
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buf;
}
std::wstring BuildLog(const std::wstring& t) {
    return L"{\"type\":\"log\",\"text\":" + JStr(t) + OBFW("fQ==");
}
std::wstring BuildProgress(int permille, const std::wstring& s) {
    return L"{\"type\":\"progress\",\"permille\":" + std::to_wstring(permille) +
           OBFW("LCJzdGFnZSI6") + JStr(s) + OBFW("fQ==");
}
std::wstring BuildConn(int st, const std::wstring& t) {
    return L"{\"type\":\"conn\",\"state\":" + std::to_wstring(st) + OBFW("LCJ0ZXh0Ijo=") + JStr(t) + OBFW("fQ==");
}
std::wstring BuildBusy(bool b) {
    return L"{\"type\":\"busy\",\"busy\":" + WBool(b) + OBFW("fQ==");
}
std::wstring BuildDetectDone(const std::wstring& path, int vs, const std::wstring& vt) {
    return L"{\"type\":\"detectDone\",\"path\":" + JStr(path) +
           OBFW("LCJ2ZXJpZnlTdGF0ZSI6") + std::to_wstring(vs) + OBFW("LCJ2ZXJpZnlUZXh0Ijo=") + JStr(vt) + OBFW("fQ==");
}
std::wstring BuildDir(const std::wstring& path, int vs, const std::wstring& vt) {
    return L"{\"type\":\"dir\",\"path\":" + JStr(path) +
           OBFW("LCJ2ZXJpZnlTdGF0ZSI6") + std::to_wstring(vs) + OBFW("LCJ2ZXJpZnlUZXh0Ijo=") + JStr(vt) + OBFW("fQ==");
}
// 自包含的 JSON string escape：BuildDone 专用，不依赖 json_mini.cpp 的
// EscapeString（05:14 反馈：obfuscate 重跑后 EscapeString 输出异常，导致含换行
// 字段的 done JSON 解析失败 → m.resultText 变 undefined → 结果框 placeholder）。
// 这里直接写死：只 escape JSON 字符串必须的 5 个字符（" \ r n t），其余原样，
// 简单可靠，与 obfuscate 状态无关。
static std::wstring JSDone(const std::wstring& s) {
    std::wstring out; out.reserve(s.size() + 16);
    for (wchar_t c : s) {
        switch (c) {
            case L'"':  out += L"\\\""; break;
            case L'\\': out += L"\\\\"; break;
            case L'\r': out += L"\\r";  break;
            case L'\n': out += L"\\n";  break;
            case L'\t': out += L"\\t";  break;
            default:   out += c;        break;
        }
    }
    return OBFW("Ig==") + out + OBFW("Ig==");
}

std::wstring BuildDone(bool ok, bool canceled, bool isDownload, bool pwdWrong,
                       const std::wstring& error, const std::wstring& resultText,
                       const std::wstring& resultLabel, const std::wstring& stage, bool copyEnabled) {
    // 全部字段用自包含的 JSDone escape（不依赖 json::EscapeString）。
    // 原因：json::EscapeString 在 json_mini.cpp 中经 obfuscate 反复重跑后，
    // 对部分控制字符的输出可能异常（实测导致 done JSON 含真换行解析失败）。
    // 这里用最简 escape 保证 done 消息一定合法。
    std::wstring out = L"{\"type\":\"done\",\"ok\":" + WBool(ok) +
           OBFW("LCJjYW5jZWxlZCI6") + WBool(canceled) +
           OBFW("LCJpc0Rvd25sb2FkIjo=") + WBool(isDownload) +
           OBFW("LCJwYXNzd29yZFdyb25nIjo=") + WBool(pwdWrong) +
           OBFW("LCJlcnJvciI6") + JSDone(error) +
           OBFW("LCJyZXN1bHRUZXh0Ijo=") + JSDone(resultText) +
           OBFW("LCJyZXN1bHRMYWJlbCI6") + JSDone(resultLabel) +
           OBFW("LCJzdGFnZSI6") + JSDone(stage) +
           OBFW("LCJjb3B5RW5hYmxlZCI6") + WBool(copyEnabled) + OBFW("fQ==");
    return out;
}

std::wstring BuildIcon(const std::wstring& b64) {
    return L"{\"type\":\"icon\",\"data\":\"" + b64 + OBFW("In0=");
}
// 上传成功后把后端返回的取回密码(SK-) 回填到页面的「取回密码」框，
// 让上传者自己也能看到/复制自己的取回码（并随 input 事件写入 config）。
std::wstring BuildFillDlPwd(const std::wstring& dl) {
    return L"{\"type\":\"dlpwd\",\"value\":" + JStr(dl) + OBFW("fQ==");
}

// 随机生成密码的查重结果（worker 线程 -> UI 线程）
struct PwdCheckResult {
    std::wstring password;
    bool         exists = false;
};
std::wstring BuildPasswordChecked(const std::wstring& pwd, bool exists) {
    return L"{\"type\":\"passwordChecked\",\"password\":" + JStr(pwd) +
           OBFW("LCJleGlzdHMiOg==") + WBool(exists) + OBFW("fQ==");
}

// 标准 Base64 编码（用于把图标资源注入页面）
std::wstring Base64Encode(const uint8_t* data, size_t len) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) v |= (uint32_t)data[i + 2];
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? tbl[(v >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? tbl[v & 0x3F] : '=');
    }
    return util::Utf8ToWide(out);
}

// 从 RCDATA 资源读取软件图标（PNG），base64 编码后供 WebView2 头部图标使用
std::wstring LoadAppIconBase64() {
    HRSRC hRes = ::FindResourceW(g_hInst, MAKEINTRESOURCE(IDR_APP_ICON_PNG), RT_RCDATA);
    if (!hRes) return L"";
    HGLOBAL hGlob = ::LoadResource(g_hInst, hRes);
    if (!hGlob) return L"";
    DWORD size = ::SizeofResource(g_hInst, hRes);
    const uint8_t* data = (const uint8_t*)::LockResource(hGlob);
    if (!data || size == 0) return L"";
    return Base64Encode(data, (size_t)size);
}

// ---------------------------------------------------------------------------
// 跨线程投递（worker 线程 -> UI 线程）
// ---------------------------------------------------------------------------
void PostLog(const std::wstring& text) {
    if (!g_hMain) return;
    ::PostMessageW(g_hMain, WM_APP_LOG, 0, (LPARAM)new std::wstring(text));
}
void PostProgress(int permille, const std::wstring& stage) {
    if (!g_hMain) return;
    ::PostMessageW(g_hMain, WM_APP_PROGRESS, (WPARAM)permille,
                   (LPARAM)new std::wstring(stage));
}

// ---------------------------------------------------------------------------
// 选择文件夹对话框
// ---------------------------------------------------------------------------
std::wstring PickFolder(HWND owner) {
    std::wstring result;

    IFileDialog* dlg = nullptr;
    HRESULT hr = ::CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_PPV_ARGS(&dlg));
    if (SUCCEEDED(hr) && dlg) {
        DWORD opts = 0;
        if (SUCCEEDED(dlg->GetOptions(&opts)))
            dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
        dlg->SetTitle(OBFW("6K+36YCJ5oupIExlYWd1ZSBvZiBMZWdlbmRzIOeahCBzYXZlcyDnm67lvZU="));

        if (SUCCEEDED(dlg->Show(owner))) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dlg->GetResult(&item)) && item) {
                PWSTR psz = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &psz)) && psz) {
                    result = psz;
                    ::CoTaskMemFree(psz);
                }
                item->Release();
            }
        }
        dlg->Release();
        return result;
    }

    BROWSEINFOW bi{};
    wchar_t buf[MAX_PATH]{};
    bi.hwndOwner = owner;
    bi.pszDisplayName = buf;
    bi.lpszTitle = OBFW("6K+36YCJ5oupIHNhdmVzIOebruW9lQ==");
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = ::SHBrowseForFolderW(&bi);
    if (pidl) {
        wchar_t path[MAX_PATH]{};
        if (::SHGetPathFromIDListW(pidl, path)) result = path;
        ::CoTaskMemFree(pidl);
    }
    return result;
}

// ---------------------------------------------------------------------------
// 工作线程（逻辑全部复用，仅把结果经 WM_APP_* 回 UI 线程）
// ---------------------------------------------------------------------------
void DetectThread() {
    g_cancel.store(false);
    ::PostMessageW(g_hMain, WM_APP_SET_BUSY, 1, 0);
    PostProgress(0, OBFW("5q2j5Zyo5qOA5rWL55uu5b2VLi4u"));
    PostLog(OBFW("5byA5aeL5qOA5rWLIHNhdmVzIOebruW9lS4uLg=="));

    auto results = lolfind::FindAll(
        [](const std::wstring& s) { PostLog(s); },
        &g_cancel, 60);

    auto* payload = new std::vector<lolfind::Candidate>(std::move(results));
    ::PostMessageW(g_hMain, WM_APP_DETECT_DONE, 0, (LPARAM)payload);
}

void UploadThread(std::wstring dir, std::wstring password) {
    g_cancel.store(false);
    ::PostMessageW(g_hMain, WM_APP_SET_BUSY, 1, 0);
    g_lastDir = dir;

    uploader::Outcome result = uploader::Run(
        dir, password,
        [](const std::wstring& s) { PostLog(s); },
        [](int permille, const std::wstring& stage) { PostProgress(permille, stage); },
        &g_cancel);

    auto* payload = new uploader::Outcome(std::move(result));
    ::PostMessageW(g_hMain, WM_APP_UPLOAD_DONE, 0, (LPARAM)payload);
}

void DownloadThread(std::wstring dir, std::wstring password) {
    g_cancel.store(false);
    ::PostMessageW(g_hMain, WM_APP_SET_BUSY, 1, 0);
    g_lastDir = dir;

    uploader::Outcome result = uploader::Download(
        dir, password,
        [](const std::wstring& s) { PostLog(s); },
        [](int permille, const std::wstring& stage) { PostProgress(permille, stage); },
        &g_cancel);

    auto* payload = new uploader::Outcome(std::move(result));
    ::PostMessageW(g_hMain, WM_APP_UPLOAD_DONE, 0, (LPARAM)payload);
}

void ConnThread() {
    uploader::HealthResult res = uploader::CheckBackend(
        [](const std::wstring& s) { PostLog(s); });
    auto* payload = new uploader::HealthResult(std::move(res));
    ::PostMessageW(g_hMain, WM_APP_CONN, 0, (LPARAM)payload);
}

// 随机生成密码查重：问后端该密码是否已被使用
void CheckPwdThread(std::wstring password) {
    bool exists = uploader::PasswordExists(password);
    auto* payload = new PwdCheckResult{ std::move(password), exists };
    ::PostMessageW(g_hMain, WM_APP_PWD_CHECK, 0, (LPARAM)payload);
}

// ---------------------------------------------------------------------------
// 内嵌 HTML 资源读取
// ---------------------------------------------------------------------------
std::wstring LoadAppHtml() {
    // RC 里 HTML 是预定义类型 RT_HTML(23)，必须用宏而非字符串 "HTML" 才能匹配
    HRSRC hRes = ::FindResourceW(g_hInst, MAKEINTRESOURCE(IDR_APP_HTML), RT_HTML);
    if (!hRes) {
        ::OutputDebugStringW(OBFW("W0xvYWRBcHBIdG1sXSBGaW5kUmVzb3VyY2VXKElEPUlEUl9BUFBfSFRNTCwgUlRfSFRNTCkg5aSx6LSl77yM6LWE5rqQ5pyq5bWM5YWlIGV4ZeOAggo="));
        return L"";
    }
    HGLOBAL hGlob = ::LoadResource(g_hInst, hRes);
    if (!hGlob) {
        ::OutputDebugStringW(OBFW("W0xvYWRBcHBIdG1sXSBMb2FkUmVzb3VyY2Ug5aSx6LSl44CCCg=="));
        return L"";
    }
    DWORD size = ::SizeofResource(g_hInst, hRes);
    if (size == 0) {
        ::OutputDebugStringW(OBFW("W0xvYWRBcHBIdG1sXSBTaXplb2ZSZXNvdXJjZSDov5Tlm54gMO+8jEhUTUwg6LWE5rqQ5Li656m644CCCg=="));
        return L"";
    }
    const char* data = (const char*)::LockResource(hGlob);
    if (!data) {
        ::OutputDebugStringW(OBFW("W0xvYWRBcHBIdG1sXSBMb2NrUmVzb3VyY2Ug5aSx6LSl44CCCg=="));
        return L"";
    }
    std::string utf8(data, (size_t)size);
    std::wstring html = util::Utf8ToWide(utf8);
    if (html.empty()) {
        ::OutputDebugStringW(OBFW("W0xvYWRBcHBIdG1sXSBVdGY4VG9XaWRlIOe7k+aenOS4uuepuuOAggo="));
    } else {
        std::wstring msg = OBFW("W0xvYWRBcHBIdG1sXSDmiJDlip/or7vlj5YgSFRNTO+8jOWFsSA=") + std::to_wstring(html.size()) + OBFW("IOS4quWuveWtl+espuOAggo=");
        ::OutputDebugStringW(msg.c_str());
    }
    return html;
}

// 将 HTML 写入临时文件并返回 file:// URI；失败返回空串
static std::wstring WriteHtmlToTemp(const std::wstring& html) {
    wchar_t tmpDir[MAX_PATH];
    if (!::GetTempPathW(MAX_PATH, tmpDir)) return L"";
    wchar_t tmpFile[MAX_PATH];
    if (!::GetTempFileNameW(tmpDir, OBFW("aGJ1aQ=="), 0, tmpFile)) return L"";

    std::wstring path(tmpFile);
    auto pos = path.rfind(L'.');
    if (pos != std::wstring::npos) path = path.substr(0, pos) + OBFW("Lmh0bWw=");
    else path += OBFW("Lmh0bWw=");

    std::string u8 = util::WideToUtf8(html);
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return L"";
    DWORD written = 0;
    BOOL ok = ::WriteFile(h, u8.data(), (DWORD)u8.size(), &written, nullptr);
    ::CloseHandle(h);
    if (!ok || written != u8.size()) return L"";

    std::wstring url = OBFW("ZmlsZTovLy8=");
    for (wchar_t c : path) url.push_back(c == L'\\' ? L'/' : c);
    return url;
}

// 先尝试 NavigateToString；若失败，把 HTML 落盘临时文件再用 file:// 导航
static HRESULT NavigateWithFallback(ICoreWebView2* webview, const std::wstring& html) {
    HRESULT hr = webview->NavigateToString(html.c_str());
    if (SUCCEEDED(hr)) return hr;

    ::OutputDebugStringW(OBFW("W1dlYlZpZXcyXSBOYXZpZ2F0ZVRvU3RyaW5nIOWksei0pe+8jOWwneivleWGmeWFpeS4tOaXtuaWh+S7tueUqCBmaWxlOi8vIOWbnumAgOOAggo="));
    std::wstring url = WriteHtmlToTemp(html);
    if (!url.empty()) {
        hr = webview->Navigate(url.c_str());
        if (FAILED(hr)) {
            ::OutputDebugStringW(OBFW("W1dlYlZpZXcyXSBmaWxlOi8vIOWbnumAgOS5n+Wksei0peOAggo="));
        }
    } else {
        ::OutputDebugStringW(OBFW("W1dlYlZpZXcyXSDml6Dms5XliJvlu7rkuLTml7YgSFRNTCDmlofku7bjgIIK"));
    }
    return hr;
}

// ---------------------------------------------------------------------------
// 桥接：页面 -> native
// ---------------------------------------------------------------------------
void HandlePageMessage(const std::wstring& msg) {
    std::string u8 = util::WideToUtf8(msg);
    auto j = json::Parse(u8);
    if (!j || !j->IsObject()) return;
    std::string type = j->GetStr("type");

    if (type == "ready") {
        g_pageReady = true;
        for (auto& p : g_pending)
            if (g_webview) g_webview->PostWebMessageAsString(p.c_str());
        g_pending.clear();
        // 启动日志打印构建时间戳（由 CMake 注入 BUILD_TIMESTAMP 宏），
        // 便于一眼区分当前运行的是哪次构建的 exe——
        // 排查「到底换没换 exe」的利器：时间戳对不上就是还在跑旧构建。
#ifdef BUILD_TIMESTAMP
        PostLog(std::wstring(L"构建时间：") + util::Utf8ToWide(BUILD_TIMESTAMP));
#endif
        // 载入记住的目录与密码，随 init 一并回传，方便重开软件直接下载
        config::AppState st; config::LoadState(st);
        PostJson(BuildInit(st.password, st.downloadPassword));
        // 把软件图标（base64）推给页面，供头部图标使用
        if (!g_appIconB64.empty()) PostJson(BuildIcon(g_appIconB64));
        // 回填上次记住的 saves 目录（若仍有效）
        if (!st.savesDir.empty()) {
            bool has = lolfind::HasMarker(st.savesDir);
            if (has) g_lastDir = st.savesDir;   // 记住回填的目录，关闭时不会被覆盖成空
            PostJson(BuildDir(st.savesDir, has ? 1 : 2,
                has ? (OBFW("5qCh6aqM6YCa6L+H77yM5bey5om+5YiwIEhhbmJvdCDnm67lvZXjgII="))
                    : (OBFW("5qCh6aqM5aSx6LSl77yM5pyq5om+5YiwIEhhbmJvdCDnm67lvZXvvIzor7fmiYvliqjpgInmi6njgII="))));
        }
    }
    else if (type == "health") {
        std::thread(ConnThread).detach();
    }
    else if (type == "detect") {
        std::thread(DetectThread).detach();
    }
    else if (type == "pick") {
        std::wstring p = PickFolder(g_hMain);
        if (!p.empty()) {
            bool has = lolfind::HasMarker(p);
            if (has) g_lastDir = p;   // 手动选择的目录也要记住，关闭时写入 ini
            int vs = has ? 1 : 2;
            std::wstring vt = has ? (OBFW("5qCh6aqM6YCa6L+H77yM5bey5om+5YiwIEhhbmJvdCDnm67lvZXjgII="))
                                  : (OBFW("5qCh6aqM5aSx6LSl77yM5pyq5om+5YiwIEhhbmJvdCDnm67lvZXvvIzor7fmiYvliqjpgInmi6njgII="));
            PostJson(BuildDir(p, vs, vt));
            PostLog(OBFW("5bey5omL5Yqo6YCJ5oup77ya") + p);
            if (!has) PostLog(L"注意：该目录里没有 " MARKER_FILE_W L"，无法上传");
        }
    }
    else if (type == "upload") {
        std::wstring dir = util::Utf8ToWide(j->GetStr("dir"));
        std::wstring pwd = util::Utf8ToWide(j->GetStr("password"));
        g_lastDir = dir;
        g_currentPwd = pwd;
        if (dir.empty() || !lolfind::HasMarker(dir)) {
            PostJson(BuildDone(false, false, false, false,
                L"当前目录无效，必须是包含 " MARKER_FILE_W L" 的 saves 目录",
                L"", OBFW("5peg5rOV5LiK5Lyg"), OBFW("5peg5rOV5LiK5Lyg"), false));
            return;
        }
        if (!util::IsValidPassword(pwd)) {
            PostJson(BuildDone(false, false, false, false,
                OBFW("6K+35YWI5Zyo5a+G56CB5qGG6L6T5YWlIDQtMjQg5L2N5a2X5q+N5oiW5pWw5a2X5a+G56CB"),
                L"", OBFW("57y65bCR5a+G56CB"), OBFW("57y65bCR5a+G56CB"), false));
            return;
        }
        std::thread(UploadThread, dir, pwd).detach();
    }
    else if (type == "download") {
        std::wstring dir = util::Utf8ToWide(j->GetStr("dir"));
        std::wstring dlPwd = util::Utf8ToWide(j->GetStr("dlpassword"));
        g_lastDir = dir;
        g_currentDlPwd = dlPwd;
        if (dir.empty() || !util::DirectoryExists(dir)) {
            PostJson(BuildDone(false, false, true, false,
                OBFW("6K+35YWI6YCJ5oup6KaB6Kej5Y6L5Yiw55qEIHNhdmVzIOebruW9lQ=="), L"", OBFW("57y65bCR55uu5b2V"), OBFW("57y65bCR55uu5b2V"), false));
            return;
        }
        if (!lolfind::HasMarker(dir)) {
            PostJson(BuildDone(false, false, true, false,
                L"该目录没有 " MARKER_FILE_W L"，不是有效的 saves 目录",
                L"", OBFW("55uu5b2V5peg5pWI"), OBFW("55uu5b2V5peg5pWI"), false));
            return;
        }
        if (!util::IsValidDownloadPassword(dlPwd)) {
            PostJson(BuildDone(false, false, true, false,
                OBFW("5Y+W5Zue5a+G56CB5qC85byP5LiN5q2j56Gu77yI5bqU5Li6IFNLLSDlvIDlpLTvvIzlhbEgMjMg5L2N77yJ"), L"", OBFW("57y65bCR5a+G56CB"), OBFW("57y65bCR5a+G56CB"), false));
            return;
        }
        std::thread(DownloadThread, dir, dlPwd).detach();
    }
    else if (type == "copy") {
        std::wstring text = util::Utf8ToWide(j->GetStr("text"));
        util::CopyTextToClipboard(g_hMain, text);
        PostLog(OBFW("57uT5p6c5bey5aSN5Yi25Yiw5Ymq6LS05p2/"));
    }
    else if (type == "minimize") {
        ::ShowWindow(g_hMain, SW_MINIMIZE);
    }
    else if (type == "close") {
        ::PostMessageW(g_hMain, WM_CLOSE, 0, 0);
    }
    else if (type == "maximize") {
        if (::IsZoomed(g_hMain)) ::ShowWindow(g_hMain, SW_RESTORE);
        else ::ShowWindow(g_hMain, SW_MAXIMIZE);
    }
    else if (type == "drag") {
        ::ReleaseCapture();
        ::SendMessageW(g_hMain, WM_SYSCOMMAND, SC_MOVE | HTCAPTION, 0);
    }
    else if (type == OBFA("Y2hlY2tQYXNzd29yZA==")) {
        // 仅「随机生成密码」按钮会发此消息：生成一个后端确认未使用过的密码。
        // 手动输入密码不再查重（同密码上传 = 覆盖更新原存档）。
        std::wstring pwd = util::Utf8ToWide(j->GetStr("password"));
        if (!pwd.empty()) std::thread(CheckPwdThread, pwd).detach();
    }
    else if (type == "password") {
        // 「上传密码」框每次变化都回传，关闭时据此写入 uploader.ini（为空即写空）
        g_currentPwd = util::Utf8ToWide(j->GetStr("password"));
    }
    else if (type == "dlpassword") {
        // 「取回密码」框每次变化都回传，关闭时据此写入 uploader.ini（为空即写空）
        g_currentDlPwd = util::Utf8ToWide(j->GetStr("dlpassword"));
    }
}

// ---------------------------------------------------------------------------
// 结果处理（Outcome -> 页面）
// ---------------------------------------------------------------------------
void HandleOutcome(uploader::Outcome* r) {
    if (!r) return;

    std::wstring resultText, resultLabel, stage;
    bool ok = r->ok, canceled = r->canceled, isDownload = r->isDownload, pwdWrong = r->passwordWrong;
    bool copyEnabled = false;

    if (canceled) {
        stage = OBFW("5bey5Y+W5raI");
    } else if (!ok) {
        if (pwdWrong) {
            stage = OBFW("5a+G56CB6ZSZ6K+v");
            resultText = OBFW("5a+G56CB5LiN5q2j56Gu77yM5peg5rOV6Kej5a+G6K+l5Y6L57yp5YyF44CCDQror7fnoa7orqTkuIvovb3ml7bkvb/nlKjnmoTlr4bnoIHkuI7kuIrkvKDml7bkuIDoh7TjgII=");
        } else {
            stage = isDownload ? OBFW("5LiL6L295aSx6LSl") : OBFW("5LiK5Lyg5aSx6LSl");
            resultText = r->error;
        }
    } else if (isDownload) {
        // 下载并解压：结果框不展示明细（用户要求只给一句完成提示），复制按钮置灰
        resultText  = OBFW("5LiL6L295bm26Kej5Y6L5a6M5oiQ");   // 下载并解压完成
        resultLabel = OBFW("5LiL6L2957uT5p6c");               // 下载结果
        stage = OBFW("5LiL6L296Kej5Y6L5a6M5oiQ");             // 下载解压完成
        copyEnabled = false;
    } else {
        // 上传成功：只展示「请记好以下信息」+ 上传密码 + 取回密码（最简，便于手抄保存）
        resultText  = OBFW("PT09PT09PT3or7forrDlpb3ku6XkuIvkv6Hmga89PT09PT09PQ==");  // ========请记好以下信息========
        resultText += OBFW("DQo=");
        resultText += OBFW("5LiK5Lyg5a+G56CBOiA=") + r->password;                     // 上传密码: 
        resultText += OBFW("DQo=");
        // 后端随上传返回的「取回密码」（SK- 开头）也要展示出来，方便用户复制分享给朋友取回
        if (!r->downloadPassword.empty())
            resultText += OBFW("5Y+W5Zue5a+G56CBOiA=") + r->downloadPassword;
        else {
            // 孤儿存档：文件已上传但服务端登记失败（取回密码为空），结果框必须明确警告，
            // 不能只丢个上传密码让人误以为正常——否则用户会拿不到取回密码、下载 404。
            resultText += OBFW("DQo=");
            resultText += OBFW("4pqgIOitpuWRiu+8muacjeWKoeWZqOeZu+iusOWksei0pe+8jOaWh+S7tuW3suS4iuS8oOS9huacjeWKoeerr+ayoeacieeZu+iusOiusOW9le+8jOWPluWbnuWvhueggeaXoOazleeUn+aIkOOAgeS4i+i9veS8muaPkOekuiA0MDTjgIIK6K+35L+d5a2Y5LiK5pa55LiK5Lyg5a+G56CB5bm26IGU57O7566h55CG5ZGY5L+u5aSN77yb5pqC5pe25LiN6KaB55So5ZCM5LiA5Liq5LiK5Lyg5a+G56CB5YaN5qyh5LiK5Lyg77yI5Lya5YaN5Lqn55Sf5LiA5Liq5Y+W5Zue5LiN5LqG55qE5a2k5YS/5paH5Lu277yJ44CC");
        }
        resultLabel = OBFW("5LiK5Lyg57uT5p6c77yI6K+35L+d5a2Y5a+G56CB77yJ");          // 上传结果（请保存密码）
        stage = OBFW("5LiK5Lyg5a6M5oiQ");                                           // 上传完成
        copyEnabled = true;

        // 上传成功后把后端返回的取回密码(SK-) 回填「取回密码」框并写入 config：
        // ① 上传者自己能在软件里看到/复制自己的取回码；② 关闭时 DownloadPassword 不再为空。
        if (!r->downloadPassword.empty()) {
            g_currentDlPwd = r->downloadPassword;
            PostJson(BuildFillDlPwd(r->downloadPassword));
        }
    }

    // 防御：理论上上传成功必带结果文案；万一为空（异常路径）也兜底给一句，避免结果框空白。
    if (ok && !canceled && !isDownload && resultText.empty()) {
        resultText = OBFW("5LiK5Lyg5a6M5oiQ77yM6K+35L+d5L+d5a2Y5a+G56CB");   // 上传完成，请保存密码
    }

    if (ok && !canceled) {
        g_lastResultText = resultText; g_uploadDone.store(true);
    }

    if (ok && !canceled && !isDownload) {
        // 已移除自动复制剪贴板：结果展示在「操作结果」框，用户自行点「复制结果」复制
        // 上传成功：运行日志不再打印「===== 上传成功，请立即保存下方密码 =====」（用户要求不显示），
        // 密码信息只在「操作结果」框展示（见上方上传成功分支）。
        // 「结果已自动复制到剪贴板」提示已移除：结果展示在「操作结果」框，用户自行点「复制结果」复制
    } else if (ok && !canceled && isDownload) {
        PostLog(OBFW("PT09PT0g5LiL6L295bm26Kej5Y6L5a6M5oiQ77yM5paH5Lu25bey6KaG55uW6Iez55uu5qCH55uu5b2VID09PT09"));
    } else if (!ok && !canceled) {
        if (pwdWrong) PostLog(OBFW("5a+G56CB6ZSZ6K+v77yM5peg5rOV6Kej5a+G5Y6L57yp5YyF"));
        else PostLog(OBFW("5pON5L2c5aSx6LSl77ya") + r->error);
    } else if (canceled) {
        PostLog(OBFW("5pON5L2c5bey5Y+W5raI"));
    }

    PostJson(BuildDone(ok, canceled, isDownload, pwdWrong, r->error,
                       resultText, resultLabel, stage, copyEnabled));
    delete r;
    PostJson(BuildBusy(false));
}

// ---------------------------------------------------------------------------
// WebView2 初始化
// ---------------------------------------------------------------------------
void InitWebView2(HWND hwnd) {
    // userDataFolder 必须存在，但绝不放程序目录（避免污染安装位置、被误删、或被便携化工具打包带走）。
    // 重定向到系统临时目录：%TEMP%\HanbotWebView2。WebView2 运行时数据（缓存/Cookie/GPU 缓存等）都在此，
    // 程序目录不再生成任何 webview2_cache 文件夹。注：WebView2 必须有 userDataFolder，无法彻底"不生成"，
    // 只能移走；临时目录下的该文件夹可被系统清理策略安全回收。
    std::wstring udf = util::GetTempDir() + OBFW("XEhhbmJvdFdlYlZpZXcy");
    ::CreateDirectoryW(udf.c_str(), nullptr);

    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        nullptr, udf.c_str(), nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [hwnd](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
                if (FAILED(hr)) {
                    ::MessageBoxW(hwnd,
                        OBFW("V2ViVmlldzIg5Yid5aeL5YyW5aSx6LSl77ya5pyq6IO95Yib5bu6546v5aKD44CCDQror7fnoa7orqTns7vnu5/lt7Llronoo4UgV2ViVmlldzIgUnVudGltZe+8iEVkZ2Ug5rWP6KeI5Zmo6Ieq5bim77yM5oiW5Yiw5b6u6L2v5a6Y572R5LiL6L295a6J6KOF77yJ44CC"),
                        APP_TITLE_W, MB_OK | MB_ICONERROR);
                    return hr;
                }
                env->CreateCoreWebView2Controller(hwnd,
                    Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                        [hwnd](HRESULT hr, ICoreWebView2Controller* ctrl) -> HRESULT {
                            if (FAILED(hr) || !ctrl) {
                                ::MessageBoxW(hwnd, OBFW("V2ViVmlldzIg5Yid5aeL5YyW5aSx6LSl77ya5pyq6IO95Yib5bu65o6n5Yi25Zmo44CC"),
                                               APP_TITLE_W, MB_OK | MB_ICONERROR);
                                return hr;
                            }
                            g_controller = ctrl;
                            ctrl->get_CoreWebView2(&g_webview);
                            if (!g_webview) return E_FAIL;

                            // 精装环境选项：禁右键/DevTools/状态栏/缩放
                            ComPtr<ICoreWebView2Settings> settings;
                            if (SUCCEEDED(g_webview->get_Settings(&settings)) && settings) {
                                settings->put_AreDefaultContextMenusEnabled(FALSE);
                                settings->put_AreDevToolsEnabled(FALSE);
                                settings->put_IsStatusBarEnabled(FALSE);
                                settings->put_IsZoomControlEnabled(FALSE);

                                // 以下三项在派生接口（Settings4/5），需 As() 做 QueryInterface；
                                // 旧版 SDK 若没有这些接口则跳过，不影响核心功能。
                                ComPtr<ICoreWebView2Settings4> s4;
                                if (SUCCEEDED(settings.As(&s4)) && s4) {
                                    s4->put_IsGeneralAutofillEnabled(FALSE);
                                    s4->put_IsPasswordAutosaveEnabled(FALSE);
                                }
                                // 注：AreBrowserExtensionsEnabled 在最新 SDK 中已挪到 ICoreWebView2EnvironmentOptions6
                                // （环境级选项，需在创建环境时传入 options，而非运行时 setting），且对应用无意义，故不调用。
                            }
                            ctrl->put_ZoomFactor(1.0);
                            ctrl->put_IsVisible(TRUE);

                            // 消息桥接
                            EventRegistrationToken token{};
                            g_webview->add_WebMessageReceived(
                                Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                                    [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                                        LPWSTR raw = nullptr;
                                        // 新版 WebView2 SDK 用 TryGetWebMessageAsString 取代老版 get_WebMessageAsString
                                        // （两者均为单参数 LPWSTR*）。用 __if_exists 编译期适配两套 SDK。
                                        __if_exists(ICoreWebView2WebMessageReceivedEventArgs::TryGetWebMessageAsString) {
                                            args->TryGetWebMessageAsString(&raw);
                                        }
                                        __if_not_exists(ICoreWebView2WebMessageReceivedEventArgs::TryGetWebMessageAsString) {
                                            args->get_WebMessageAsString(&raw);
                                        }
                                        std::wstring msg(raw ? raw : L"");
                                        if (raw) ::CoTaskMemFree(raw);
                                        HandlePageMessage(msg);
                                        return S_OK;
                                    }).Get(), &token);

                            // 铺满客户区
                            RECT rc{};
                            ::GetClientRect(hwnd, &rc);
                            ctrl->put_Bounds(rc);

                            // 载入内嵌 HTML
                            std::wstring html = LoadAppHtml();
                            HRESULT navHr = E_FAIL;
                            if (!html.empty()) {
                                navHr = NavigateWithFallback(g_webview.Get(), html);
                            }
                            if (html.empty() || FAILED(navHr)) {
                                std::wstring err = OBFW("5pyq6IO95Yqg6L295bqU55So55WM6Z2i44CCCg==");
                                if (html.empty())
                                    err += OBFW("5Y6f5Zug77ya5peg5rOV5LuOIGV4ZSDlhoXltYzotYTmupDor7vlj5YgSFRNTO+8iElEUl9BUFBfSFRNTCDlj6/og73nvLrlpLHmiJbkuLrnqbrvvInjgIIK");
                                else
                                    err += OBFW("5Y6f5Zug77yaTmF2aWdhdGVUb1N0cmluZyDkuI7kuLTml7bmlofku7blm57pgIDlnYflpLHotKXjgIIK");
                                err += OBFW("6K+35bCd6K+V6YeN5paw5p6E5bu677yM5oiW6IGU57O75oqA5pyv5pSv5oyB44CC");
                                ::MessageBoxW(hwnd, err.c_str(), APP_TITLE_W, MB_OK | MB_ICONERROR);
                            }

                            return S_OK;
                        }).Get());
                return S_OK;
            }).Get());
    (void)hr;
}

// ---------------------------------------------------------------------------
// 圆角窗口区域
// ---------------------------------------------------------------------------
void UpdateWindowRgn(HWND hwnd) {
    if (!g_useRgn) return;
    RECT rc{};
    ::GetClientRect(hwnd, &rc);
    HRGN rgn = ::CreateRoundRectRgn(rc.left, rc.top, rc.right, rc.bottom, S(16), S(16));
    if (rgn) {
        ::SetWindowRgn(hwnd, rgn, TRUE);
        ::DeleteObject(rgn);
    }
}

// ---------------------------------------------------------------------------
// 窗口过程
// ---------------------------------------------------------------------------
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {

    case WM_CREATE: {
        g_hMain = hwnd;
        g_dpi = QueryWindowDpi(hwnd);
        if (g_dpi <= 0) g_dpi = 96;
        g_titleH = S(42);

        // Win11：用 DWM 原生圆角（自带阴影）；Win10：用 rgn + CS_DROPSHADOW
        int pref = 2; // DWMWCP_ROUND
        if (SUCCEEDED(::DwmSetWindowAttribute(hwnd, 33 /*DWMWA_WINDOW_CORNER_PREFERENCE*/,
                                             &pref, sizeof(pref))))
            g_useRgn = false;

        UpdateWindowRgn(hwnd);

        // 启动工作线程：后端连接检测 / saves 目录检测
        // WebView2 初始化移到 ShowWindow 之后，确保父窗口已可见，避免部分机器上控制器创建后白屏
        std::thread(ConnThread).detach();
        // 本机已记住有效 saves 目录 → 跳过全盘扫描（避免每次打开软件都扫盘）；
        // 只有没记住或记住的目录已失效时才自动检测。
        config::AppState st0; config::LoadState(st0);
        bool haveSaved = !st0.savesDir.empty() && lolfind::HasMarker(st0.savesDir);
        if (!haveSaved) {
            std::thread(DetectThread).detach();
        }
        return 0;
    }

    case WM_DPICHANGED: {
        g_dpi = HIWORD(wp);
        g_titleH = S(42);
        RECT* nr = (RECT*)lp;
        ::SetWindowPos(hwnd, nullptr, nr->left, nr->top,
                       nr->right - nr->left, nr->bottom - nr->top,
                       SWP_NOZORDER | SWP_NOACTIVATE);
        UpdateWindowRgn(hwnd);
        return 0;
    }

    case WM_SIZE:
        if (g_controller) {
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            g_controller->put_Bounds(rc);
        }
        UpdateWindowRgn(hwnd);
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = S(680);
        // 最小高度从 640 抬到 720：640 时下半部日志区只剩约 72px，3 行日志就出滚动条。
        // 720 才能保证「运行日志」+「操作结果」两框在最小窗口下都舒服放下、不出滚动条。
        mmi->ptMinTrackSize.y = S(720);
        return 0;
    }

    case WM_APP_LOG: {
        auto* s = (std::wstring*)lp;
        if (s) { PostJson(BuildLog(*s)); delete s; }
        return 0;
    }

    case WM_APP_PROGRESS: {
        int permille = (int)wp;
        if (permille < 0) permille = 0;
        if (permille > 1000) permille = 1000;
        std::wstring stage;
        auto* s = (std::wstring*)lp;
        if (s) { stage = *s; delete s; }
        PostJson(BuildProgress(permille, stage));
        return 0;
    }

    case WM_APP_DETECT_DONE: {
        auto* results = (std::vector<lolfind::Candidate>*)lp;
        std::wstring path; int vs = 0; std::wstring vt;
        if (!results || results->empty()) {
            vs = 2; vt = OBFW("5qCh6aqM5aSx6LSl77yM5pyq5om+5YiwIEhhbmJvdCDnm67lvZXvvIzor7fmiYvliqjpgInmi6njgII=");
        } else {
            path = (*results)[0].savesPath;
            if (!path.empty()) g_lastDir = path;   // 记住扫描到的目录，关闭时写入 ini，避免下次再全盘扫
            vs = lolfind::HasMarker(path) ? 1 : 2;
            vt = vs == 1 ? (OBFW("5qCh6aqM6YCa6L+H77yM5bey5om+5YiwIEhhbmJvdCDnm67lvZXjgII="))
                         : (OBFW("5qCh6aqM5aSx6LSl77yM5pyq5om+5YiwIEhhbmJvdCDnm67lvZXvvIzor7fmiYvliqjpgInmi6njgII="));
        }
        delete results;
        PostJson(BuildDetectDone(path, vs, vt));
        PostJson(BuildBusy(false));
        return 0;
    }

    case WM_APP_UPLOAD_DONE:
        HandleOutcome((uploader::Outcome*)lp);
        return 0;

    case WM_APP_SET_BUSY:
        PostJson(BuildBusy(wp != 0));
        return 0;

    case WM_APP_CONN: {
        auto* r = (uploader::HealthResult*)lp;
        if (r) {
            PostJson(BuildConn(r->ok ? 1 : 2, (r->ok ? OBFW("4pyTIA==") : OBFW("w5cg")) + r->message));
            delete r;
        }
        return 0;
    }

    case WM_APP_PWD_CHECK: {
        auto* p = (PwdCheckResult*)lp;
        if (p) {
            PostJson(BuildPasswordChecked(p->password, p->exists));
            delete p;
        }
        return 0;
    }

    case WM_CLOSE:
        if (g_busy.load()) {
            // 任务进行中：原「确认中止」弹框已按用户要求移除，直接发取消信号让工作线程收尾。
            g_cancel.store(true);
            ::Sleep(200);
        }
        // 关闭时把当前目录与密码写入 uploader.ini 的 [State] 段（密码为空则写空），方便重开直接下载
        config::SaveState(g_lastDir, g_currentPwd, g_currentDlPwd);
        if (g_uploadDone.load() && !g_lastResultText.empty()) {
            // 原「密码已自动保存，是否确认退出」确认框已按用户要求移除：直接退出即可。
            (void)g_lastResultText;
        }
        ::DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        g_cancel.store(true);
        ::PostQuitMessage(0);
        return 0;

    default: break;
    }

    return ::DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
// DPI 感知（运行时探测，兼容老系统）
// ---------------------------------------------------------------------------
void EnableDpiAwareness() {
    HMODULE user32 = ::GetModuleHandleW(OBFW("dXNlcjMyLmRsbA=="));
    if (user32) {
        using SetCtxFn = BOOL (WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto setCtx = (SetCtxFn)::GetProcAddress(user32, OBFA("U2V0UHJvY2Vzc0RwaUF3YXJlbmVzc0NvbnRleHQ="));
        if (setCtx && setCtx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) return;
    }

    HMODULE shcore = ::LoadLibraryW(OBFW("c2hjb3JlLmRsbA=="));
    if (shcore) {
        using SetAwareFn = HRESULT (WINAPI*)(int);
        auto setAware = (SetAwareFn)::GetProcAddress(shcore, OBFA("U2V0UHJvY2Vzc0RwaUF3YXJlbmVzcw=="));
        if (setAware) { setAware(2 /* PROCESS_PER_MONITOR_DPI_AWARE */); ::FreeLibrary(shcore); return; }
        ::FreeLibrary(shcore);
    }

    ::SetProcessDPIAware();
}

} // namespace

// ===========================================================================
// 入口
// ===========================================================================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    g_hInst = hInst;

    // 预读取软件图标（base64），待页面 ready 后注入头部
    g_appIconB64 = LoadAppIconBase64();

    EnableDpiAwareness();
    ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS | ICC_WIN95_CLASSES };
    ::InitCommonControlsEx(&icc);

    config::Load();
    config::WriteTemplateIfMissing();

    // 只允许运行一个实例
    HANDLE mutex = ::CreateMutexW(nullptr, TRUE, OBFW("R2xvYmFsXEhhbmJvdFNhdmVzVXBsb2FkZXJfU2luZ2xlSW5zdGFuY2U="));
    if (mutex && ::GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND exist = ::FindWindowW(OBFW("SGFuYm90VXBsb2FkZXJXbmRDbGFzcw=="), nullptr);
        if (exist) {
            ::ShowWindow(exist, SW_RESTORE);
            ::SetForegroundWindow(exist);
        }
        return 0;
    }

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.style         = CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = OBFW("SGFuYm90VXBsb2FkZXJXbmRDbGFzcw==");
    wc.hIcon         = ::LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_APP_ICON));
    wc.hIconSm       = ::LoadIconW(g_hInst, MAKEINTRESOURCEW(IDI_APP_ICON));

    if (!::RegisterClassExW(&wc)) {
        ::MessageBoxW(nullptr, OBFW("56qX5Y+j5rOo5YaM5aSx6LSl"), APP_TITLE_W, MB_OK | MB_ICONERROR);
        return 1;
    }

    // 依据主显示器 DPI 预估初始窗口大小
    {
        HDC screen = ::GetDC(nullptr);
        if (screen) {
            const int dpi = ::GetDeviceCaps(screen, LOGPIXELSX);
            if (dpi > 0) g_dpi = dpi;
            ::ReleaseDC(nullptr, screen);
        }
    }

    // 期望的客户区尺寸（逻辑像素，S() 按 DPI 放大）。
    // 高度给到 840（与 HTML 里 .window 的预览高度一致）：页面内容（连接条 + 目录 + 密码 + 双按钮 + 进度 + 5 行日志 + 结果区 + 页脚）
    // 大约需要 700px，840 给足余量，避免下半部被挤压后互相重叠。最小高度仍由 WM_GETMINMAXINFO 限制为 720（小屏可拖小、不超屏）。
    RECT wr{ 0, 0, S(760), S(840) };
    ::AdjustWindowRectEx(&wr, WS_POPUP | WS_SYSMENU, FALSE, 0);

    int winW = wr.right - wr.left;
    int winH = wr.bottom - wr.top;

    // 夹到桌面工作区内：150% / 175% 缩放的小屏笔记本上，S(800) 可能比屏幕还高，
    // 不夹取的话窗口会跑出屏幕，页面被压扁，控件就叠在一起了。
    int x = 0, y = 0;
    RECT wa{};
    if (::SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0) &&
        wa.right > wa.left && wa.bottom > wa.top) {
        const int availW = wa.right - wa.left;
        const int availH = wa.bottom - wa.top;
        if (winW > availW) winW = availW;
        if (winH > availH) winH = availH;
        x = wa.left + (availW - winW) / 2;
        y = wa.top + (availH - winH) / 2;
    } else {
        x = (::GetSystemMetrics(SM_CXSCREEN) - winW) / 2;
        y = (::GetSystemMetrics(SM_CYSCREEN) - winH) / 2;
    }

    HWND hwnd = ::CreateWindowExW(0, wc.lpszClassName, APP_TITLE_W,
                                  WS_POPUP | WS_SYSMENU,
                                  x >= 0 ? x : CW_USEDEFAULT,
                                  y >= 0 ? y : CW_USEDEFAULT,
                                  winW, winH,
                                  nullptr, nullptr, hInst, nullptr);
    if (!hwnd) {
        ::MessageBoxW(nullptr, OBFW("56qX5Y+j5Yib5bu65aSx6LSl"), APP_TITLE_W, MB_OK | MB_ICONERROR);
        return 1;
    }

    ::ShowWindow(hwnd, nCmdShow);
    ::UpdateWindow(hwnd);

    // 窗口显示后再初始化 WebView2：确保父窗口已可见，规避部分环境下控制器创建后白屏
    InitWebView2(hwnd);

    MSG msg{};
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!::IsDialogMessageW(hwnd, &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
    }

    if (mutex) ::CloseHandle(mutex);
    ::CoUninitialize();

    return (int)msg.wParam;
}
