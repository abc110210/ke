#include "uploader.h"
#include "config.h"
#include "util.h"
#include "zip_writer.h"
#include "zip_reader.h"
#include "http_client.h"
#include "json_mini.h"
#include "lol_finder.h"

#include <windows.h>

namespace uploader {

namespace {

http::Timeouts MakeTimeouts() {
    http::Timeouts t;
    t.connectMs = config::ConnectTimeoutMs;
    t.sendMs    = config::SendTimeoutMs;
    t.recvMs    = config::RecvTimeoutMs;
    return t;
}

// 发送前自检请求体是否为合法 JSON 对象。
// 手拼 JSON 曾因字段间漏逗号导致服务端 400（还误以为是版本/网络问题），
// 这里兜底：拼坏了客户端直接报内部错误，而不是发一个坏请求出去。
bool JsonOk(const std::string& s) {
    auto v = json::Parse(s);
    return v && v->IsObject();
}

// 请求体脱敏（密码打码），用于 JsonOk 失败时打日志排查——UI 日志对用户可见，
// 不能直接把密码打出去。
std::wstring MaskedJsonForLog(const std::string& s) {
    std::string m = s;
    const std::string marker = "\"password\":\"";
    std::size_t p = m.find(marker);
    if (p != std::string::npos) {
        std::size_t q = m.find('"', p + marker.size());
        if (q != std::string::npos)
            m.replace(p + marker.size(), q - p - marker.size(), "***");
    }
    return util::Utf8ToWide(m);
}

std::vector<http::Header> AuthHeaders() {
    std::vector<http::Header> h;
    h.emplace_back(OBFW("WC1DbGllbnQtS2V5"), util::Utf8ToWide(config::ClientKey));
    h.emplace_back(OBFW("WC1DbGllbnQtVmVyc2lvbg=="), APP_VERSION_W);
    return h;
}

// 临时文件自动清理
class ScopedTempFile {
public:
    explicit ScopedTempFile(std::wstring path) : path_(std::move(path)) {}
    ~ScopedTempFile() {
        if (!keep_ && !path_.empty()) {
            ::SetFileAttributesW(path_.c_str(), FILE_ATTRIBUTE_NORMAL);
            ::DeleteFileW(path_.c_str());
        }
    }
    void Keep() { keep_ = true; }
    const std::wstring& Path() const { return path_; }

private:
    std::wstring path_;
    bool         keep_ = false;
};

std::wstring PrettyHttpError(const http::Response& r, const std::wstring& what) {
    if (!r.error.empty()) return what + OBFW("77ya") + r.error;

    std::wstring detail;
    if (!r.body.empty()) {
        auto v = json::Parse(r.body);
        if (v && v->IsObject()) {
            const std::string m = v->GetStr("message", v->GetStr("error", ""));
            if (!m.empty()) detail = OBFW("77yM5pyN5Yqh5Zmo5o+Q56S677ya") + util::Utf8ToWide(m);
        }
        if (detail.empty()) {
            std::string b = r.body.substr(0, 300);
            detail = OBFW("77yM6L+U5Zue5YaF5a6577ya") + util::Utf8ToWide(b);
        }
    }

    wchar_t buf[64]{};
    ::swprintf(buf, 64, OBFW("77yISFRUUCAlZO+8iQ=="), r.status);
    return what + buf + detail;
}

} // namespace

// ===========================================================================
Outcome Run(const std::wstring& savesDir,
            const std::wstring& password,
            const LogFn& log,
            const ProgressFn& progress,
            const std::atomic<bool>* cancel) {
    Outcome out;

    auto L = [&](const std::wstring& s) { if (log) log(s); };
    auto P = [&](int permille, const std::wstring& stage) { if (progress) progress(permille, stage); };
    auto Canceled = [&]() { return cancel && cancel->load(); };

    // ---------------- 0. 前置校验 ----------------
    P(0, OBFW("5qOA5p+l55uu5b2V"));
    if (savesDir.empty() || !util::DirectoryExists(savesDir)) {
        out.error = OBFW("55uu5b2V5LiN5a2Y5Zyo77yM6K+35YWI5qOA5rWL5oiW5omL5Yqo6YCJ5oupIHNhdmVzIOebruW9lQ==");
        return out;
    }
    if (!lolfind::HasMarker(savesDir)) {
        out.error = L"该目录里没有找到 " MARKER_FILE_W L"，不是有效的 saves 目录";
        return out;
    }
    if (!util::IsValidPassword(password)) {
        out.error = OBFW("5a+G56CB5b+F6aG75pivIDQtMjQg5L2N5a2X5q+N5oiW5pWw5a2X");
        return out;
    }
    L(OBFW("55uu5qCH55uu5b2V77ya") + savesDir);

    // ---------------- 1. 扫描 ----------------
    P(10, OBFW("5q2j5Zyo5omr5o+P5paH5Lu2"));
    std::vector<zipw::Entry> entries;
    zipw::ScanResult scan = zipw::ScanDirectory(savesDir, OBFW("c2F2ZXM="), entries, cancel);
    if (Canceled()) { out.canceled = true; out.error = OBFW("5bey5Y+W5raI"); return out; }
    if (!scan.ok) { out.error = scan.error.empty() ? OBFW("5omr5o+P55uu5b2V5aSx6LSl") : scan.error; return out; }

    {
        wchar_t buf[256]{};
        ::swprintf(buf, 256, OBFW("5YWxICVsbHUg5Liq5paH5Lu244CBJWxsdSDkuKrlrZDnm67lvZXvvIzljp/lp4vlpKflsI8gJXM="),
                   (unsigned long long)scan.fileCount,
                   (unsigned long long)scan.dirCount,
                   util::FormatSize(scan.totalBytes).c_str());
        L(buf);
    }

    if (scan.fileCount == 0) {
        out.error = OBFW("55uu5b2V6YeM5rKh5pyJ5Lu75L2V5paH5Lu277yM5peg6ZyA5LiK5Lyg");
        return out;
    }
    // 体积上限由服务端 MAX_UPLOAD_BYTES 校验，客户端不再做本地拦截。

    // ---------------- 2. 使用用户输入的密码 ----------------
    const std::string pw = util::WideToUtf8(password);
    out.password = password;
    L(OBFW("5bCG5L2/55So5oKo6L6T5YWl55qE5a+G56CB6L+b6KGM5Yqg5a+G5omT5YyF77yI6K+35Yqh5b+F54mi6K6w5q2k5a+G56CB77yM5LiL6L295pe26ZyA55So5ZCM5LiA5a+G56CB77yJ"));

    // ---------------- 3. 打包 ----------------
    const std::wstring stamp = util::TimestampCompact();
    const std::wstring machine = util::MachineId();
    const std::wstring zipName = OBFW("c2F2ZXNf") + machine + OBFW("Xw==") + stamp + OBFW("LnppcA==");
    const std::wstring zipPath = util::JoinPath(util::GetTempDir(), OBFW("aGFuYm90Xw==") + zipName);

    ScopedTempFile temp(zipPath);

    P(60, OBFW("5q2j5Zyo5omT5YyF"));
    L(OBFW("5q2j5Zyo5Yqg5a+G5omT5YyF77yM6K+356iN5YCZLi4u"));

    auto packProgress = [&](unsigned long long done, unsigned long long total,
                            const std::wstring& cur) -> bool {
        if (Canceled()) return false;
        int permille = 60;
        if (total > 0) {
            // 打包阶段占总进度 60‰ ~ 550‰
            permille = 60 + (int)((done * 490ull) / total);
            if (permille > 550) permille = 550;
        }
        std::wstring shortName = cur;
        if (shortName.size() > 48) shortName = OBFW("Li4u") + shortName.substr(shortName.size() - 45);
        P(permille, OBFW("5omT5YyF5LitIA==") + shortName);
        return true;
    };

    zipw::PackResult pack = zipw::CreateEncryptedZip(zipPath, entries, pw, packProgress, cancel);
    if (Canceled() || pack.error == OBFW("5bey5Y+W5raI")) { out.canceled = true; out.error = OBFW("5bey5Y+W5raI"); return out; }
    if (!pack.ok) { out.error = pack.error.empty() ? OBFW("5omT5YyF5aSx6LSl") : pack.error; return out; }

    out.rawBytes  = pack.rawBytes;
    out.zipBytes  = pack.zipBytes;
    out.fileCount = pack.fileCount;
    out.skipped   = pack.skipped;

    {
        wchar_t buf[256]{};
        ::swprintf(buf, 256, OBFW("5omT5YyF5a6M5oiQ77yaJXMgLT4gJXPvvIglbGx1IOS4quaWh+S7tiVz77yJ"),
                   util::FormatSize(pack.rawBytes).c_str(),
                   util::FormatSize(pack.zipBytes).c_str(),
                   (unsigned long long)pack.fileCount,
                   pack.skipped ? OBFW("77yM5Y+m5pyJ6YOo5YiG5paH5Lu26KKr5Y2g55So5bey6Lez6L+H") : L"");
        L(buf);
    }

    // ---------------- 4. 申请上传凭证 ----------------
    P(560, OBFW("5q2j5Zyo55Sz6K+35LiK5Lyg5Yet6K+B"));
    L(OBFW("5q2j5Zyo5ZCR5pyN5Yqh5Zmo55Sz6K+35LiK5Lyg5Yet6K+BLi4u"));

    std::string reqJson;
    {
        // 用普通字符串字面量拼装（与可正常工作的旧备份一致），由混淆工具在构建后统一混淆。
        // 之前手写为 OBFA(...) base64 字面量，混淆工具因幂等保护跳过、未重新混淆，
        // 一旦某个 base64 运行时解码与预期有偏差就会拼出非法 JSON 被自检拦下——已改回。
        reqJson  = "{";
        reqJson += "\"machine\":\""   + json::EscapeString(util::WideToUtf8(machine))  + "\",";
        reqJson += "\"filename\":\""  + json::EscapeString(util::WideToUtf8(zipName))  + "\",";
        reqJson += "\"size\":"        + std::to_string(pack.zipBytes) + ",";
        reqJson += "\"raw_size\":"    + std::to_string(pack.rawBytes) + ",";
        reqJson += "\"file_count\":"  + std::to_string(pack.fileCount) + ",";
        reqJson += "\"source_dir\":\"" + json::EscapeString(util::WideToUtf8(savesDir)) + "\",";
        // 带密码申请凭证：后端据此判断「同密码覆盖上传」——已有记录则复用旧 key
        // 签发覆盖式凭证，新存档直接覆盖原存档；没有记录才发全新 key。
        reqJson += "\"password\":\""  + json::EscapeString(pw) + "\"";
        reqJson += "}";
    }

    // 发送前自检：拦截并阻断。请求体非法（手拼 JSON 漏逗号等）绝不发出，
    // 直接报错返回——避免把一个坏请求打到服务端换来 400 / 难排查的诡异失败。
    // 现在请求体已是普通字符串拼接（合法 JSON），正常路径不会触发此拦截；
    // 若日后有人改坏拼装，这里会立即拦下，正是该函数的存在意义。
    if (!JsonOk(reqJson)) {
        out.error = OBFW("5a6i5oi356uv5YaF6YOo6ZSZ6K+v77ya55Sf5oiQ55qE6K+35rGC5L2T5LiN5ZCI5rOV");
        if (log) log(OBFW("6K+35rGC5L2T5YaF5a6577ya") + MaskedJsonForLog(reqJson));
        return out;
    }

    const std::wstring tokenUrl = config::BackendBaseUrl + OBFW("L2FwaS91cGxvYWQtdG9rZW4=");
    http::Response tr = http::PostJson(tokenUrl, reqJson, AuthHeaders(), MakeTimeouts());

    if (!tr.ok || !tr.Is2xx()) {
        out.error = PrettyHttpError(tr, OBFW("55Sz6K+35LiK5Lyg5Yet6K+B5aSx6LSl"));
        return out;
    }

    auto tj = json::Parse(tr.body);
    if (!tj || !tj->IsObject()) {
        out.error = OBFW("5pyN5Yqh5Zmo6L+U5Zue55qE5pWw5o2u5peg5rOV6Kej5p6Q77yM6K+356iN5ZCO5YaN6K+V");
        return out;
    }

    const std::string uploadToken = tj->GetStr("upload_token");
    const std::string objectKey   = tj->GetStr("key");
    const std::string uploadHost  = tj->GetStr("upload_host", OBFA("aHR0cHM6Ly91cC16Mi5xaW5pdXAuY29t"));

    if (uploadToken.empty() || objectKey.empty()) {
        const std::string msg = tj->GetStr("message", "");
        out.error = OBFW("5pyN5Yqh5Zmo5pyq6L+U5Zue5pyJ5pWI55qE5LiK5Lyg5Yet6K+B") +
                    (msg.empty() ? std::wstring() : (OBFW("77ya") + util::Utf8ToWide(msg)));
        return out;
    }

    out.objectKey = util::Utf8ToWide(objectKey);
    L(OBFW("5Yet6K+B6I635Y+W5oiQ5Yqf77yM55uu5qCH5a+56LGh77ya") + out.objectKey);

    // 后端随上传凭证一并返回「取回密码」（SK- 开头，23 位）。
    // 同一上传密码 → 同一取回密码（pw_map 1:1 映射），不会每次上传都变。
    out.downloadPassword = util::Utf8ToWide(tj->GetStr("download_password"));

    // ---------------- 5. 直传七牛 ----------------
    P(580, OBFW("5q2j5Zyo5LiK5Lyg"));
    L(OBFW("5q2j5Zyo5LiK5Lyg5Yiw5a+56LGh5a2Y5YKo77ya") + util::Utf8ToWide(uploadHost));

    std::vector<std::pair<std::string, std::string>> fields;
    fields.emplace_back(OBFA("dG9rZW4="), uploadToken);
    fields.emplace_back("key", objectKey);
    fields.emplace_back(OBFA("eDptYWNoaW5l"), util::WideToUtf8(machine));

    auto upProgress = [&](unsigned long long sent, unsigned long long total) -> bool {
        if (Canceled()) return false;
        int permille = 580;
        if (total > 0) {
            // 上传阶段占 580‰ ~ 960‰
            permille = 580 + (int)((sent * 380ull) / total);
            if (permille > 960) permille = 960;
        }
        wchar_t buf[128]{};
        ::swprintf(buf, 128, OBFW("5LiK5Lyg5LitICVzIC8gJXM="),
                   util::FormatSize(sent).c_str(), util::FormatSize(total).c_str());
        P(permille, buf);
        return true;
    };

    // 直传七牛走公网，偶有「包体被截断 → 七牛报 400 invalid multipart / NextPart: EOF」
    // 这类瞬时网络问题（与 CF Tunnel 无关，是客户端↔up-z2.qiniup.com 这段）。
    // 与 report 同理加重试：每次都是新连接（已禁用 keep-alive），重试通常能自愈；
    // 最坏多等几秒，远比「一次截断就整个失败、文件变孤儿、用户干等才知道」好。
    http::Timeouts upTm; upTm.connectMs = 15000; upTm.sendMs = 60000; upTm.recvMs = 30000;

    http::Response ur;
    bool uploadOk = false;
    for (int attempt = 1; attempt <= 3 && !Canceled(); ++attempt) {
        if (attempt > 1) {
            L(std::wstring(L"上传到对象存储失败，正在重试 (") + std::to_wstring(attempt - 1) + L"/3)...");
            ::Sleep(attempt == 2 ? 1000 : 2000);
            if (Canceled()) break;
        }
        const auto upT0 = ::GetTickCount64();
        ur = http::UploadMultipartFile(
            util::Utf8ToWide(uploadHost),
            fields,
            OBFA("ZmlsZQ=="),
            util::WideToUtf8(zipName),
            zipPath,
            {},                 // 七牛直传不需要额外头
            upTm,
            upProgress,
            cancel);
        const DWORD upMs = (DWORD)(::GetTickCount64() - upT0);
        if (!ur.ok) { continue; }
        if (ur.Is2xx()) { uploadOk = true; break; }
        // 非 2xx：响应体细节保留以便排查（不再打 [调试] 前缀）
    }

    if (Canceled()) { out.canceled = true; out.error = OBFW("5bey5Y+W5raI"); return out; }

    if (!uploadOk) {
        out.error = PrettyHttpError(ur, OBFW("5LiK5Lyg5Yiw5a+56LGh5a2Y5YKo5aSx6LSl"));
        return out;
    }

    {
        auto uj = json::Parse(ur.body);
        if (uj && uj->IsObject()) {
            const std::string k = uj->GetStr("key");
            if (!k.empty()) out.objectKey = util::Utf8ToWide(k);
        }
    }
    L(OBFW("5LiK5Lyg5a6M5oiQ"));

    // ---------------- 6. 回报后端登记 ----------------
    P(970, OBFW("5q2j5Zyo55m76K6w"));

    std::string repJson;
    {
        // 同 reqJson：普通字面量拼装，交由混淆工具统一混淆（不再手写 OBFA base64）。
        repJson  = "{";
        repJson += "\"key\":\""        + json::EscapeString(util::WideToUtf8(out.objectKey)) + "\",";
        repJson += "\"password\":\""    + json::EscapeString(pw) + "\",";
        repJson += "\"machine\":\""     + json::EscapeString(util::WideToUtf8(machine)) + "\",";
        repJson += "\"size\":"          + std::to_string(pack.zipBytes) + ",";
        repJson += "\"raw_size\":"      + std::to_string(pack.rawBytes) + ",";
        repJson += "\"file_count\":"    + std::to_string(pack.fileCount) + ",";
        repJson += "\"source_dir\":\""  + json::EscapeString(util::WideToUtf8(savesDir)) + "\",";
        repJson += "\"ip\":\""          + json::EscapeString(util::WideToUtf8(util::GetMachineIp())) + "\"";
        repJson += "}";
    }

    // 拦截并阻断（同 reqJson）：非法回报体不发出
    if (!JsonOk(repJson)) {
        out.error = OBFW("5a6i5oi356uv5YaF6YOo6ZSZ6K+v77ya55Sf5oiQ55qE6K+35rGC5L2T5LiN5ZCI5rOV");
        if (log) log(OBFW("6K+35rGC5L2T5YaF5a6577ya") + MaskedJsonForLog(repJson));
        return out;
    }

    const std::wstring reportUrl = config::BackendBaseUrl + OBFW("L2FwaS9yZXBvcnQ=");

    // 报告用更短的超时（recv 20s），且失败自动重试 3 次（间隔 1s/2s）。
    // 文件已经上传到七牛，唯一的缺口就是服务端登记——0x00002EE2 这类瞬时网络/CF Tunnel 错误重试通常能救回 SK-；
    // 最坏情况总等待上限约 63s（旧版单次 120s 直接放弃，文件变孤儿，用户干等 2 分钟才看到失败）。
    http::Timeouts repTm; repTm.connectMs = 15000; repTm.sendMs = 30000; repTm.recvMs = 20000;

    http::Response rr;
    bool reportOk = false;
    std::wstring lastErr;
    for (int attempt = 1; attempt <= 3 && !Canceled(); ++attempt) {
        if (attempt > 1) {
            L(std::wstring(L"服务器登记失败，正在重试 (") + std::to_wstring(attempt-1) + L"/3)...");
            ::Sleep(attempt == 2 ? 1000 : 2000);
            if (Canceled()) break;
        }
        const auto repT0 = ::GetTickCount64();
        rr = http::PostJson(reportUrl, repJson, AuthHeaders(), repTm);
        const DWORD repMs = (DWORD)(::GetTickCount64() - repT0);
        if (!rr.ok) { lastErr = PrettyHttpError(rr, L""); continue; }
        if (rr.Is2xx()) {
            auto rj = json::Parse(rr.body);
            if (rj && rj->IsObject()) {
                out.downloadUrl = util::Utf8ToWide(rj->GetStr("download_url"));
                const long long expires = rj->GetInt("expires_in", 0);
                if (expires > 0) {
                    wchar_t buf[96]{};
                    ::swprintf(buf, 96, OBFW("5LiL6L296ZO+5o6l5pyJ5pWI5pyf57qmICVsbGQg5bCP5pe2"), expires / 3600);
                    out.expireText = buf;
                }
                // upload-token 对全新密码不一定带 SK-（服务端只在 handle_report 才生成），
                // 漏掉这一步即使报告成功也会显示「没 SK-」，看起来跟报告失败一样。
                const std::string dl = rj->GetStr("download_password");
                if (!dl.empty()) {
                    out.downloadPassword = util::Utf8ToWide(dl);
                }
            }
            L(OBFW("5bey5Zyo5pyN5Yqh5Zmo55m76K6w77yM5a+G56CB5bey5ZCM5q2l5L+d5a2Y"));
            reportOk = true;
            break;
        }
        // rr.ok 但非 2xx（如 429/500）：记错误并进入重试
        lastErr = PrettyHttpError(rr, L"");
    }

    if (!reportOk && !Canceled()) {
        // 3 次都失败：文件已在七牛但服务端没登记，存档已成「孤儿」，无法通过软件正常取回。
        // 提示用户密码仍可看到、并联系管理员处理（同一上传密码重新上传只能再生成一个新 key/新孤儿，
        // 救不回原始文件）。
        L(OBFW("5o+Q56S677ya5pyN5Yqh5Zmo55m76K6w5aSx6LSl77yI") + lastErr + OBFW("77yJ77yM5L2G5paH5Lu25bey5LiK5Lyg5oiQ5Yqf77yM6K+35Yqh5b+F6Ieq6KGM5L+d5a2Y5LiL5pa55a+G56CB"));
    }

    P(1000, OBFW("5a6M5oiQ"));
    out.ok = true;
    return out;
}

// ===========================================================================
Outcome Download(const std::wstring& savesDir,
                 const std::wstring& password,
                 const LogFn& log,
                 const ProgressFn& progress,
                 const std::atomic<bool>* cancel) {
    Outcome out;
    out.isDownload = true;

    auto L = [&](const std::wstring& s) { if (log) log(s); };
    auto P = [&](int permille, const std::wstring& stage) { if (progress) progress(permille, stage); };
    auto Canceled = [&]() { return cancel && cancel->load(); };

    // ---------------- 0. 前置校验 ----------------
    P(0, OBFW("5qOA5p+l55uu5b2V"));
    // 2026-08-06 设计原则：目标 saves 目录由「自动检测 / 手动选择」得到，必定已存在，
    // 工具【绝不创建】任何目录（含其祖先）。仅当路径失效（手改 ini / 选完删文件夹）
    // 时才驳回，提示用户重新检测或手动选择。
    if (savesDir.empty() || !util::DirectoryExists(savesDir)) {
        out.error = L"找不到路径，请重新检测或手动选择目录";
        return out;
    }
    if (!lolfind::HasMarker(savesDir)) {
        out.error = L"该目录里没有找到 " MARKER_FILE_W L"，不是有效的 saves 目录，无法解压";
        return out;
    }
    if (!util::IsValidDownloadPassword(password)) {
        out.error = OBFW("5Y+W5Zue5a+G56CB5qC85byP5LiN5q2j56Gu77yI5bqU5Li6IFNLLSDlvIDlpLTvvIzlhbEgMjMg5L2N77yJ");
        return out;
    }
    const std::string dlToken = util::WideToUtf8(password);  // 用户输入的取回密码（SK-），仅用于向后端换取下载链接
    out.downloadPassword = password;                         // 记录取回密码（结果展示 / 日志用）
    L(OBFW("55uu5qCH55uu5b2V77ya") + savesDir);

    // ---------------- 1. 换取下载链接 ----------------
    P(5, OBFW("5q2j5Zyo5o2i5Y+W5LiL6L296ZO+5o6l"));
    L(OBFW("5q2j5Zyo5ZCR5pyN5Yqh5Zmo5p+l6K+i6K+l5a+G56CB5a+55bqU55qE5a2Y5qGjLi4u"));
    const std::string req = "{\"password\":\"" + json::EscapeString(dlToken) + "\"}";
    const std::wstring dlUrl = config::BackendBaseUrl + OBFW("L2FwaS9kb3dubG9hZA==");
    http::Response dr = http::PostJson(dlUrl, req, AuthHeaders(), MakeTimeouts());
    if (!dr.ok || !dr.Is2xx()) {
        out.error = PrettyHttpError(dr, OBFW("5p+l6K+i5LiL6L296ZO+5o6l5aSx6LSl"));
        return out;
    }
    auto dj = json::Parse(dr.body);
    if (!dj || !dj->IsObject()) {
        out.error = OBFW("5pyN5Yqh5Zmo6L+U5Zue55qE5pWw5o2u5peg5rOV6Kej5p6Q");
        return out;
    }
    const std::string downloadUrl = dj->GetStr("download_url");
    const std::string key = dj->GetStr("key");
    // 后端随取回凭证一并返回「存档密码」（即加密 zip 用的上传密码）；
    // 下载者只持有 SK- 取回密码，解密必须用这个后端下发的存档密码，而非 SK- 本身。
    std::string archPwd = dj->GetStr("password");
    if (archPwd.empty()) archPwd = dlToken;  // 兼容未返回 password 的老服务端（解密大概率失败，但流程不中断）
    out.password = util::Utf8ToWide(archPwd);  // 真正用于解密的存档密码
    if (downloadUrl.empty() || key.empty()) {
        out.error = OBFW("5pyN5Yqh5Zmo5pyq6L+U5Zue5pyJ5pWI55qE5LiL6L295L+h5oGv");
        return out;
    }
    // key 形如 saves/2026-08-04/2b310b54/saves_2b310b54_...zip
    // 日志只展示文件名部分（去掉 saves/日期/机器 前缀），并用半角冒号
    out.objectKey = util::Utf8ToWide(key);
    {
        std::string displayKey = key;
        auto pos = displayKey.find_last_of('/');
        if (pos != std::string::npos) displayKey = displayKey.substr(pos + 1);
        L(L"已找到对应存档，对象:" + util::Utf8ToWide(displayKey));
    }

    // ---------------- 2. 下载到压缩包 ----------------
    // 2026-08-06 用户要求：压缩包【下载到软件同目录】再解压到指定目录——
    // 而不是临时目录（临时目录会被系统清理/找不到，用户想亲眼确认 zip 完整）。
    // 解压后【保留】该 zip（不自动删），用户可自行查看/留档/清理。
    P(20, OBFW("5q2j5Zyo5LiL6L29"));
    const std::wstring stamp  = util::TimestampCompact();
    const std::wstring machine = util::MachineId();
    const std::wstring tmpName = OBFW("aGFuYm90X2RsXw==") + machine + OBFW("Xw==") + stamp + OBFW("LnppcA==");
    const std::wstring tmpPath = util::JoinPath(util::GetExeDir(), tmpName);   // exe 同目录
    // 不再用 ScopedTempFile（解压后保留 zip，不自动删除）

    auto dlProgress = [&](unsigned long long received, unsigned long long total) -> bool {
        if (Canceled()) return false;
        int permille = 20;
        if (total > 0) {
            permille = 20 + (int)((received * 880ull) / total);
            if (permille > 900) permille = 900;
        }
        wchar_t buf[128]{};
        ::swprintf(buf, 128, OBFW("5LiL6L295LitICVzIC8gJXM="),
                   util::FormatSize(received).c_str(), util::FormatSize(total).c_str());
        P(permille, buf);
        return true;
    };

    http::Response fr = http::DownloadToFile(util::Utf8ToWide(downloadUrl), tmpPath,
                                             {}, MakeTimeouts(), dlProgress, cancel);
    if (Canceled() || fr.error == OBFW("5bey5Y+W5raI")) { out.canceled = true; out.error = OBFW("5bey5Y+W5raI"); return out; }
    if (!fr.ok) {
        out.error = (fr.status == 403)
            ? OBFW("5LiL6L296KKr5ouS57ud77yIQ0ROIOmYsuebl+mTvuagoemqjOWksei0pe+8jOivt+ehruiupOWuouaIt+err+eJiOacrOaIluiBlOezu+euoeeQhuWRmO+8iQ==")
            : PrettyHttpError(fr, OBFW("5LiL6L295aSx6LSl"));
        return out;
    }

    // 记录下载字节数（读取临时文件大小）
    {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (::GetFileAttributesExW(tmpPath.c_str(), GetFileExInfoStandard, &fad)) {
            ULARGE_INTEGER s{}; s.LowPart = fad.nFileSizeLow; s.HighPart = fad.nFileSizeHigh;
            out.downloadedBytes = s.QuadPart;
        }
    }
    L(OBFW("5LiL6L295a6M5oiQ77yI") + util::FormatSize(out.downloadedBytes) + OBFW("77yJ77yM5byA5aeL6Kej5a+G6Kej5Y6LLi4u"));

    // ---------------- 3. 解密解压到 savesDir（覆盖）----------------
    P(910, OBFW("5q2j5Zyo6Kej5Y6L"));
    zipr::ExtractResult ex = zipr::ExtractEncryptedZip(tmpPath, savesDir, archPwd);
    if (ex.passwordWrong) {
        out.passwordWrong = true;
        out.error = OBFW("5a+G56CB5LiN5q2j56Gu77yM5peg5rOV6Kej5a+G6K+l5Y6L57yp5YyF77yI6K+356Gu6K6k5a+G56CB5piv5ZCm5q2j56Gu77yJ");
        return out;
    }
    if (!ex.ok) {
        out.error = ex.error.empty() ? OBFW("6Kej5Y6L5aSx6LSl") : ex.error;
        return out;
    }
    out.extractedFiles = ex.fileCount;
    out.rawBytes = ex.writtenBytes;
    L(OBFW("6Kej5Y6L5a6M5oiQ77yM5YWx5oGi5aSNIA==") + std::to_wstring(ex.fileCount) + OBFW("IOS4quaWh+S7tu+8jOW3suimhuebluiHs+ebruagh+ebruW9lQ=="));

    P(1000, OBFW("5a6M5oiQ"));
    out.ok = true;
    return out;
}

// ===========================================================================
// 后端连通性检测：调用 GET /api/health
// ===========================================================================
// ===========================================================================
HealthResult CheckBackend(const LogFn& log) {
    HealthResult res;
    const std::wstring url = config::BackendBaseUrl + OBFW("L2FwaS9oZWFsdGg=");

    // 注意：日志面板对用户可见，这里刻意不打印后端地址，避免暴露服务端 IP / 端口。
    if (log) log(OBFW("5q2j5Zyo5qOA5rWL5pyN5Yqh5Zmo6L+e5o6lLi4u"));

    http::Response r = http::Get(url, AuthHeaders(), MakeTimeouts());

    // 网络层失败，或收到非 2xx 响应（例如 CF 隧道活着但后端进程挂了 →
    // cloudflared 返回 502 错误页），一律按「服务器连接失败」处理。
    // 不能把 502 之类算成「版本不匹配」，那会误导用户去升级客户端。
    if (!r.ok || !r.Is2xx()) {
        res.reachable = false;
        // 只给一句结论，不带地址、不带状态码——那些对用户没意义，还会泄露后端地址。
        res.message = OBFW("5pyN5Yqh5Zmo6L+e5o6l5aSx6LSl");
        if (log) log(res.message);
        return res;
    }

    res.reachable = true;
    auto j = json::Parse(r.body);
    if (j && j->IsObject()) {
        const bool ok         = j->GetBool("ok", false);
        const bool configured = j->GetBool("configured", false);
        // service 字段只用于内部判断，不再回显到界面（属于服务端身份信息）。
        if (ok && configured) {
            res.ok = true;
            res.message = OBFW("5pyN5Yqh5Zmo6L+e5o6l5oiQ5Yqf");
        } else if (ok && !configured) {
            res.ok = false;
            res.message = OBFW("5pyN5Yqh5Zmo5bey6L+e5o6l77yM5L2G5a2Y5YKo5pyq6YWN572u77yM5LiK5Lyg5Lya5aSx6LSl");
        } else {
            res.ok = false;
            res.message = OBFW("5pyN5Yqh5Zmo5bey5ZON5bqU77yM5L2G54q25oCB5byC5bi4");
        }
    } else {
        // 2xx 但响应体不是合法 JSON（几乎不会发生）：说明后端返回了意料之外的内容，
        // 提醒用户稍后重试即可，别再抛「版本不匹配」误导人。
        res.ok = false;
        res.message = OBFW("5pyN5Yqh5Zmo6L+U5Zue5byC5bi45pWw5o2u77yM6K+356iN5ZCO6YeN6K+V");
    }

    if (log) log(res.message);

    return res;
}

// ===========================================================================
// 后端密码占用查询：POST /api/check-password
//   仅用于「随机生成密码」时核对，保证生成出来的密码未被使用过；
//   手动输入密码不再查重（同密码上传 = 覆盖更新原存档）。
// ===========================================================================
bool PasswordExists(const std::wstring& password) {
    if (!util::IsValidPassword(password)) return false;

    const std::string req = "{\"password\":\"" + json::EscapeString(util::WideToUtf8(password)) + "\"}";
    const std::wstring url = config::BackendBaseUrl + OBFW("L2FwaS9jaGVjay1wYXNzd29yZA==");
    http::Response r = http::PostJson(url, req, AuthHeaders(), MakeTimeouts());
    if (!r.ok || !r.Is2xx()) return false;     // 异常时不拦截，直接用生成的密码

    auto j = json::Parse(r.body);
    if (!j || !j->IsObject()) return false;
    return j->GetBool("exists", false);
}

} // namespace uploader
