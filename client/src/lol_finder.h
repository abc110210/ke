#pragma once

// ---------------------------------------------------------------------------
// League of Legends saves 目录探测
//   判定标准只有一条：目录里必须存在 hanbot_core.ini
//   探测顺序（快 -> 慢）：
//     1. 正在运行的 LoL 进程所在目录
//     2. Riot 官方元数据文件（product_settings.yaml / RiotClientInstalls.json）
//     3. 注册表卸载信息
//     4. 各磁盘常见安装路径
//     5. 有界深度遍历（先找 League of Legends 目录，再直接找 saves 目录）
// ---------------------------------------------------------------------------

#include <string>
#include <vector>
#include <functional>
#include <atomic>

namespace lolfind {

struct Candidate {
    std::wstring savesPath;   // 命中的 saves 目录绝对路径
    std::wstring source;      // 命中来源，用于日志展示
};

using LogFn = std::function<void(const std::wstring&)>;

// 校验目录是否为目标 saves 目录（必须含 hanbot_core.ini）
bool HasMarker(const std::wstring& dir);

// 完整探测，返回全部命中项（已去重）。timeoutSeconds <= 0 表示不限时。
std::vector<Candidate> FindAll(const LogFn& log,
                               const std::atomic<bool>* cancel,
                               int timeoutSeconds);

} // namespace lolfind
