#pragma once

// ---------------------------------------------------------------------------
// 资源 / 控件 ID 与自定义窗口消息
// ---------------------------------------------------------------------------

// ---- 资源 ----
#define IDI_APP_ICON              101
#define IDR_APP_MANIFEST            1   // CREATEPROCESS_MANIFEST_RESOURCE_ID
#define IDR_APP_HTML              200   // 内嵌的 webui/index.html（WebView2 渲染用）
#define IDR_APP_ICON_PNG          202   // 软件图标（PNG），运行时 base64 注入页面头部

// ---- 静态文本 ----
#define IDC_STATIC_HEADER        1001
#define IDC_STATIC_SUBHEADER     1002
#define IDC_STATIC_PATH_LABEL    1003

// ---- 路径行 ----
#define IDC_EDIT_PATH            1004
#define IDC_BTN_DETECT           1005
#define IDC_BTN_BROWSE           1006
#define IDC_STATIC_VERIFY        1007

// ---- 主操作 ----
#define IDC_BTN_UPLOAD           1008
#define IDC_PROGRESS             1009
#define IDC_STATIC_STAGE         1010

// ---- 日志 ----
#define IDC_EDIT_LOG             1011

// ---- 结果区 ----
#define IDC_STATIC_RESULT_LBL    1012
#define IDC_EDIT_RESULT          1013
#define IDC_BTN_COPY             1014

// ---- 密码框 ----
#define IDC_STATIC_PWD_LABEL     1017
#define IDC_EDIT_PWD             1018
#define IDC_STATIC_PWD_HINT      1019

// ---- 下载按钮 ----
#define IDC_BTN_DOWNLOAD         1020

// ---- 页脚 ----
#define IDC_STATIC_FOOTER        1016

// ---- 后端连接状态 ----
#define IDC_STATIC_CONN          1021

// ---------------------------------------------------------------------------
// 自定义消息（工作线程 -> UI 线程）
//   LPARAM 若为 new 出来的对象，由 UI 线程负责 delete
// ---------------------------------------------------------------------------
#define WM_APP_LOG           (WM_APP + 1)   // LPARAM: new std::wstring*
#define WM_APP_PROGRESS      (WM_APP + 2)   // WPARAM: 0-1000, LPARAM: new std::wstring*
#define WM_APP_DETECT_DONE   (WM_APP + 3)   // LPARAM: new std::vector<Candidate>*
#define WM_APP_UPLOAD_DONE   (WM_APP + 4)   // LPARAM: new uploader::Outcome*
#define WM_APP_SET_BUSY      (WM_APP + 5)   // WPARAM: 1=忙, 0=空闲
#define WM_APP_CONN          (WM_APP + 6)   // LPARAM: new uploader::HealthResult*
#define WM_APP_PWD_CHECK     (WM_APP + 7)   // LPARAM: new PwdCheckResult*（随机生成密码的查重结果）
