# Hanbot 存档打包上传器（客户端）

Windows 桌面程序，把英雄联盟 `League of Legends/saves/` 目录打包成**带随机密码的加密 ZIP**，
上传到七牛云对象存储。纯 Win32 + C++17 实现，**零第三方依赖**，**静态链接 `/MT`**，
目标机器不需要安装任何 VC++ 运行库，兼容 Win10 / Win11（x64）。

## 功能

- 自动探测 `saves/` 目录：以目录内含 `hanbot_core.ini` 作为判定依据（各机器路径不同也认得）
- **二次元风格界面**：自定义圆角窗口 + 樱粉/薰衣草渐变背景 + 自绘圆角按钮（纯 Win32 手绘，无 UI 框架）
- **一个密码框 + 两个按钮**：
  - 密码框：填 **4~24 位字母/数字**（实时过滤非法字符），作为压缩包密码，上传和下载都用同一密码
  - **「📤 打包并上传」**：把 `saves` 目录加密打包成 ZIP（文件名带机器指纹+时间戳，避免互相覆盖）后直传七牛云，并把「密码 ↔ 压缩包」登记到后端
  - **「📥 下载并解压」**：凭密码向后端换取下载链接，下载后解密解压并**覆盖**到该 `saves` 目录
- 密码必须自己记住：不存储于本地、无法找回（上传成功后会自动复制到剪贴板）
- 只用 HTTP（明文可接受，数据不敏感）
- 探测失败可手动选择目录

## 使用流程

1. 程序启动自动检测 `saves` 目录（也可「自动检测」/「手动选择」），校验通过会显示 `√`
2. 在密码框输入 **4~24 位字母或数字** 作为压缩包密码（提示：上传/下载都要用同一个密码）
3. 点「📤 打包并上传」→ 等待进度完成 → 结果区显示密码与下载信息（已自动复制）
4. 换机恢复时：选好目标 `saves` 目录，输入**同一密码**，点「📥 下载并解压」即可覆盖恢复

> 上传时后端会记录本机 IP，同一 IP 30 分钟内禁止重复上传（避免刷包）；下载链接带时间戳防盗链，
> 客户端使用白名单 UA `xlingran/hanbot/1.1` 访问。

## 构建（本地）

需要先安装 **Visual Studio 2022（含“使用 C++ 的桌面开发”工作负载）** 与 **CMake ≥ 3.20**：

```bat
cd client
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

生成的 exe：`build/Release/HanbotSavesUploader.exe`（路径以实际为准，可用
`Get-ChildItem -Recurse -Filter HanbotSavesUploader.exe` 定位）。

## 构建（GitHub Actions）

推送到 `main` 或发起 PR 时，工作流 `.github/workflows/build.yml` 会自动在
`windows-latest` 上用 VS2022 x64 Release 编译，并把 exe 作为
`HanbotSavesUploader-windows-x64` 构件上传，到 Actions 页面下载即可。

## 运行前配置

exe 旁边放一个 `uploader.ini`（UTF-8），内容示例：

```ini
[server]
backend = http://106.52.205.16:8000
client_key = hanbot-client-key-change-me
```

`client_key` 必须与后端 `server.conf` 里的 `CLIENT_API_KEY` 一致。
后端地址、AK/SK 都在服务端管理，客户端永远拿不到 AK/SK。

## 可选：程序图标

放一个 `client/res/app.ico`，然后把 `client/res/app.rc` 里
`// IDI_APP_ICON ICON "app.ico"` 的注释去掉即可（同时改 `main.cpp` 的图标加载）。
不配置也能正常编译运行。
