# 代码结构

仓库按职责分为 UI、应用控制器、后台协议、本机存储与平台桥、第三方代码、开发工具和原生 macOS 工程。根目录只保留薄入口 `main.go`；构建脚本（`scripts/xcode-build-go.sh`）与 `go tool mygo dev` 仍编译仓库根包。

## 目录总览

```text
main.go                        入口，只调用 app.Run()
internal/
  app/                         应用控制器：窗口（主窗口、设置、账号中心）、菜单、生命周期、登录/解锁、
                               同步、自动更新、密码库编辑器，以及把各领域面板接到存储与 Vaultwarden 会话的控制器
  ui/                          UI 层（MyGo Native UI，无 WebView）
    kit/                       共享主题、颜色、图标与通用组件（Action、Pill、DetailCard……）
    account/                   账号、认证管理、MFA 表单、恢复、紧急访问、设备与设备登录
    send/                      Send 面板及原生文件选择对话框
    organization/              组织业务、目录、事件、批量操作与资源恢复面板
    uitest/                    跨包共享的 UI 测试辅助，只被测试导入
  vaultwarden/                 后台协议客户端：Client、Session 及账号/密码库/附件/Send/
                               组织/策略/恢复/通知等操作
    vaultcrypto/               KDF、EncString 与附件流式加解密
    totp/                      标准 TOTP 与 Steam 动态验证码
    vaulterr/                  共享哨兵错误；vaultwarden.ErrX 是同值别名
  localstore/                  本机加密快照存储协议、账号切换与恢复日志、运行期密钥许可、
                               目标恢复检查（经 Swift 桥落盘）
  fileio/                      附件、备份与组织导入导出的本地文件暂存与原子发布
  platform/
    nativelib/                 定位应用包内的原生 Swift 桥库
    sysauth/                   WebAuthn、Duo、SSO 等交互认证到 macOS 系统认证的桥
  passwordstrength/            主密码强度评估（goja 执行官方 zxcvbn）
resources/                     图标与图片；resources.go 嵌入运行期绘制的 Logo
third_party/
  zxcvbn/                      官方 zxcvbn 脚本与许可证，Go 包 zxcvbn 以 Script 嵌入
  licenses/                    goja 等运行期依赖的许可证副本
tools/
  dev-debug/                   开发监听、构建、安装、重启工具（入口 scripts/dev-debug.sh）
  invitation-smtp/             集成测试用的邀请邮件 SMTP 接收器
  release-update/              生成签名更新包与 manifest，并为 Release 构建输出更新源链接参数（docs/updates.md）
scripts/                       构建、安装、签名、许可证收集与图标生成脚本
macos/                         Xcode 工程与 Swift：App、AutoFill 扩展、Bridge、Shared、
                               Authentication 及其 Tests
docs/                          设计与验收文档；docs/parallel/ 为历史开发记录
```

## 依赖方向

```text
main → internal/app → internal/ui/* ─┐
                    → internal/localstore, internal/fileio, internal/platform/*
                    → internal/vaultwarden → vaultcrypto, totp → vaulterr
internal/ui/*  → internal/ui/kit, internal/vaultwarden, internal/passwordstrength
internal/passwordstrength → third_party/zxcvbn
```

- 只有 `internal/app` 可以把各层组装起来；其他包都不能导入 `internal/app`。
- `internal/ui` 下的领域包互不依赖，只依赖 `kit`、`vaultwarden`、`passwordstrength`、MyGo 与标准库。面板通过 Host、回调或字段接收控制器能力，不直接访问存储或网络会话。
- `vaultcrypto`、`totp`、`vaulterr` 是不依赖 Session 的叶子包。

## 窗口

所有窗口都画同一个 `app` 状态，状态只在主线程修改：

| 窗口 | 文件 | 内容 |
|---|---|---|
| 主窗口 | `ui.go`、`ui_auth.go` | 锁定时只显示登录/解锁；解锁后是侧栏、列表、详情与编辑器。关闭时隐藏，Dock 图标恢复 |
| 设置 | `window_settings.go` | 账号、存储与自动填充、更新、关于；账号与存储标签在锁定时只显示占位 |
| 账号中心 | `window_account.go` | Send、设备与登录审批、账号与安全、两步验证、紧急访问 |
| 更新 | MyGo `plugins/updater/native` | 由 `updates.go` 接入，见 [自动更新](updates.md) |

- 哪些窗口打开、显示哪个标签是 `windowSet` 中的状态（`windows.go`）；原生窗口只是它的投影，`Run` 设置 `native` 后才创建。headless 测试直接改状态并用 `ui.NewTester` 渲染 `settingsWindowView`、`accountWindowView`。
- 后台结果经 `dispatchUI`/`postUI` 回到主线程并重绘所有窗口；某个窗口的一帧改变了共享状态（`uiSignature`）时，`frame` 重绘其他窗口。
- 账号中心各页面的面板共用一个 `controllerLease`，`advanceEpoch` 会关闭全部面板。`reconcileAccountPanels` 在每个窗口每帧开头运行，只保留账号中心当前显示页面的面板；关闭账号中心立即撤销。`openAccountPage` 是菜单、设置与侧栏的唯一入口，在锁定、`pending` 或主窗口有编辑器时不打开面板。
- 菜单栏（`menu.go`）与工具栏共用 `runMenuCommand`。

## 测试放置

- Go 单元测试与被测代码同包，白盒测试可以访问未导出符号。
- 需要 `app` 对象、`writableUIFixture` 等夹具的控制器集成测试留在 `internal/app`。
- 跨包共享的测试辅助放在 `internal/ui/uitest` 这类只被测试导入的包中。
- 以下测试辅助在两个包里各有一份逐字副本，因为 `_test.go` 中的声明不能跨包使用。修改时必须同步：
  - `recoveryNativeCall`、`targetFixture`：`internal/localstore` 测试与 `internal/app/localstore_fixture_darwin_test.go`
  - `orgResourceUIFixture`：`internal/ui/organization/resource_test.go` 与 `internal/app/org_resource_fixture_test.go`
  - `backupTestDirectory`：`internal/fileio/backup_test.go` 与 `internal/app/backup_controller_test.go`
- Swift 测试位于 `macos/Tests` 与 `macos/Authentication/Tests`。

## 新代码放在哪里

| 内容 | 位置 |
|---|---|
| 不依赖 app 状态的新面板或表单 | 对应的 `internal/ui/<领域>`；新领域另建子包 |
| 通用按钮、颜色、图标 | `internal/ui/kit` |
| 窗口状态、控制器、把面板接到存储或会话的逻辑 | `internal/app`（控制器文件以 `controller_` 开头） |
| Vaultwarden HTTP/协议操作 | `internal/vaultwarden` |
| 不依赖 Session 的密码学原语 | `internal/vaultwarden/vaultcrypto` |
| 原生快照或恢复日志协议 | `internal/localstore` |
| 本地文件读写与暂存 | `internal/fileio` |
| purego 原生桥 | `internal/platform` |
| 第三方源码或资源 | `third_party/`，并更新 `THIRD_PARTY_NOTICES.md` 与 `scripts/collect-licenses.sh` |
| 开发辅助程序 | `tools/` |

## 已知限制

- `internal/app` 的 `app` 类型保存所有窗口共享的全部状态，约 160 个方法分布在约 45 个文件中。Go 要求方法与类型同包，因此控制器层仍集中在一个包。进一步拆分需要先把编辑器和控制器改成持有窄接口的独立对象，属于设计调整，而不是目录迁移。
- `internal/vaultwarden` 以 `Session` 为核心（约 250 个方法），同样只拆出了不依赖 Session 的叶子部分。
