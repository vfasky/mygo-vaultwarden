# 代码结构

仓库按职责分为 UI、应用控制器、后台协议、本机存储与平台桥、第三方代码、开发工具和原生 macOS 工程。根目录只保留薄入口 `main.go`；构建脚本（`scripts/xcode-build-go.sh`）与 `go tool mygo dev` 仍编译仓库根包。

## 目录总览

```text
main.go                        入口，只调用 app.Run()
internal/
  app/                         应用控制器：主窗口、生命周期、登录/解锁、同步、密码库编辑器，
                               以及把各领域面板接到存储与 Vaultwarden 会话的控制器
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
  testfixture/                 共享测试数据、隔离 C ABI 与工具链辅助；仅测试导入
  passwordstrength/            主密码强度评估（goja 执行官方 zxcvbn）
resources/                     图标与图片；resources.go 嵌入运行期绘制的 Logo
third_party/
  zxcvbn/                      官方 zxcvbn 脚本与许可证，Go 包 zxcvbn 以 Script 嵌入
  licenses/                    goja 等运行期依赖的许可证副本
tools/
  dev-debug/                   开发监听、构建、安装、重启工具（入口 scripts/dev-debug.sh）
  invitation-smtp/             集成测试用的邀请邮件 SMTP 接收器
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
- `internal/ui` 下的领域包互不依赖，只依赖 `kit`、`vaultwarden`、`passwordstrength`、MyGo 与标准库；`send` 的原生文件选择适配另依赖 `fileio` 读取用户选择的文件。面板通过 Host、回调或字段接收控制器能力，不直接访问存储或网络会话。
- `vaultcrypto`、`totp`、`vaulterr` 是不依赖 Session 的叶子包。

## 测试放置

- Go 单元测试与被测代码同包，白盒测试可以访问未导出符号。
- 需要 `app` 对象、`writableUIFixture` 等夹具的控制器集成测试留在 `internal/app`。
- 跨包共享的测试辅助放在 `internal/testfixture` 与 `internal/ui/uitest`，只允许 `_test.go` 导入。生产依赖不得导入这些包。
- `internal/testfixture` 统一提供恢复 C ABI 调用、目标快照、组织资源归档与规范化临时目录。各包原有的小写 helper 只转发调用，夹具数据和资源生命周期只有一份实现。
- 原生 helper 使用泛型请求/回执，并由调用测试注入 `BoundedStorageCall`；它不导入 `localstore`，避免同包测试的依赖循环。`testfixture/toolchain` 独立于业务包，为 live SMTP 子进程选择 `GO_BIN` 或 PATH 中的 Go。
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

## 已集成的领域边界与剩余耦合

本次集成完成两个实际领域对象的抽取；Session 和 app 仍保留其他业务编排，后续维护拆分不能以文件移动代替边界设计。

- `controllerNotifications` 通过 `notificationSession` 窄接口启动订阅，独立管理通知工作线程、取消、检查点、revision 与迟到事件；它不持有 `*app`。app 负责组装 dispatcher/storage 能力和 UI 更新。
- `idleLockController` 独立管理 15 分钟空闲期限、系统活动源、定时器和回调代次。后台同步与重绘不会续期；其他应用键鼠输入计入系统活动。
- `resourceBackupService` 通过五方法 `resourceBackupAccess` 接口完成资源归档、附件恢复 staging/哈希验证及恢复内容核验；不嵌入 Session，也不访问 Session 字段。Session 的薄适配器保留授权、锁和生命周期检查。
- 资源备份三个方法已移入服务，个人/组织元数据导入导出及授权编排仍保留九个有实际逻辑的 Session 备份方法。app 仍持有 UI、认证、编辑器等状态，尚未完成整体解耦。C3 的长文件可读性整理和 UI 错误展示迁移由后续串行阶段落实。
