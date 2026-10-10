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

初次集成抽出了通知与资源备份领域；独立审查后的整改又落实组织 host、异步备份导入和个人备份导出三个接缝。Session 和 app 仍保留其他业务编排，以下区分领域逻辑与薄适配器。

- `controllerNotifications` 通过 `notificationSession` 窄接口启动订阅，独立管理通知工作线程、取消、检查点、revision 与迟到事件；它不持有 `*app`。app 负责组装 dispatcher/storage 能力和 UI 更新。
- `idleLockController` 独立管理 15 分钟空闲期限、系统活动源、定时器和回调代次。后台同步与重绘不会续期；其他应用键鼠输入计入系统活动。
- `resourceBackupService` 通过五方法 `resourceBackupAccess` 接口完成资源归档、附件恢复 staging/哈希验证及恢复内容核验；不嵌入 Session，也不访问 Session 字段。Session 的薄适配器保留授权、锁和生命周期检查。
- `orgServicesController` 通过 `orgServicesHost` 请求窗口、忙状态、提示和已验证回执采用能力，不持有 `*app`。控制器继续拥有取消、提示挑战、lease、grant、隔离回执和迟到结果过滤。`appOrgServicesHost` 是 UI 组装适配器，负责主窗口的 epoch/快照采用、其他草稿撤销和原账号恢复告警；不是把 app 当成通用状态仓库交给控制器。
- `backupImportController` 持有单次导入计划、context/cancel、不可重放的 started 状态、checkpoint progression 和迟到回执过滤；通过 `personalBackupImporter` 与 `backupImportHost` 工作，不需要完整 app/Session。`app.importBackupWith` 仅检查入口、组装依赖及登记 busy；`appBackupImportHost` 将当前结果反映到视图并复用原检查点/未知写入策略。
- `personalBackupService.export` 执行完整个人备份转换：选择集、元数据、解密、兼容格式处理、文件夹、输出复验和最终授权。六方法 `personalBackupAccess` 只提供 scope、策略、grant、受控解密及最终授权；服务看不到 Session 或原始密钥。Session 的 `ExportPersonalBackup`/`ExportPersonalBackupAuthorized` 仅转发；私有 `exportPersonalBackup` 保留锁和 beginOperation 生命周期并调用服务。
- Session 中仍含实际领域逻辑的路径包括 `ImportPersonalBackup`、`withOrganizationBackup`、`ImportOrganizationBackup`、`WriteResourceBackup`；`personalBackupAuthorizationLocked`、`backupResourceDescriptions`、`prepareResourcePublication` 及 Publish 方法保留授权/发布屏障。这些不被计作已抽完的领域。

串行迁移阶段已完成以下跨层契约：

- 主存储协议调用点使用 `localstore.Operation` 常量，Swift Bridge 分派使用生成的 `StorageOperation`；33 个 wire 字符串来自 `tools/storage-operations/operations.json`。两个 Shared 恢复 API 仍接收 String，由已校验的 Bridge enum 通过 `.rawValue` 适配；未改其 ABI。运行期秘密能力的 activate/revoke/copy 协议和 `__transfer_v1` 外层传输帧是独立协议，不混入此枚举。
- UI/app 通过 `vaultwarden.ErrorMessage` 展示错误。`vaulterr` 保留稳定身份；领域转换、轮换准备、未知写入和 Send 上传提示优先于通用错误。应用自有的本地错误通过 `UserMessage` 明确提供安全文案，国际化 sentinel 使用 `i18n.MessageError` 在展示时翻译；未经认可的错误与外层包装文字不会直接显示。不得把响应体或秘密放入这个展示接口。
- 长条件按相同短路顺序拆为身份、状态和证据校验；字段/策略定义按条目展开，回调使用领域类型。非测试生产逻辑已无超过 300 字符的行；60 条双语言 catalog 文案和 3 条测试夹具数据长行保留原文，不为长度指标拆散翻译或数据。

### C1 本轮接缝与后续演进

独立审查指出原 C1 未完成，本轮按确认范围落实上述三个实际接缝，并用 fake host/service 验证正常、取消、过期回执、未知写入不重放、撤销后无明文输出；现有真实 Session 的隔离/检查点回归继续执行。是否关闭本轮审查项仍由独立复审判断，不能仅按方法数量验收。

串行迁移时的 AST 统计为 app **68 个字段、163 个接收者方法**、Session **25 个字段、246 个接收者方法**；本轮保留对外兼容方法，因此接收者数量没有机械下降。薄组装/转发和实际领域逻辑已在上方分别列明，未宣称整套 app/Session 完全解耦。

| 剩余边界 | 下一批建议的独占文件范围 | 最小可验证拆分 |
|---|---|---|
| app 个人编辑/备份/附件与视图状态 | `cipher_*`、`attachment_editor.go`、`backup_*`、`folder_editor.go`、`bulk_editor.go`；协调 app 字段组装 | 继续分离尚在 app 的编辑视图、草稿和资源续接；异步元数据导入生命周期已由 backupImportController 拥有 |
| app 登录、MFA、设备临时会话与恢复 | `network.go`、`login_flow.go`、`controller_mfa.go`、`controller_device_login.go`、`controller_*recovery*.go`、`vault_authority.go` | 认证生命周期控制器独立拥有 epoch/取消，主窗口只接收当前代次结果；保留账户替换、锁定与撤销测试 |
| app 组织管理及共享 UI | `controller_organization*`、`organization_*ui.go`、`member/group/policy/collection_management_ui.go` | orgServicesController 的 host 接缝已落实；后续分离仍为 app 方法的成员/群组/策略编辑器，保持隔离与权限变化回归 |
| Session 条目、附件、Send | `cipher_*`、`ciphers_api.go`、`attachment*`、`send_session.go`、`item_authorization.go` | 建立持有窄授权/传输能力的领域服务；Session 保持锁、取消与授权检查，先验证一种完整操作而非迁移包装器 |
| Session 组织、成员、策略及账户恢复 | `organization*`、`member*`、`group*`、`policy*`、`account*`、`emergency*`、`target_recovery*` | 分批抽出编排服务并保留检查点/未知结果屏障；不能把网络移出锁后省略并发证明 |

上述剩余演进范围不是本轮三个接缝的完成证据；后续修改仍需单写入者和独立审查。
