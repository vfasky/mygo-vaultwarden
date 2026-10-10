# MyGo Vaultwarden

使用 Go + MyGo Native UI 和 Swift/AppKit 构建的 macOS Vaultwarden 客户端，采用 GPL-3.0-only。主窗口不使用 HTML、JavaScript 或 WebView。

本版聚焦个人密码库。支持八种个人项目的保存、搜索、编辑、复制、同步、文件夹、收藏、归档及回收站；自定义字段、密码历史、URI 匹配和逐字段冲突核对沿用完整加密模型。敏感读取和再次验证有短期授权，未知写入结果不会自动重放。个人附件与完整资源备份支持有界流式处理、逐文件恢复、正常同步续接和下载核验；MyGo 完整资源格式与官方 JSON 明确区分，不能无损表达的内容会被具体阻止，不会静默丢弃。

账号服务入口位于“账号与设置”：Send、设备登录与审批、账号安全、MFA 和紧急访问。登录使用实际 MFA 流程；设备批准后的临时在线库不伪造磁盘密码包装、不持久保存运行期密钥或 token，也不注册运行期 AutoFill。显式绑定密码后必须重新同步，才能发布持久快照。替换另一账号的本机缓存需要明确确认和系统认证；旧保护未解决时拒绝替换，未知结果只检查同一次操作。

**组织产品 UI 延期到下一版本。** 本版不开放组织/成员/群组/集合管理、策略编辑、共享/复制/导入导出/审计/API key/Public 目录或管理员恢复动作；没有占位按钮。已审模块与开发成果保留。服务器同步中的组织加密数据和未知字段仍完整保存，已有组织政策、权限、隔离与 pending 约束继续执行；个人列表不会把组织条目当作个人条目。完整用户密钥轮换仍核验必要的组织恢复材料，缺少证据时停止，不以空适配器绕过。已有跨账号恢复屏障可以由目标本人重新认证和核验，但这不重新开放管理员操作。

完整同步保存在受 Keychain / 主密码保护的 AES-GCM 本机快照中。持久快照的系统 AutoFill 仍使用独立、按现有权限和策略过滤的 Login 投影；它不代表本版开放组织业务 UI。令牌刷新先加密落盘；UI/worker 代次、scope、snapshot ID 和存储版本共同阻止迟到结果重新打开密码库。普通同步不能清除未解决的账号变更或跨账号恢复日志。

当前交付范围、执行证据与平台限制以 [本版验收矩阵](docs/personal-release-acceptance.md) 为准；[API 模块矩阵](docs/vaultwarden-api-coverage.md) 保留底层能力记录，不等同于本版 UI 承诺。冲突处理见 [docs/cipher-conflicts.md](docs/cipher-conflicts.md)，安全存储见 [docs/secure-snapshots.md](docs/secure-snapshots.md)。

## 开发环境

- macOS 14+、完整 Xcode、Go 1.27.1+。
- MyGo 固定 v0.2.15，保留 goja 与官方 zxcvbn 的主密码评分实现。
- `go` 不在 PATH 时使用 `GO_BIN=/absolute/path/to/go`；`scripts/resolve-go.sh` 也识别项目用户缓存工具链。
- 真实 AutoFill 安装需要 Apple Developer Program、Xcode 登录账号、相应证书及 provisioning profile。未签名构建不能证明系统填充可用。

## 目录结构

| 目录 | 内容 |
|---|---|
| `main.go` | 薄入口，调用 `internal/app` |
| `internal/app` | 应用控制器：主窗口、生命周期、登录解锁、同步与密码库编辑器 |
| `internal/ui` | UI：`kit` 共享组件，`account`、`send`、`organization` 领域面板 |
| `internal/vaultwarden` | Vaultwarden 协议客户端，`vaultcrypto`、`totp`、`vaulterr` 子包 |
| `internal/localstore`、`internal/fileio`、`internal/platform` | 本机加密快照、本地文件暂存、原生桥与系统认证 |
| `third_party` | 官方 zxcvbn 与第三方许可证 |
| `tools`、`scripts` | Go 开发工具；构建、安装与许可证脚本 |
| `macos` | Xcode 工程、AutoFill 扩展与 Swift 安全存储桥 |

依赖方向、测试放置约定和新代码的归属见 [docs/architecture.md](docs/architecture.md)。

## 构建与安装

完整开发入口：

```sh
bash scripts/dev-debug.sh
# 仅构建、安装、启动一次
bash scripts/dev-debug.sh --once
```

该脚本监听 Go、Swift、资源及构建配置，完整构建主应用、安全存储桥与 AutoFill 扩展，验证签名后安装并重启。首次启动前退出已安装应用；构建失败保留正在运行的版本。原有 `mygo dev` 预览不会被关闭。代码重载不保留内存登录状态，已有加密快照可重新认证解锁。

也可分别执行：

```sh
bash scripts/build-macos.sh debug
bash scripts/install-macos.sh debug
```

产物为 `build/debug/MyGo Vaultwarden.app`，安装到 `~/Applications/MyGo Vaultwarden.app`。脚本不会替用户开启系统 AutoFill。仅预览界面可运行 `go tool mygo dev`；该 `.dev` 模式不含安全存储及 AutoFill，不能用于验收这些功能。

签名设置写在忽略的 `.local/signing.env`，变量为 `MYGO_SIGNING_IDENTITY`、`MYGO_TEAM_ID` 和可选的 `MYGO_NOTARY_PROFILE`。证书私钥、公证凭据及 provisioning profile 不应提交。主应用与扩展的 bundle ID 必须匹配自己的团队配置。

```sh
bash scripts/build-macos.sh release
# 可选：本地打包、公证，不上传发行站点
bash scripts/build-macos.sh release --notarize
```

Xcode 管理主应用和扩展两个 target；Go build phase 生成主可执行文件，原生扩展嵌入 `Contents/PlugIns`，共享 Swift 桥位于 `Contents/Frameworks/libSnapshotBridge.dylib`。应用图标与资源说明见 [docs/app-icon.md](docs/app-icon.md)。

## 使用与安全边界

1. 输入服务器、邮箱和主密码，按服务器实际要求完成 MFA。使用 HTTPS，仅本机回环允许 HTTP。
2. 个人项目按类型、文件夹、收藏、归档或回收站筛选。使用 `⌘F` 搜索，键盘上下键选择；详情可复制用户名或打开 HTTP(S) 网站。
3. 锁定立即隐藏列表、详情和敏感输入，并撤销内存权限。重启后可用主密码或系统认证解锁持久快照。
4. 在 macOS“自动填充与密码”启用 MyGo Vaultwarden，再实际核验 Safari 填充。严格 Host / Exact 规则只在系统给出可核对来源时匹配。
5. 账号变更、紧急接管或未知切换若留下恢复记录，使用对应专用入口核验；取消、重启、普通登录或 HTTP 200 本身都不能代替完整证明。

原始主密码不发送到服务器，不写配置、日志或命令行。持久 payload 保存加密的 refresh token、设备标识和必要密钥材料，不保存原始密码或 access token；临时设备会话不写入这些材料。普通网络失败保留上次成功缓存；身份、密钥、授权或来源失效会停止当前权限。退出临时库只撤销临时能力，保留无关磁盘账号。

密钥轮换的固定 Vaultwarden 1.37.4 兼容判断是对所配置服务器的协议声明，不是二进制远程证明。公开接口无法独立读回的恢复包装采用已记录的严格协议顺序见证，并与实际读回证据区分。不可判定时保留屏障和恢复材料。

## 测试

```sh
go test -tags headless ./...
go vet -tags headless ./...
swift test --package-path macos
swift test --package-path macos/Authentication
```

Go/Swift 测试覆盖加密、身份/权限、生命周期、持久化、URI 匹配和原生组件。真实服务/CLI 回环只使用独立、带所有权标记的本机固定版本实例；模拟 Keychain 和隔离 C ABI 不等于真实 Touch ID、签名安装、Safari 或 IdP 系统窗口已经验证。具体结果和大库测量见验收矩阵。

```sh
codesign --verify --deep --strict 'build/debug/MyGo Vaultwarden.app'
pluginkit -m -v -i yz.sh.mygo-vaultwarden.autofill
```

## 许可证与来源

项目采用 [GPL-3.0-only](LICENSE)。自动填充流程参考 KeePassium，来源及复用范围见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。MyGo、goja、zxcvbn 等保留各自许可证，应用包携带第三方声明。
