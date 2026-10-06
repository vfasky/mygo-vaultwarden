# MyGo Vaultwarden

使用 Go + MyGo Native UI 和 Swift/AppKit 构建的 macOS Vaultwarden 客户端。采用 GPL-3.0-only。

当前已接入 Vaultwarden 只读登录与同步：支持 PBKDF2、Argon2id、TOTP 双重验证、token 刷新和个人 Login 条目解密。主密码使用 AppKit 安全输入框；解密结果写入受 Keychain 保护的加密快照，支持离线解锁与 macOS 系统自动填充。暂不支持编辑、组织库或新 COSE 加密格式，兼容边界见 [只读接入说明](docs/vaultwarden-readonly.md)。

## 开发环境

- macOS 14+，Xcode 完整安装。
- Go 1.27.1+；MyGo 固定为 v0.2.15。
- 完整 AutoFill 验证需要 Apple Developer Program、Xcode 中已登录的开发者账号、开发证书和 Developer ID Application 证书。
- Go 主界面不使用 HTML、JavaScript 或 WebView。`resources/demo-login.html` 仅是 Safari 的外部验收页面。

`go` 不在 PATH 时可通过 `GO_BIN=/absolute/path/to/go` 指定。脚本也识别 Homebrew 和本项目的用户缓存工具链。

## 构建与安装

```sh
bash scripts/build-macos.sh debug
bash scripts/install-macos.sh debug
```

输出：`build/debug/MyGo Vaultwarden.app`。

安装位置：`~/Applications/MyGo Vaultwarden.app`。更新前请退出已安装的主应用。安装脚本会登记 Launch Services 和 PlugInKit，再启动应用；不会修改系统自动填充开关。

完整 app 使用 Xcode 管理主应用和扩展两个 target；主应用的实际可执行文件由 Xcode build phase 调用 Go 生成，扩展以原生 macOS `.appex` 形式嵌入 `Contents/PlugIns`。`Contents/Frameworks/libSnapshotBridge.dylib` 提供 Go → Swift 进程内接口，主应用和扩展复用 `macos/Shared` 中的同一套加密存储代码。

仅开发主界面时：

```sh
go tool mygo dev
```

这个命令不包含 AutoFill 扩展和安全存储组件，MyGo 开发包也使用独立的 `.dev` 标识。此模式用于界面开发，安全存储按钮不可用。测试共享快照和系统填充请使用上面的完整构建安装流程。

## 应用图标

已配置 1024×1024 PNG 和多尺寸 macOS ICNS，MyGo 开发包与 Xcode 完整应用共用同一设计。资源位置、规范适配与重新生成命令见 [docs/app-icon.md](docs/app-icon.md)。

## 签名与发布构建

构建脚本读取本机 `.local/signing.env`，也支持通过环境变量设置 `MYGO_SIGNING_IDENTITY`、`MYGO_TEAM_ID` 和可选的 `MYGO_NOTARY_PROFILE`。`.local/` 已被 Git 忽略，用于保存本地配置和开发记录；证书私钥、公证凭据和 provisioning profile 不应提交到仓库。

首次构建前，请配置自己的开发者证书和团队，并将 Xcode 工程及 `mygo.json` 中的 bundle ID 改为自己团队拥有的标识。主应用和 AutoFill 扩展均需要匹配的 provisioning profile，构建脚本通过 Xcode archive/export 自动配置。

```sh
bash scripts/build-macos.sh release
# 可选：仅本地打包、公证，不上传发行站点
bash scripts/build-macos.sh release --notarize
```

开发构建没有执行公证。Xcode Developer ID 导出仍会申请签名时间戳，需要网络。

## 登录、同步与 Safari

1. 填入 Vaultwarden 服务地址和邮箱，点击“登录并同步”。使用 HTTPS；仅本机回环地址允许 HTTP。
2. 在 AppKit 安全输入框中填写主密码；账号启用 TOTP 时继续填写验证器代码。
3. 同步成功后，主窗口显示个人登录条目和未支持/排除数量，可搜索或打开对应网站。
4. 在 macOS“自动填充与密码”中启用 MyGo Vaultwarden；需要时点击“更新系统候选”并完成系统认证。
5. 在 Safari 的匹配网站选择本应用的凭据，经系统认证后填充。严格 Host / Exact 规则只在系统提供可核对的来源时匹配，详见协议说明。
6. 主应用退出后，扩展仍能独立读取加密快照。重启主应用可点“离线解锁”查看本机列表。

主窗口采用三栏布局：左侧为密码库与分类，中间为可搜索的项目列表，右侧为选中项目详情。使用 `⌘F` 搜索标题、用户名或网站，列表支持上下键选择；详情支持复制用户名和打开 HTTP(S) 网站。右上角或左下角的“账号与设置”包含登录、离线解锁、候选更新和退出账号。主窗口不读取或展示明文密码，密码仍通过系统认证后自动填充。

界面使用浅灰紫背景、白色圆角面板和本地生成的文字图标，不请求远程网站图标。收藏、支付卡、身份、安全笔记、SSH 密钥等未同步分类会明确显示支持边界；文件夹、归档和回收站暂不可用。

登录会先切换并撤销此前本机账号快照。锁定或退出会清除在线令牌和用户密钥；后续在线同步需重新登录，离线解锁和填充使用系统认证。

原始主密码不发送到服务器，不写入配置、日志或命令行；它只在本次登录/MFA 流程内用于本地派生。手动查看扩展列表和实际填充分别认证，过期或被锁定的请求不能继续提交。

本机测试账号可使用“本机测试页”检查公开 fixture；该页面不是 Vaultwarden 登录页，不应输入真实账号密码。`resources/demo-credentials.json` 不进入扩展包，也不会作为真实同步失败的回退数据。

成功同步全量替换快照；普通网络/解密失败保留上次成功快照并明确报错。账号身份或认证失效要求重新登录。登出先撤销快照，再清理 Keychain 和系统候选。候选回执与旧密钥清理的状态独立显示。

实现边界见 [安全快照设计](docs/secure-snapshots.md) 和 [只读接入说明](docs/vaultwarden-readonly.md)。

## 测试

```sh
go test ./...
go vet ./...
swift test --package-path macos
```

界面交互测试覆盖搜索、键盘选择、详情切换、复制用户名、打开网站与快照撤销后的详情清除。可使用公开虚构数据导出原生渲染预览（不访问真实密码库或 Keychain）：

```sh
MYGO_UI_PREVIEW_DIR="$PWD/build/ui-preview" go test -run TestVaultVisualPreviews .
```

Go 测试包含官方加密固定向量、请求重定向与 TLS 边界、token 刷新、身份/密钥变化、条目筛选与解析；Swift 测试覆盖加密快照、账号隔离、并发撤销、候选回执及域名/URI 匹配。真实服务测试与官方 CLI 核对使用独立本机实例，不接触生产账号。单元测试中的模拟 Keychain 不代表真实系统认证已验证。

诊断：

```sh
codesign --verify --deep --strict 'build/debug/MyGo Vaultwarden.app'
pluginkit -m -v -i yz.sh.mygo-vaultwarden.autofill
log show --last 10m --style compact \
  --predicate 'subsystem == "yz.sh.mygo-vaultwarden.autofill"'
```

签名应用还提供不返回密码或密钥的诊断接口：

```sh
app="$HOME/Applications/MyGo Vaultwarden.app/Contents/MacOS/MyGo Vaultwarden"
"$app" --storage-action status
"$app" --storage-action verifyWithoutUI   # 有快照时应拒绝无交互读密钥，退出码 1
"$app" --storage-action verify            # 需要本人完成系统认证
```

`publish`、`delete` 仅适用于公开演示快照，不允许覆盖真实账号；`lock`、`logout` 会锁定或撤销当前本机快照。`reindex` 更新候选，`retryCleanup` 重试旧密钥清理。响应中的 `ok` 表示存储操作结果，`indexPending` 和 `cleanupPending` 独立表示后续清理是否完成。短命诊断进程退出时异步索引更新可能未完成，索引验收应通过持续运行的应用或扩展进行。

本地验证记录保存在 Git 忽略的 `.local/`，不将开发者账户和签名信息写入公共文档。

## 目录

```text
main.go                          MyGo 原生主窗口
ui.go / ui_icons.go               三栏密码库界面、分类、搜索和详情
network.go                       登录、同步、取消与 UI 代次控制
internal/vaultwarden/            只读协议、KDF、解密及兼容性测试
demo.go                          本机演示服务器与公开 fixture
storage*.go                      受限 JSON / C ABI 桥接与错误处理
resources/                       主应用公开演示数据和 Safari 测试页面
macos/App/                       主应用 Info.plist 与共享权限
macos/AutoFill/                   AppKit Credential Provider
macos/Bridge/                    主应用进程内 Swift 动态库入口
macos/Shared/                    加密、Keychain、跨进程存储、版本与索引
macos/Tests/                     Swift 安全存储与匹配测试
macos/MyGoVaultwarden.xcodeproj/  两个 target 的构建与扩展嵌入
scripts/                         构建、安装与第三方许可证收集
```

## 许可证与来源

项目从初始 MIT 许可证切换为 GPLv3，见 [LICENSE](LICENSE)。自动填充流程参考 KeePassium；来源与复用范围见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。MyGo 等依赖保留各自许可证，应用包携带第三方声明。
