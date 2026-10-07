# MyGo Vaultwarden

使用 Go + MyGo Native UI 和 Swift/AppKit 构建的 macOS Vaultwarden 客户端。采用 GPL-3.0-only。

已接入 Vaultwarden 登录、同步及个人密码库写入：支持 PBKDF2、Argon2id、TOTP 登录验证、先持久化的令牌刷新、八种项目的标准字段新增/编辑、四类自定义字段、网址匹配策略、密码历史查看、文件夹管理/筛选、收藏、归档和回收站操作。编辑页可将当前表单复制为使用独立密钥的新个人项目，保留标准字段和历史；含附件、通行密钥或未知扩展的项目会明确拒绝复制。批量移动、归档、软删、恢复和清回收站均需确认，并同步逐项核对结果，部分成功不会自动重复执行。完整服务器加密同步数据保存在受 Keychain / 主密码保护的本机加密快照中；系统自动填充使用独立的个人 Login 投影。顶栏「导入导出」提供逐项选择的 Bitwarden 兼容 JSON 与八类 MyGo 明文备份，均需预检和敏感确认；文件夹（含空文件夹）、历史与标准字段可回导，导入创建新副本并逐项核对，未知结果不重试。MyGo 格式与官方格式明确分开，尚不能无损转换的附件/通行密钥/扩展会阻断，已有导出文件不会覆盖。个人再次验证项目已接入30秒主密码授权，登录密码/TOTP短时显示和认证受控复制已实现；同步后可比较本地与远端改动，并明确选择采用远端或把所选修改重新应用到最新草稿，详见 [冲突处理](docs/cipher-conflicts.md)。完整 API 工作仍未完成：含附件/通行密钥等项目的完整复制与备份、组织导入导出、批量/导出的逐项再次验证、双改列表逐行冲突处理、组织、附件、Send 和账号安全管理等尚缺；准确状态见 [API 覆盖矩阵](docs/vaultwarden-api-coverage.md)。

## 开发环境

- macOS 14+，Xcode 完整安装。
- Go 1.27.1+；MyGo 固定为 v0.2.15。
- 完整 AutoFill 验证需要 Apple Developer Program、Xcode 中已登录的开发者账号、开发证书和 Developer ID Application 证书。
- Go 主界面不使用 HTML、JavaScript 或 WebView。

`go` 不在 PATH 时可通过 `GO_BIN=/absolute/path/to/go` 指定。脚本也识别 Homebrew 和本项目的用户缓存工具链。

## 构建与安装

开发时要体验真实登录、安全存储及系统自动填充，使用一键完整 Debug 入口：

```sh
bash scripts/dev-debug.sh
```

脚本默认持续监听 Go、Swift、资源和构建配置的变化，自动完整构建、验证签名、安装并重启包含安全存储组件和 AutoFill 扩展的应用。需要先配置下文的本机签名信息和 Xcode 开发者账号；日志追加到 `build/debug/dev-debug.log`。

首次启动监听前请退出已安装的完整应用。后续保存代码即可自动重载：编译或签名失败时保留正在运行的版本；构建期间再次保存会继续构建最新源码。构建产物不会触发重复构建。同一台机器只允许一套此脚本管理完整应用；关闭应用或按 `Ctrl+C` 会结束监听，并清理本次监听启动的进程。已有的 `mygo dev` 界面预览不会被关闭。

这里与 [MyGo 的 `mygo dev`](https://mygo.egoist.dev/docs/cli#mygo-dev) 一样采用重新编译并重启进程的方式，不保留内存中的登录状态。已有加密快照可在重启后通过主密码或系统认证解锁，并恢复已保存的登录会话以继续同步。完整签名和扩展导出耗时比仅界面预览更长。修改监听器自身（`scripts/dev-debug/`）后需要重新启动脚本。

只构建、安装并启动一次可用：

```sh
bash scripts/dev-debug.sh --once
```

启动后点击“登录并同步”体验真实登录。系统自动填充仍需在 macOS“自动填充与密码”中手动启用 MyGo Vaultwarden，并实际验证 Safari 填充。

也可分别执行构建与安装：

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
2. 在登录页填写主密码；账号启用 TOTP 时，页面切换到“两步验证”，输入验证器代码并继续。错误提示、重试和取消都在页面内完成。
3. 同步成功后，主窗口显示个人登录条目和未支持/排除数量，可搜索或打开对应网站。
4. 在 macOS“自动填充与密码”中启用 MyGo Vaultwarden；需要时点击“更新系统候选”并完成系统认证。
5. 在 Safari 的匹配网站选择本应用的凭据，经系统认证后填充。严格 Host / Exact 规则只在系统提供可核对的来源时匹配，详见协议说明。
6. 主应用退出后，扩展仍能独立读取加密快照。重启主应用后，可输入主密码并点击“解锁密码库”，或点击“使用 Touch ID 解锁”查看本机列表。

未登录时显示独立的“登录服务器”页面，直接填写服务器地址、邮箱和主密码；需要两步验证时在同一窗口切换至验证码表单，不弹出登录对话框。已有本机快照但未解锁时显示独立锁定页，输入主密码并点击“解锁密码库”（支持回车），或选择“使用 Touch ID 解锁”；系统认证也允许按 macOS 提示使用 Mac 登录密码。旧版快照需重新登录并同步一次，才能启用主密码离线解锁及登录凭据持久化，已有 Touch ID 入口继续可用。也可以选择“使用其他账号”进入登录页，提交前会提示替换已有离线快照。各认证页面均沿用应用 Logo、灰紫渐变和现有圆角控件，采用居中布局。

解锁后进入三栏主界面：左侧为密码库与分类，中间为可搜索的项目列表，右侧为选中项目详情。使用 `⌘F` 搜索标题、用户名或网站，列表支持上下键选择；详情支持复制用户名和打开 HTTP(S) 网站。右上角或左下角的“账号与设置”提供登录服务器入口、离线解锁、候选更新和退出账号。右上角“锁定”会立即隐藏项目列表和详情、清空搜索及敏感输入，并完整切换至解锁页。主密码和验证码使用遮掩输入；密码库条目的密码仍通过系统认证后自动填充。

界面使用浅灰紫背景、白色圆角面板和本地生成的文字图标，不请求远程网站图标。八类个人项目、收藏、文件夹、归档和回收站均可导航；侧栏可新建/管理文件夹，顶栏可创建项目或进入批量管理。组织等未实现模块仍见覆盖矩阵。

登录会先切换并撤销此前本机账号快照。成功同步后，refresh token、设备标识、用户密钥和快照包装密钥保存在 AES-GCM 加密 payload 内；不保存原始主密码或 access token。锁定只清除内存中的会话与显示内容，主密码或 Touch ID 解锁后可恢复登录会话，点击“同步”会刷新 access token 并下载密码库。退出登录则撤销本机快照、已保存登录凭据和密钥。服务器撤销或拒绝登录凭据时才需要重新登录；旧版缓存没有登录凭据时，点击“同步”会引导登录一次。Safari 自动填充仍使用系统认证。

原始主密码不发送到服务器，不写入配置、日志或命令行；仅在登录或离线解锁时参与本地派生。手动查看扩展列表和实际填充分别认证，过期或被锁定的请求不能继续提交。

成功同步全量替换快照；普通网络/解密失败保留上次成功快照并明确报错。refresh token 更新会先加密落盘，再下载密码库，即使后续断网也可在下次解锁后继续同步。账号身份或认证失效要求重新登录。登出先撤销快照，再清理 Keychain 和系统候选。候选回执与旧密钥清理的状态独立显示。

实现边界见 [安全快照设计](docs/secure-snapshots.md)、[登录与同步说明](docs/vaultwarden-readonly.md) 和 [API 覆盖矩阵](docs/vaultwarden-api-coverage.md)。

## 测试

```sh
go test ./...
go vet ./...
swift test --package-path macos
```

界面交互测试覆盖主密码遮掩和复制限制、验证码校验与重试、敏感输入清空后的撤销隔离、认证取消与过期响应、登录/锁定页面切换、回车提交、认证期间的导航禁用、锁定后的内容隐藏，以及搜索、键盘选择、详情切换、复制用户名、打开网站与快照撤销后的详情清除。可使用公开虚构数据导出登录页、两步验证页、锁定页和三栏界面的原生渲染预览（不访问真实密码库或 Keychain）：

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

## 目录

```text
main.go                          MyGo 原生主窗口
ui.go / ui_auth.go / ui_icons.go  登录、解锁与三栏密码库界面
network.go                       登录、同步、取消与 UI 代次控制
internal/vaultwarden/            协议、KDF、个人项目加解密与写入及兼容性测试
storage*.go                      受限 JSON / C ABI 桥接与错误处理
resources/                       应用图标及品牌资源
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
