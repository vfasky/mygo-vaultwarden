# Vaultwarden macOS 原生客户端可行性调研

调研日期：2026-10-06。范围：MyGo Native UI 主应用、参考 KeePassium 的 macOS 系统自动填充、Vaultwarden 协议与本地安全存储。

## 结论

有条件可行。推荐采用 Go + MyGo Native UI 主应用、Swift/AppKit Credential Provider Extension、Swift 系统安全桥接层的混合架构。

MyGo 能承担密码库界面与 Go 业务逻辑，但其 Native UI 是 GPU 自绘控件，不是 AppKit/SwiftUI 控件集合。系统自动填充需要独立的 Apple 扩展 target、权限、签名和生命周期管理。不能把“整个产品只需一个纯 Go 二进制”作为本项目约束。

目前证据支持进入小型技术验证阶段；尚未完成 MyGo 主应用运行、真实 Vaultwarden 登录解密、扩展安装注册、Safari 填充、共享 Keychain 和 Developer ID 分发测试，不能据此称为端到端方案验证通过。

## 证据与版本边界

本次读取官方网页、GitHub 源码以及本机 Apple SDK。

- MyGo 树查询返回提交：`da84fc54dfc532704f60d5a066c0d1025d4dd282`。
- KeePassium 树查询返回提交：`e651df4f89b0b8550371566ca9aa55a964d2904e`。
- 源码文件按调研时的 main/master 获取；上述 SHA 是同次调研的树查询快照，未对每个文件做 blob 哈希一致性校验。正式 PoC 应固定依赖提交。
- MyGo 文档站显示 0.2.15；读取到的 `go.mod` 要求 Go 1.27.1，README 概述为 Go 1.27+。
- 本机 Xcode 27.0，macOS SDK 27.0；当前 shell PATH 中没有 `go`。
- 在临时目录编写一个独立 Swift API 探针，以 `arm64-apple-macosx14.0` 为目标，使用 `swiftc -typecheck` 成功验证 AppKit 视图、Credential Provider 子类及交互/无交互回调的类型。未执行这个扩展，没有使用实际凭据，也没有签名、安装或授权。

## MyGo 能承担的部分

已确认的能力：

- Go 编写视图，macOS 使用 Metal 绘制，无须 WebView。
- 文本输入、密码模式、列表、搜索、布局、键盘操作和可访问性接口。
- 窗口、菜单、托盘、剪贴板、全局快捷键、系统锁屏事件。
- 应用 bundle、Universal Binary、自定义 Info.plist 与 entitlements、代码签名、公证和更新。
- 打包原生动态库和 helper，支持通过 purego 使用原生库的集成模式。

需要补齐的部分：

1. 没有在已核查文档中发现现成的 AutoFill、Keychain 或 Touch ID 高层接口，需要自行封装 Security、LocalAuthentication、AuthenticationServices。
2. `cmd/mygo/bundle.go` 的 bundle 构建代码创建 `Contents/MacOS` 和 `Contents/Resources`，资源复制到 Resources。它不负责创建 Credential Provider target，也没有看到把 `.appex` 安装到 `Contents/PlugIns` 的配置。
3. 当前签名参数包含 `--deep`；含扩展的发布流程应明确区分主应用、动态库、扩展各自的 entitlements 和 provisioning profile，并按内到外顺序签名。不能把一个权限文件递归套到所有嵌套代码。
4. 自绘界面的 VoiceOver、中文输入、焦点、菜单和密码输入行为需要真实 macOS 测试；文档声明支持不等同于本项目已通过测试。

### 密码输入的具体发现

`ui.TextInput(...).Password()` 有遮挡字符、限制复制/剪切、隔离输入法文本、隐藏辅助功能值等设计。但读取 `ui/editor.go` 后发现：

- `.Password()` 设置 editor 的 password 标志。
- 通用 editor 保留 undo/redo，`record()` 没有针对密码模式排除历史记录。
- `command()` 对复制和剪切判断 password，但 undo/redo 仍进入通用逻辑。
- `setText()` 在已有撤销历史时保留先前内容用于撤销。

这意味着“把绑定的主密码字符串设为空”不能视为完整清理编辑器状态。此为源码控制流发现，尚未做运行时复现或内存取证。

建议：主密码/敏感字段进入生产前，补充禁用或安全重置历史的机制，核查 Secure Event Input、失焦/锁定时状态销毁和日志脱敏。Go 的不可变字符串及垃圾回收不能提供严格的全副本清零保证，应尽量缩短明文与密钥驻留时间，避免业务状态、调试输出和 UI 历史持有多份秘密。

## KeePassium 自动填充可参考什么

已读取以下实现：

- `KeePassium AutoFill/CredentialProviderViewController.swift`
- `KeePassium AutoFill/AutoFillCoordinator+quickMode.swift`
- `KeePassium AutoFill/AutoFillCoordinator+exitPoints.swift`
- `KeePassiumLib/KeePassiumLib/util/autofill/QuickTypeAutoFillStorage.swift`
- 主应用/扩展的 macOS entitlements 和 Keychain 封装。

可参考的流程：

1. 主应用将可填充条目的域名/URL、用户名及稳定 record ID 发布到 `ASCredentialIdentityStore`，用于系统候选。
2. 系统通过 `ASCredentialProviderViewController` 回调扩展。
3. 无交互请求在可以安全取得凭据时返回；否则取消并返回 `.userInteractionRequired`，由系统进入交互流程。
4. 交互流程完成解锁、匹配、搜索与用户选择，通过扩展上下文返回凭据。
5. 数据变更、删除和退出账号时维护系统候选索引。

`ASCredentialIdentityStore` 存的是候选身份，不是密码本体；它会向系统暴露必要的服务标识与用户名元数据，应在产品设计中说明。

KeePassium 这部分代码使用 UIKit，并包含 Mac Catalyst 分支，Xcode 工程也有 Catalyst 支持配置。因此适合参考回调、协调器分层、候选维护和共享存储模式；不能直接认为其 UI 可以移入 AppKit/MyGo。

Apple 为原生 macOS 提供对应 API：本机 SDK 标注基础 Credential Provider 为 macOS 11+，新式 request 回调与 passkey 相关接口为 macOS 14+，OTP Credential Provider 接口为 macOS 15+。本项目建议首版基线设为 macOS 14，OTP 系统填充通过版本判断在 macOS 15+ 启用，实际兼容性仍需运行测试。

## 推荐架构

```text
Vaultwarden 服务器
      │ HTTPS：登录、刷新 token、同步和写入
      ▼
MyGo 主应用（Go）
  ├─ 原生自绘 UI：密码库、搜索、详情、编辑、设置
  ├─ Vaultwarden 协议与 Bitwarden 格式加解密
  └─ Swift 安全桥：Keychain、Touch ID、App Group、候选索引
                  │
                  ▼
App Group：加密的自动填充快照与版本元数据
共享 Keychain：受访问控制保护的快照解密密钥
                  ▲
                  │
Swift/AppKit Credential Provider Extension
  ├─ 独立解锁与凭据选择 UI
  ├─ 按 record ID/服务标识读取匹配项
  └─ 返回 ASPasswordCredential 等系统对象
```

### 数据共享方案

建议首版由 Go 主应用负责完整 Vaultwarden 解密与同步，再生成仅包含自动填充所需字段的本地加密快照。Swift 扩展只负责这种本地格式的解密、选择和返回，不重复实现全套 Bitwarden 协议。

建议快照采用版本化格式、认证加密（例如 AES-GCM），其本地快照密钥独立于服务端账号密钥，由具有正确访问控制的 Keychain 项保护。完整 Vaultwarden 缓存仍以服务端密文形式保存。快照明确包含账号/服务端身份、条目 ID、版本和时间，以免账号切换后命中错误条目。

需要满足的约束：

- 扩展是独立进程。主应用关闭后，应能基于最近同步快照完成允许的离线填充。
- Touch ID 必须参与解密密钥的访问控制；不能仅做 UI 弹窗认证，再从无保护文件读取密钥。
- 无交互路径不强行弹出系统认证；需要认证则交回系统的交互流程。
- 更新快照采用原子替换或事务；先使快照可读，再更新索引，崩溃后可以重建索引。快照与系统索引之间不存在天然跨存储事务。
- 删除、登出、账号切换、主密码更改和锁定策略需要一致地处理索引、快照、Keychain 和扩展内存。不能只清理主进程状态；对并发中的请求也需要版本/撤销校验。
- 明确“锁定后允许通过 Touch ID 再解锁”和“退出账号立即撤销缓存”的差异。
- 服务器上的删除或权限变化，在离线状态下不能即时传达；应把离线缓存有效性策略作为产品规则。
- 持久化只有密文；主密码、解密密钥和 token 不进入日志、命令行参数或普通偏好文件。

Swift bridge 可设计为小型动态库，通过稳定 C ABI 与 Go 连接；MyGo 的 purego 集成方式能支持这条方向，但桥接、回调线程和签名仍需要 PoC。主应用和扩展应尽量复用同一套 Swift 快照/Keychain 代码。

另一方案是把共享 Go/Rust 核心链接进扩展，使两边直接读取 Bitwarden 密文。它减少派生快照，却引入跨语言构建、运行时和扩展约束，建议暂不作为首个验证版本的前提。

## Vaultwarden 兼容性

读取服务端源码后确认核心流程包括：

1. `/identity/accounts/prelogin` 获取该账号 KDF 类型及参数。
2. 客户端本地派生登录所需数据，调用 `/identity/connect/token`，处理 MFA 和 token 刷新。
3. `/api/sync` 返回 profile、ciphers、folders、collections、domains、policies 等加密数据和元数据。
4. 客户端恢复用户密钥，完成字段解密；编辑时在本地重新加密后提交。

需要实现的是 Bitwarden Password Manager 客户端协议，而不是只调用一个获取明文密码的 API。必须按账号返回参数支持 PBKDF2-SHA256 和 Argon2id，不能写死默认参数。

主要复杂度：

- 主密钥、用户密钥、条目密钥以及组织密钥之间的层级与格式演进。
- 常见 cipher string 的 AES-CBC/HMAC 等格式、认证校验、编码、KDF 参数和历史账号兼容。
- 个人条目和组织条目不同的解密路径。
- token 刷新、不同 MFA、设备身份、服务端版本差异。
- URL 匹配模式、等价域名、显式禁止匹配等规则；发布宽泛系统候选后仍需扩展按产品规则复核。
- 未支持字段的保留、修订冲突和并发修改；过早添加写入会增加破坏数据的风险。

当前源码已经同时保留若干新旧密钥字段与不同大小写约定，证明需要版本适配层和固定兼容性测试样本。

官方 `sdk-go` 面向 Secrets Manager，不能当作现成的密码库客户端 SDK。`sdk-internal` 含密码管理器逻辑和 Rust 加密库，但官方明确说不面向第三方公开使用、接口不稳定。其许可证也要按目录与依赖审查，不能笼统认定全都可无条件复用。

建议先实现有限范围 Go 适配层，以成熟密码库实现基础算法，使用官方客户端/SDK生成或核对固定测试向量。不要发明加密算法。若未来范围扩展到大量组织功能与 passkey，再比较维护 Go 兼容层和集成 Rust SDK 的长期成本。

## 系统自动填充的覆盖范围

- Safari 是首个验收对象。
- 其他原生应用取决于其与系统 AutoFill 的集成，需逐个测试。
- Chrome/Firefox 的网站自动填充不能因为实现了苹果 Credential Provider 就直接承诺支持；完整覆盖可能仍需浏览器扩展。
- 1Password 风格的任意应用快捷填充、辅助功能注入、窗口识别，属于额外功能。
- 自动保存网页中新密码、复杂表单填充、passkey 注册/签名不等价于基础密码填充。

## 打包、权限与分发

主应用与扩展都需要 AutoFill Credential Provider entitlement；共享数据与密钥还需各自正确配置 App Groups 和 Keychain Access Groups。KeePassium 的 macOS 扩展启用了 App Sandbox。

Apple 官方 macOS capability 表的 HTML 中，AutoFill credential provider 在 ADP 和 Developer ID 两列均有 `alt="yes"` 的勾选标记。因此支持 Developer ID 分发这一路径，不能断言只能上 Mac App Store。实际分发仍需匹配的开发者团队、标识、权限、profile、签名及公证验证。

建议构建流程：

1. 构建 Go/MyGo 主可执行文件或初始 bundle。
2. 使用 Xcode 构建 Swift bridge 与原生 macOS `.appex`。
3. 把扩展安装到 `App.app/Contents/PlugIns/AutoFill.appex`，按需要嵌入动态库及 profile。
4. 分别用各 target 对应权限签名嵌套代码和扩展，再签名外层主应用。
5. 最终签名后再生成 DMG、更新包并公证；不要继续发布 MyGo 在嵌入扩展前生成的旧产物。
6. 在干净用户环境验证安装、启用、升级、主应用关闭时填充和卸载。

主应用 sandbox 化建议在 PoC 中一并验证，避免后期改动权限与存储路径。Mac App Store 要求宿主 sandbox；本次证据不足以把这一要求外推为所有 Developer ID 宿主必需。

## 许可证

- MyGo：MIT。
- KeePassium：GPLv3；其源码头部另列商业授权联系方式。
- Bitwarden SDK：仓库默认提供 GPLv3 或 SDK License 选择，但 `bitwarden_license` 目录只适用 SDK License。

参考公开 API、行为与架构后独立实现，和复制/翻译源码是两种不同的复用方式。若直接移植 KeePassium 或 GPL SDK 代码，应按实际衍生/链接关系履行许可证义务；仅把代码放进另一个进程或扩展不自动免除这些义务。

本次“参考 KeePassium”不预设为直接复制代码，也不预设用户已选定整个项目的发行许可证。

## 推荐实施顺序与验收

先做有真实证据的技术验证，验证通过后再铺完整 UI：

1. 扩展骨架：MyGo 宿主嵌入 Swift `.appex`，用正式开发配置安装；系统设置可识别并启用，Safari 能填入固定测试凭据。
2. 共享安全存储：主应用写加密快照；完全退出主应用，扩展经认证读取并填充。验证取消认证、锁屏、登出、删除、索引过期、并发更新和扩展重启。
3. 真实协议只读：使用测试 Vaultwarden 账号，分别验证 PBKDF2 和 Argon2id、MFA、同步、离线解锁和 Safari 填充；与官方客户端核对同一条目。
4. MyGo 敏感输入：验证主密码清空后的撤销行为、锁定后 editor 状态、辅助功能可见值、输入法和剪贴板策略。
5. 发布验证：实际签名、公证、安装与升级，确认权限和 Keychain 访问持续有效。

首个可用版本建议包括：单服务器/单账号、主密码登录、TOTP MFA、个人 Login 条目只读同步、搜索、离线缓存、Touch ID、Safari 密码自动填充。

后续再加入：条目编辑和新建、组织库、浏览器扩展、多账号、OTP 系统填充、passkey。对于首版未支持的账号或条目类型，应明确提示，不假装同步完整，也不写回不理解的数据。

## 主要来源

- [MyGo 官方文档](https://mygo.egoist.dev/docs)
- [MyGo Native UI](https://github.com/egoist/mygo/blob/main/docs/ui/README.md)
- [MyGo 构建与分发](https://github.com/egoist/mygo/blob/main/docs/distribution.md)
- [MyGo bundle/签名实现](https://github.com/egoist/mygo/blob/main/cmd/mygo/bundle.go)
- [MyGo 文本编辑器](https://github.com/egoist/mygo/blob/main/ui/editor.go)
- [KeePassium 自动填充入口](https://github.com/keepassium/KeePassium/blob/master/KeePassium%20AutoFill/CredentialProviderViewController.swift)
- [KeePassium 候选索引实现](https://github.com/keepassium/KeePassium/blob/master/KeePassiumLib/KeePassiumLib/util/autofill/QuickTypeAutoFillStorage.swift)
- [KeePassium macOS 扩展权限](https://github.com/keepassium/KeePassium/blob/master/KeePassium%20AutoFill/KeePassium_AutoFill-macOS.entitlements)
- [Apple Credential Provider API](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)
- [Apple macOS capability/分发方式矩阵](https://developer.apple.com/help/account/reference/supported-capabilities-macos/)
- [Vaultwarden 登录实现](https://github.com/dani-garcia/vaultwarden/blob/main/src/api/identity.rs)
- [Vaultwarden prelogin 实现](https://github.com/dani-garcia/vaultwarden/blob/main/src/api/core/accounts.rs)
- [Vaultwarden 同步与条目实现](https://github.com/dani-garcia/vaultwarden/blob/main/src/api/core/ciphers.rs)
- [Bitwarden Internal SDK](https://github.com/bitwarden/sdk-internal)
- [Bitwarden SDK 许可证范围](https://github.com/bitwarden/sdk-internal/blob/main/LICENSE)
