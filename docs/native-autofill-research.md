# macOS 无浏览器扩展的账号密码填充调研

调研日期：2026-10-13  
范围：MyGo Vaultwarden 在 macOS 上，不安装 Chrome 浏览器扩展时的账号密码填充能力，以及以 Raycast 扩展作为快捷键入口的可行性。  
状态：已完成公开资料调研和项目代码核对；未实现原型，未进行 Chrome 实机填充测试。Raycast 部分基于既有知识评估，未联网查阅其当前 API 文档，标注“需确认”的条目须核实后再作为依据。

## 结论

原生 macOS App 可以不依赖 Chrome 扩展完成账号密码填充，但不同路线的能力和权限边界不同：

- Apple 系统 AutoFill：适用于 Safari 和支持该机制的原生 App。本项目已经实现这条路线。
- 原生辅助功能填充：通过全局快捷键、原生账号选择器及辅助功能 API，向 Chrome 等浏览器和其他 App 填充。1Password Universal Autofill 提供了产品先例。
- Auto-Type：模拟键盘输入账号、Tab 和密码，KeePassXC 提供了产品先例。它依赖焦点和字段顺序，网站身份验证能力有限。

本次未找到 Chrome 在 macOS 上直接接入任意第三方系统密码提供者、提供与 Safari 相同账号密码填充体验的官方依据。因此不能承诺仅修改现有 Credential Provider 扩展，就能让 Chrome 登录框显示本项目的密码候选。

若目标是 Chrome 无插件填充，建议先验证“快捷键呼出 → 选择账号 → 填入当前页面”的原生辅助功能方案。其主要架构约束是：本项目主应用和 AutoFill 扩展均启用了 App Sandbox，而 Apple 明确说明沙盒应用不能使用跨应用辅助功能 API。[1][4][7]

补充判断：

- 项目已有“沙盒主应用 + 内嵌非沙盒 XPC 服务”的先例（`UpdateHelper`），非沙盒填充辅助程序的分发和进程通信有现成模式可参照；但辅助功能授权归属于哪个进程尚未验证，这是决定架构的首要风险。
- 快捷键呼出和账号选择器可以留在沙盒主应用内；需要高权限的只有“识别目标与写入字段”这一窄接口。
- Raycast 扩展只能替代快捷键和选择界面这部分，不能解决可信网站身份、字段定位和沙盒限制。建议仅作为打开 MyGo 原生选择器的附加入口，密码不进入 Raycast 进程。

## 方案对比

| 方案 | 无 Chrome 扩展是否可行 | 交互方式 | 主要边界 | 本项目状态 |
|---|---|---|---|---|
| Apple 系统 AutoFill | 对 Safari 和支持该机制的 App 可行；Chrome 账号密码接入未确认 | 系统展示候选，用户选择并认证后填充 | 依赖目标应用接入系统机制，无法主动控制任意网页输入框 | 已实现 |
| 原生辅助功能填充 | 可行，有成熟产品先例；本项目仍需原型验证 | 快捷键呼出原生选择器，识别目标并填充 | 需要辅助功能授权、浏览器适配及非沙盒执行组件 | 未实现 |
| Auto-Type | 可行，有成熟产品先例 | 在当前焦点处模拟账号、Tab、密码等输入 | 焦点、字段顺序、键盘布局和页面变化影响可靠性；窗口标题不构成可信网站身份 | 未实现 |
| 快速搜索 + 复制 | 可行 | 快捷键呼出搜索面板，复制后由用户粘贴，定时清除 | 不验证目标页面；剪贴板可被其他进程读取 | 复制与定时清除已有，快捷键面板未实现 |
| Raycast 扩展入口 | 可作为入口；不改变上述各路线的安全边界 | Raycast 快捷键触发命令 | 用户须安装 Raycast；取网址只能靠 AppleScript；密码若经 Raycast 则扩大信任范围 | 未实现 |

“不依赖浏览器扩展”并不意味着不需要安装其他系统组件：Apple 系统 AutoFill 使用随原生 App 分发的 Credential Provider 扩展，辅助功能方案可能需要独立辅助程序。

## 路线一：Apple 系统 AutoFill

### 工作机制

原生 App 提供基于 `ASCredentialProviderViewController` 的 Credential Provider 扩展，并在主应用和扩展上启用 AutoFill Credential Provider entitlement。用户在 macOS 设置中启用提供者后，系统向扩展请求凭据；扩展可以发布凭据标识供系统展示候选，并在用户选择后交付账号密码。[1][2]

这是系统介导的填充机制，支持范围取决于目标应用。它不赋予密码管理器读取或控制任意浏览器页面的能力。

### 已确认的范围和未确认的范围

- Apple 官方资料描述了第三方提供者向 Safari 和支持的 App 提供凭据的路径。[1][2]
- 1Password 的原生 macOS AutoFill 文档同样描述了 Safari 和兼容 Mac App 的使用方式。[3]
- 本次未找到 Chrome 在 macOS 上直接接入任意第三方 Credential Provider、提供 Safari 同等账号密码候选体验的官方证据。
- Apple 自家的 Passwords 为第三方浏览器提供了浏览器扩展路径；这能说明一种实际集成方式，但不能单独证明所有其他接入方式都不存在。[9]
- Passkey 与账号密码属于不同的认证交互，不能用 Chrome 的 Passkey 支持推断其账号密码 AutoFill 支持。

### 项目现状

| 代码或配置 | 已核对内容 |
|---|---|
| [CredentialProviderViewController.swift](../macos/AutoFill/CredentialProviderViewController.swift) | 继承 `ASCredentialProviderViewController`；接收服务标识和凭据请求；通过 `ASPasswordCredential` 向系统交付账号密码 |
| 同上 | 非交互回调返回 `userInteractionRequired`，交互流程执行认证；不能把它描述为后台静默读取密码 |
| [AutoFill/Info.plist](../macos/AutoFill/Info.plist) | 声明 `ProvidesPasswords`；`ProvidesPasskeys` 与 `ProvidesOneTimeCodes` 为 false |
| [App.entitlements](../macos/App/App.entitlements) | 主应用启用 AutoFill Credential Provider entitlement 和 App Sandbox |
| [AutoFill.entitlements](../macos/AutoFill/AutoFill.entitlements) | AutoFill 扩展启用对应 entitlement 和 App Sandbox |
| [README-cn.md](../README-cn.md) | 对用户承诺的系统自动填充场景为 Safari |
| [project.pbxproj](../macos/MyGoVaultwarden.xcodeproj/project.pbxproj) | 当前 macOS 部署目标为 14.0 |

这些是源码和配置核对结果，不等同于本次进行了签名产物检查或各浏览器的运行验证。

## 路线二：原生辅助功能填充

### 产品先例

1Password Universal Autofill 要求用户在 macOS“隐私与安全性 → 辅助功能”中授权，使用 `⌘\` 向当前 App 或网页填充；多个账号匹配时通过 Quick Access 选择。[4]

其权限说明明确表示，会使用 macOS 辅助功能 API 检查应用、识别可填充字段、推荐凭据并执行填充。[5]

这一先例证明原生辅助功能路线具备产品可行性，但其支持文档未公开完整实现。本次没有确认它具体如何取得 Chrome 当前 URL，也不能认定其网站验证逻辑与浏览器扩展完全相同。

### 可供本项目验证的交互

1. 用户在 Chrome 登录页面触发全局快捷键。
2. 捕获前台应用、目标窗口及当前页面身份，尝试识别登录字段。
3. 显示原生账号选择器；密码库锁定时先完成解锁或所需认证。
4. 用户选择账号后，重新核对目标应用、页面和焦点，防止选择过程中切换了目标。
5. 填入账号密码；初期默认不自动提交表单。

这是建议流程，不是现有实现。

### 职责拆分建议

为缩小高权限组件的范围，建议按进程拆分职责：

| 职责 | 建议位置 | 说明 |
|---|---|---|
| 全局快捷键 | 沙盒主应用 | 预期使用 Carbon `RegisterEventHotKey`，通常不需要额外授权；仍需在签名沙盒产物上验证 |
| 账号选择器、解锁、认证 | 沙盒主应用 | 复用现有密码库、Touch ID 和锁定流程 |
| 识别前台目标（应用、页面 URL、焦点字段） | 非沙盒填充辅助程序 | 只返回比对所需的目标描述，不接触密码库 |
| 写入字段 | 非沙盒填充辅助程序 | 只接收本次请求的单条凭据；写入前再次核对目标，目标变化即中止 |

辅助程序不缓存凭据。每个请求带唯一标识和有效期；锁定、取消、账号切换或目标变化后，旧请求及迟到结果一律作废。这是设计建议，不是已实现或已验证的安全结论。

### 需要验证的技术边界

- 辅助功能树不等同于网页 DOM。需要实测 Chrome 是否稳定暴露当前 URL、用户名框、密码框以及可用的写入操作。
- Chrome 通常在辅助功能客户端设置 `AXManualAccessibility` 或 `AXEnhancedUserInterface` 后才完整暴露网页内容。首个原型应确认设置后能否稳定读取网页区域的 URL；这是待验证的技术线索，不是已确认行为。
- 页面身份应从焦点密码框向上查找最近的网页区域取得，而不是只读取地址栏或顶层页面 URL，以便识别 iframe 中的登录框。若无法取得字段所属框架的来源，应拒绝自动匹配。
- 直接设置输入框的值可能不触发 React 等前端框架识别的输入事件。可评估的退路是：先通过辅助功能确认并聚焦目标字段，再以键盘事件输入该字段，前提是目标字段已经核实。
- 标准双字段登录、先账号后密码的分步登录、自定义输入控件、跨域 iframe 和动态重绘页面需分别验证。
- Chrome、Edge、Brave 等虽然共享 Chromium 基础，也不能未经测试就承诺相同兼容性。
- 原生选择器显示和认证可能改变前台窗口或焦点。填充前必须重新核对目标，目标变化时停止本次操作。
- 能读取地址栏 URL，不等于已确认目标输入框所属 iframe 的来源。顶层网页与实际接收密码的框架可能不同。
- 窗口标题由网页控制，不能作为可信域名依据。无法可靠验证网站身份时，应阻止自动匹配发送密码，提供清晰的人工确认或手动操作路径。
- 辅助功能授权和自动化授权是不同权限。只有实现实际使用 Apple Events 等能力时，才评估相应自动化授权；不预先把它列为所有方案的必需权限。

## 路线三：Auto-Type

KeePassXC 提供不依赖浏览器扩展的 Auto-Type，典型序列为 `{USERNAME}{TAB}{PASSWORD}{ENTER}`，可以配置全局快捷键和窗口标题匹配。[6]

它适合规则简单、焦点明确的表单，也可作为用户主动选择凭据后的兼容路径，但存在明显限制：

- Tab 顺序或页面布局变化可能把密码输入到错误字段。
- 分步登录和异步加载需要额外等待与状态判断。
- 窗口标题匹配不等于 URL 或来源验证。即使标题包含可信域名，恶意网页也可以伪造该标题。[10]
- 模拟键盘、辅助功能写入和剪贴板粘贴是不同实现，不能仅凭某一种技术可用就推断其余方式的权限和可靠性。

若验证此路线，建议首版只由用户显式触发，默认不发送 Enter，不将窗口标题匹配用作自动释放密码的安全依据。

### AppleScript 取 URL 的变体

Chrome、Edge、Brave、Arc 等提供脚本接口，可通过 AppleScript 读取当前标签页 URL，再配合模拟键盘输入。这一变体有可能不新增非沙盒进程，但需要自动化授权和沙盒的 Apple Events 例外 entitlement，且存在以下不足：

- 只能取得顶层页面 URL，无法识别 iframe 中登录框的来源。
- 不能确认键盘输入最终落入哪个字段。
- Firefox 等不提供同类脚本接口的浏览器无法使用。

按本文“网站身份无法核实时不自动发送密码”的标准，它弱于辅助功能方案。建议不作为独立路线，仅在辅助功能已核实目标字段、直接写入失败时，作为字段输入的退路。

## 快速搜索与复制入口

在完成辅助功能原型之前，可以先提供不新增权限的入口：全局快捷键呼出搜索面板，用户选择条目后复制用户名或密码，再自行粘贴。

项目已有复制与定时清除实现：

| 代码 | 已核对内容 |
|---|---|
| [SensitiveClipboard.swift](../macos/Shared/SensitiveClipboard.swift) | 写入时附加 `org.nspasteboard.ConcealedType` 与 `TransientType` 标记及随机所有者标识；清除前核对 `changeCount` 与所有者，避免误清他人写入 |
| [SnapshotBridge.swift](../macos/Bridge/SnapshotBridge.swift) | 复制后按剩余时长定时调用 `clear(ifOwned:)` |

代码注释已说明其边界：Concealed/Transient 只是提示，其他进程仍可读取剪贴板；清除是尽力而为，无法保证击败并发的外部写入。该入口不验证目标页面，只适合作为用户主动操作的兜底，同时可为后续原生选择器打基础。

## Raycast 扩展入口评估

### 项目对外通道现状

| 项目 | 核对结果 |
|---|---|
| 命令行工具 | 无，`cmd/` 为空目录 |
| 本地 HTTP 或 socket 服务 | 无；Go 代码中唯一的监听位于测试工具 [tools/invitation-smtp](../tools/invitation-smtp/main.go) |
| URL Scheme | 仅 `bitwarden://`，用于认证回调（[App/Info.plist](../macos/App/Info.plist)） |
| 加密快照 | 位于 App Group，密钥在团队专属钥匙串分组，外部进程不可访问，也不应开放 |

因此，若让 Raycast 读取凭据，主要开发量和安全风险不在扩展本身，而在为沙盒主应用新开一条外部进程可调用的通道。

### Raycast 可提供的能力

以下条目基于既有知识，未联网核实：

- 用户可以为扩展命令绑定全局快捷键；扩展可能无法自带默认快捷键（需确认）。
- 以 TypeScript/React 构建列表搜索界面，可获取前台应用。
- `Clipboard.copy` 提供 `concealed` 选项，可不进入 Raycast 剪贴板历史；`Clipboard.paste` 通过剪贴板加模拟 `⌘V` 输入，借用 Raycast 自身的辅助功能授权。粘贴是否同样不进历史、是否恢复原剪贴板，需确认。
- Raycast 的浏览器标签接口依赖 Raycast 浏览器扩展，违反本调研“不安装浏览器扩展”的前提，不能采用。不用该扩展时，只能通过 AppleScript 读取顶层 URL，自动化授权归属 Raycast。
- 扩展可运行本地程序（可能支持 Swift 原生代码，需确认）。这些子进程的辅助功能授权很可能归属 Raycast，理论上可绕开 MyGo 沙盒读取 Chrome 界面，但这会把密码和界面控制交给第三方进程，不建议采用。

### 不能解决的问题

- 网站身份：与“AppleScript 取 URL 的变体”相同，无法识别 iframe 来源和焦点字段。
- 填充目标：粘贴写入当前焦点，无法确认焦点是目标密码框。
- 信任范围：密码若进入 Raycast，会经过不开沙盒的第三方进程及其 Node 运行时，JavaScript 字符串无法可靠清零；使用粘贴还会经过系统剪贴板。这与 README 中“最小权限自动填充”的表述冲突。

### 集成方式对比

| 方式 | 做法 | 判断 |
|---|---|---|
| Raycast 仅作启动器 | 命令打开新增 URL（如 `mygo-vaultwarden://quick-fill`），由 MyGo 自己显示选择器、认证并填充 | 建议采用，前提是原生选择器已实现。密码不进入 Raycast，扩展代码量很小。URL Scheme 可被任意网页或应用触发，因此只能打开面板，不得携带参数直接填充指定条目 |
| Raycast 选择，MyGo 填充 | Raycast 获取名称、用户名、域名等非敏感列表，选定后把条目标识交给 MyGo | 不建议。明文列表文件会泄露账号与网站清单；XPC 方案开发量大。服务端校验调用方签名只能证明调用方是本项目签名的程序，不能证明由用户发起，因为任意本地进程都能执行该程序，每次填充仍需在 MyGo 中确认和认证 |
| Raycast 全包 | 使用现有社区 Bitwarden Raycast 扩展，通过官方 `bw` CLI 连接自建 Vaultwarden | 可作为零开发的交互体验基准；与 MyGo 无关，需单独解锁，凭据缓存及安全边界由 Raycast 与 `bw` 决定 |

### 其他约束

- 分发：Raycast 商店扩展统一发布在 raycast/extensions 仓库并采用 MIT 许可（需确认）；本项目为 GPL-3.0-only，扩展须作为独立新代码，不能直接复用项目中的 GPL 代码。仅个人使用时可通过本地开发模式导入。
- 用户覆盖：只有安装 Raycast 的用户可用，不能替代 MyGo 自带入口。
- 价值：MyGo 可自行注册全局快捷键，Raycast 入口主要服务于已习惯 Raycast 的用户。

## App Sandbox 对架构的影响

Apple 技术支持在官方论坛说明：“Sandboxed app cannot use the Accessibility APIs”，并指向 App Sandbox 文档。[7][8]

因此，用户授予辅助功能权限并不意味着现有沙盒进程就能使用跨应用辅助功能接口。不能把这个功能当作在主应用里增加一个权限提示即可完成的改动。

上述结论针对跨应用辅助功能路线。本次未确认所有 `CGEventPost` 用法都被沙盒一概禁止，不能把不同 API 的限制混为一谈。

### 项目已有的非沙盒 XPC 先例

| 代码或文档 | 已核对内容 |
|---|---|
| [UpdateHelper/main.swift](../macos/UpdateHelper/main.swift) | 内嵌于 `Contents/XPCServices/UpdateHelper.xpc`；工程中未为其配置 entitlements 文件，即不启用 App Sandbox；监听时以 `setCodeSigningRequirement` 只接受同团队、同标识符主应用的连接 |
| [UpdateHelperClient.swift](../macos/Bridge/UpdateHelperClient.swift) | 主应用通过 `NSXPCConnection(serviceName:)` 拉起并连接该服务 |
| [updates.md](updates.md) | 说明该服务不开沙盒的原因、调用方签名要求，以及只处理自身所在 bundle、不接收路径参数的窄接口设计 |

这说明“沙盒主应用 + 非沙盒内嵌组件”的签名、分发、公证和进程通信在本项目已有可参照模式。填充辅助程序可沿用相同的连接方校验和窄接口原则。该先例只证明更新场景可用，不证明辅助功能场景可用。

### 首要风险：辅助功能授权的归属

macOS 隐私授权通常记在“负责进程”上，内嵌 XPC 服务的负责进程一般是宿主应用。这意味着很可能是主应用出现在“辅助功能”列表中，而实际调用接口的是非沙盒 XPC 服务。这种组合在主应用启用沙盒时能否成立，本次未验证，必须用正式签名产物实测。

若不成立，可评估以 `SMAppService` 注册的独立登录项辅助程序。它在系统中具有独立身份和独立授权，代价是安装、启动、更新和卸载流程更复杂。

### 可评估的架构选项

| 选项 | 影响 | 判断 |
|---|---|---|
| 保持现有沙盒架构，仅使用系统 AutoFill | 保留当前安全边界和 Safari 集成；无法据此承诺 Chrome 无插件填充 | 现有能力的稳妥延续 |
| 主应用改为非沙盒 | 更直接地承载辅助功能逻辑，但失去主应用现有的沙盒保护 | 不建议在未验证替代架构前采用 |
| 主应用和系统 AutoFill 保持沙盒，增加内嵌非沙盒 XPC 填充服务 | 可沿用 `UpdateHelper` 模式，限制高权限能力的范围；授权归属未验证 | 建议优先原型验证 |
| 主应用和系统 AutoFill 保持沙盒，增加独立登录项辅助程序 | 授权身份独立清晰，但生命周期和分发更复杂 | XPC 方案授权归属不成立时的备选 |

采用非沙盒组件不等于必须放弃 Developer ID 签名、公证或 Hardened Runtime；这些机制与 App Sandbox 的职责不同。具体分发和权限行为仍需用正式签名产物验证。

若评估独立辅助程序，应至少验证以下边界：

- 沙盒主应用能否通过受支持的机制安装、启动并连接辅助程序。
- 通信双方的签名身份验证、调用授权和请求有效期。
- 辅助程序是否可以只接收本次填充所需的单条凭据，避免长期持有整个解密密码库。
- 锁定、取消、账号切换、目标窗口变化后，旧请求和迟到结果是否失效。
- 辅助功能权限被拒绝、撤销，以及应用更新后的恢复行为。

这些属于后续验证要求，不是已经实现或已通过的安全结论。

### 对外说明的影响

README 目前只承诺 Safari 系统自动填充，并写明“主应用与自动填充扩展均启用 App Sandbox”。若增加 Chrome 填充，需要同步说明新增的辅助功能授权、非沙盒组件的职责范围及其不持有密码库的约束，避免让用户误以为所有组件都在沙盒中运行。

## 建议的最小验证范围

保留 Safari 系统 AutoFill，先以 Chrome 为唯一目标进行可行性验证，再决定是否开发正式功能。按风险从高到低排序：

| 顺序 | 验证项 | 通过标准 |
|---|---|---|
| 1 | 辅助功能授权归属 | 正式签名产物中，内嵌非沙盒 XPC 服务在沙盒主应用下可获得并使用辅助功能授权；不成立时改为验证独立登录项方案。此项决定整体架构 |
| 2 | 网站身份识别 | 从浏览器界面可靠识别焦点字段所属页面的 URL，不依赖网页标题；明确 iframe 场景的识别限制 |
| 3 | 基本字段填充 | 标准账号密码表单可正确填写，不误填其他文本框；比较直接写值与“聚焦后键盘输入”两种方式在普通表单和 React 表单上的表现 |
| 4 | 分步登录 | 账号页到密码页的状态变化有明确处理，页面未就绪时不盲目输入 |
| 5 | 全局快捷键 | 沙盒主应用中可注册并触发全局快捷键 |
| 6 | 焦点与目标变化 | 选择凭据、认证或填充过程中切换窗口、标签页时停止旧操作 |
| 7 | 密码库状态 | 锁定、取消、账号切换会使待执行填充失效 |
| 8 | 失败处理 | 权限撤销、字段不可识别、网站身份无法核实时明确失败，不自动退化为向未知焦点发送密码 |

第 1、2 项均通过后，方案才具备落地基础；任何一项失败，应先回到架构选择，而不是退回窗口标题匹配。

首轮可用测试凭据和本地测试页面验证字段操作，再测试真实网站的页面结构与浏览器行为。正式支持清单应按实际测试结果建立，不能以浏览器同属 Chromium 作为兼容性证明。

## 建议的实施顺序

1. 快速搜索与复制入口：沙盒内完成，不新增权限。
2. 按“建议的最小验证范围”完成辅助功能原型，确定填充辅助程序的形态。
3. 原型通过后开发正式的原生辅助功能填充。
4. 原生选择器可用后，按需增加只负责打开 MyGo 选择器的 Raycast 命令。

## 本次调研的证据与限制

已完成：

- 检索 Apple、1Password、KeePassXC 的官方文档和相关维护者讨论。
- 核对本项目 Credential Provider 实现、沙盒 entitlement、部署目标和 README 中的支持范围。
- 确认系统 AutoFill 与辅助功能填充是不同路线，并识别现有沙盒架构对后者的限制。
- 核对 `UpdateHelper` 的非沙盒 XPC 模式、安全剪贴板实现，以及项目当前没有对外数据通道。

尚未完成：

- Chrome、Safari 或其他 App 的现场填充测试。
- Chrome 辅助功能树、URL 获取、字段写入和跨域 iframe 行为的原型验证。
- 内嵌 XPC 服务或独立辅助程序的辅助功能授权归属、生命周期、签名、授权及通信验证。
- 各 macOS 和浏览器版本的兼容性验证。
- 查阅 Raycast 当前 API 文档与商店政策，核实本文标注“需确认”的条目。

因此，本次结论是“存在可行的技术路线和产品先例”，不是“本项目已具备 Chrome 无插件自动填充能力”。

## 参考资料

以下链接为本次调研使用的资料，产品文档可能持续更新。Raycast 部分未引用外部资料。

1. Apple：ASCredentialProviderViewController  
   https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller
2. Apple：Credential provider extensions  
   https://support.apple.com/en-ca/guide/security/sec6319ac7b9/web
3. 1Password：Use 1Password to sign in to apps and websites on your Mac（原生 macOS AutoFill）  
   https://support.1password.com/macos-autofill/
4. 1Password：Use Universal Autofill in apps and browsers on your Mac  
   https://support.1password.com/mac-universal-autofill/
5. 1Password：About macOS Privacy & Security settings for Universal Autofill  
   https://support.1password.com/mac-universal-autofill-settings/
6. KeePassXC：User Guide（Auto-Type）  
   https://keepassxc.org/docs/KeePassXC_UserGuide
7. Apple Developer Forums：Sandbox Entitlements Question（Apple DTS 答复）  
   https://developer.apple.com/forums/thread/789663
8. Apple：Protecting user data with App Sandbox  
   https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox
9. Apple：Get extensions to autofill passwords in third-party browsers  
   https://support.apple.com/guide/passwords/get-extensions-mchlf7ac261e/mac
10. KeePassXC：关于 Auto-Type 窗口标题与 URL 匹配的讨论  
    https://github.com/keepassxreboot/keepassxc/discussions/10681
11. 1Password：About the security of 1Password Autofill in your browser（浏览器扩展的域名与 iframe 来源校验，用于区分两种路线）  
    https://support.1password.com/browser-autofill-security/
