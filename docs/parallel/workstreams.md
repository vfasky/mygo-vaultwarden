# 并行客户端开发契约

## 共同基线与本轮启动整合

- 功能模块共同基线：`14bbaf0ec2f176c598560883cc895f4dcd24405d`。各模块在自己的干净 Board 工作树从该固定提交开发，不复制其它工作树的未提交内容。
- 本卡启动时实际 `main` 和工作树 HEAD：`b5cfebe13d80d777789718bad6b36eb09512304a`，已包含 `272cc580670d8bfe6d027e0bed93e520da06e174` 的侧栏折叠功能。卡片原记载的 `0b88875e044ee8f3f30b6c21576aed9d22e3c28d` 已不是启动时主线。
- `0b88875` 与原功能基线 `4b0a910` 的树差异只有 `shot.png` 和 `shot-s.png`；必须保留这两张截图。`b5cfebe` 又增加 `main.go`、`ui.go`、`ui_icons.go`、`ui_test.go` 的侧栏变化。
- #5 负责在自己的 Board 分支执行 `git merge --no-ff --no-edit 14bbaf0ec2f176c598560883cc895f4dcd24405d`，保留双方历史和已授权成果。协调者已确认启动主线变化应保留，因此验收为“指定基线能力 + 启动主线全部历史、截图、侧栏行为 + 必要兼容”，不声称整棵树与 `14bbaf0` 相同。
- #5 是这一轮启动主线兼容的唯一所有者；功能卡继续使用固定功能基线，独立 Review 后由协调者通过 Board merge 合入。以 #5 集成结果为后续主线；最终集成卡统一完成导航注册与共享接线。
- 不直接操作主工作区，不 reset/main/stash/gc/prune，不移动 `recovery/vaultwarden-96bc7ef`。附件 #3 的未提交内容属于其独立工作树，不读取或复制为本卡成果。

## 所有权

| 工作流 | 独占修改范围 | 交付与共享边界 |
| --- | --- | --- |
| 附件 #3 | `attachment*.go`（含协议包）；当次附件所需 `cipher_editor`、`organization_ui`、`authenticated` 接线 | 沿用独立卡权限、恢复与传输测试要求；其它卡不同时修改这些接线 |
| Send | 新增 `send*` 协议及独立原生 UI 文件 | 提供真实协议和可注入组件，统一 app 注册留给最终集成 |
| 账号 | 新增 `account*` 文件 | 独立账号业务组件及接口契约，不各自扩写公共 Session |
| 组织补齐 | 新增 `org_*` 文件 | 与既有组织模块协作，避免修改附件当次占有的组织接线 |
| 存储 | `storage*`、`session_storage*`，Swift 存储和 AutoFill | 保留认证快照、策略校验、持久化顺序及撤销边界；共享接口变更须协调 |
| 后续 MFA、设备通知、恢复、legacy | 各自依赖卡明确的独立模块 | 先满足依赖和接口约定，再独立实现、验证及审查 |
| 最终集成 | `main.go`、`ui.go`、`network.go`、公共 Session 接口、构建配置、总 README 与覆盖矩阵 | 等依赖全部审查合入后，统一导航、生命周期、注册、必要兼容与整体测试 |
| 本次 #5 | 基线合并、已有侧栏兼容、本文档 | 仅启动整合，不承接各业务模块，不宣称完整客户端完成 |

路径所有权是跨卡协作契约。若实际需求超出所属文件，先通过 supervisor 向协调者说明具体接口签名、调用方、权限及生命周期需求；由协调者指定共享改动的唯一所有者和先后顺序。不能为绕过所有权引入全局映射、隐藏注册表或平行 Session 实现。

## 接口协作

模块交付必须同时包含真实 Vaultwarden 协议、独立可测试的原生业务组件及定向验证，不能只有路由包装或占位页面。组件使用依赖注入对接网络、会话、存储、策略和 UI 生命周期，明确输入、输出、取消与错误语义；共享 app 文件不允许并行争写。

接口说明应包括账号和服务器作用域、认证回执及快照版本、请求取消与锁定/退出后的迟到响应、策略预检和组织隔离、持久化前后顺序、秘密清理责任，以及请求结果不明确时的恢复方式。不得从 UI 状态猜测权限、跳过快照认证，或用自动重试掩盖未知写入结果。接口的最终统一适配由最终集成卡完成。

客户端接入既有 Vaultwarden API，不重写服务端。保持 MyGo `v0.2.15`，保留 goja 和既有密码强度实现，不引入 SQLite。验收以可用客户端业务流程和安全边界为准，不用原始 API 路由数量替代客户端可用性。

## 集成门槛

1. 每张卡使用独立工作树、独立提交和隔离测试资源；保留已有提交，不触碰别人的运行实例、数据、进程和构建产物。
2. 提交前运行与修改相关的协议、原生组件及失败/取消/撤销回归，记录真实命令、结果和未覆盖范围。真实服务器验证只能使用自有隔离实例，并精确清理本卡资源。
3. 接口需求先协调；独立模块可测试后交付。统一导航和生命周期接线由最终集成在全部依赖合入后完成。
4. 必须干净提交后由另一 reviewer 对准确 HEAD 执行只读独立 Review。Review PASS 后，由协调者通过 Board merge 合入；本卡不手动合并 main。
5. 最终集成至少运行 Go build/test/vet、Swift 回归和各新增业务流程的定向测试；准确更新总 README 与覆盖矩阵，明确协议实现、UI 接入、真实实例验证和平台验证的区别。

## #5 冲突处理与验证记录

本轮共同祖先为 `2aa0d3b9f10f2a9ae41344393fbaf69ff676364d`，因此 Git 对原基线已有内容也报告了文本或 add/add 冲突。核对 `4b0a910..0b88875` 只有截图差异后，以下冲突恢复为 `14bbaf0` 已实现版本：

- `README.md`、`THIRD_PARTY_NOTICES.md`、`docs/secure-snapshots.md`、`docs/vaultwarden-readonly.md`。
- `internal/vaultwarden/client.go`、`login_challenge_test.go`、`session_state.go`、`session_state_test.go`、`types.go`。
- `macos/Bridge/SnapshotBridge.swift`、`macos/MyGoVaultwarden.xcodeproj/project.pbxproj`、`macos/Shared/SnapshotStore.swift`、`SnapshotTypes.swift`、`macos/Tests/SnapshotStoreTests.swift`。
- `network.go`、`session_storage.go`、`storage.go`、`unlock_test.go`。

`main.go` 保留全部基线状态和解锁/策略逻辑，同时保留 `sidebarCollapsed`。`ui.go` 保留基线业务入口和个人/组织过滤语义，加入折叠按钮、⌘B、64/236 宽度、系统标题栏避让、图标导航及 tooltip；组织、集合和文件夹也使用折叠导航。原全局 `navItem` 继续为编辑器提供带文本按钮，折叠状态只影响侧栏包装。`ui_icons.go` 保留启动主线图标。`ui_test.go` 保留侧栏回归，将旧只读断言适配为基线已支持的支付卡与个人范围，并增加折叠下组织/集合/文件夹导航、授权编辑、个人范围排除组织项目、锁定清理回归。

相对 `14bbaf0` 的最终差异仅为：`main.go`、`ui.go`、`ui_icons.go`、`ui_test.go`、两张原有截图及本文档。协议、安全存储、依赖及其余业务文件保持指定基线版本。

实际执行：

| 命令 | 结果 |
| --- | --- |
| `go test . -run 'Test(VaultSidebarToggle\|CollapsedSidebar)' -count=1` | 最终通过；首轮发现编辑器仍依赖全局 `navItem`，保留该入口并隔离侧栏包装后复验通过 |
| `go build ./...` | 通过，Go 1.27.1 darwin/arm64 |
| `go vet ./...` | 通过 |
| `go test ./... -count=1` | 全部包通过；未配置真实实例的条件测试不等于真实服务器验证 |
| `swift test --package-path macos --scratch-path "$TMPDIR/swift-card5"` | 独立临时构建目录，63 项 XCTest 全通过 |

本次没有执行签名安装、真实 Keychain/Touch ID、Safari AutoFill 或新建真实 Vaultwarden 实例端到端测试。Swift 模拟存储和原生命名剪贴板测试不能替代这些平台验收。附件、Send、账号、组织补齐、存储迁移及后续模块仍属于其它卡；本卡只交付可审查的共同基线。

## #5 主线推进后的冲突修复

候选 `a9551a3` 的旧 Review 通过后，Board merge 因主线推进发生冲突并自动中止；该候选没有合入主线。本次从干净的 `a9551a3` 工作树合入已提交的 `9fee5bd420a76d0cf6ab678cb4a13f5de0221e51`，保留它包含的 `aa632e2` 标题栏侧栏布局和行对齐测试。没有读取或复制主工作区未提交内容，也没有操作主分支。

唯一文本冲突位于 `ui.go` 的 `sidebarContent`：采用主线的无 `TitleBar` 参数签名，保留基线的 `a.navItem` 包装及折叠时隐藏 section label 的逻辑。主线的 `titleBarButton`、`sidebarToggle`、展开顶栏按钮、折叠交通灯避让、标题栏背景连续、header padding 原样保留；基线的组织、集合、文件夹导航及授权编辑/撤销边界保留。`ui_test.go` 自动合并后，额外断言展开/折叠按钮位于标题栏高度内，且展开按钮位于侧栏范围内并避开交通灯。主线新增的行对齐测试完整保留。

本次执行并通过 `go test . -run 'Test(VaultSidebarToggle|CollapsedSidebar.*|DumpAlignment)$' -count=1`、`go build ./...`、`go vet ./...`、`go test ./... -count=1` 和 `git diff --check`。此轮只涉及 UI、UI 测试与本文档，不重复 Swift 全套；上面的 63 项 Swift 结果属于原候选验证记录。本次没有真实窗口交互或平台端到端验证。协议、存储、依赖和其它业务文件仍保持 `14bbaf0` 内容，两截图及原基线历史保留。新提交必须重新独立 Review，不能复用旧候选的 PASS。
