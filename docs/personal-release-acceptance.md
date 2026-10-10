# 本版个人密码库候选：范围与验收

本文件为 Board #14 当前范围的验收入口。组织产品 UI 按用户最新要求延期；下面的“通过”仅指已执行的检查，不代表已独立 Review、合并、签名安装或生产系统验证。历史开发记录见 `docs/parallel/final-integration.md`。

## 审计修复期间的证据适用范围

下方 Board #44 与候选验证是对应候选提交的历史执行记录，不自动覆盖后续审计修复。新增自动化入口、live 许可和 skip 语义见 [CI 与验证边界](ci.md)。审计修复必须在最终集成提交重新验收；单个组件的测试、跳过的 live 任务或新增 CI 配置都不能继承为全量通过。

## 审计串行迁移后的本地验证

本节对应 `audit-fixes/20261010-current` 中以 `0803daf` 为输入的串行迁移，累计差异基线为最新用户快照 `f407d305`。它不重跑七个组件任务，不继承历史 live 或签名测试的通过结论。最终提交号见本阶段交接；本节只记录这次实际执行及尚缺条件。

| 检查 | 本阶段结果与条件 |
|---|---|
| Go headless 全仓、race、vet | 均通过；Go 1.27.1。重新编译隔离 MemoryKeys Swift harness，`SNAPSHOT_TEST_HARNESS=… go test -tags headless ./...` 和 `go test -race -tags headless ./...` 均通过，无 `-skip`；live 测试仍按 opt-in 跳过 |
| Swift | `swift test --package-path macos` 104 项、`macos/Authentication` 9 项通过 |
| 协议与测试依赖 | `go run ./tools/storage-operations -check`、`bash scripts/ci-check-fixtures.sh` 通过；生产目标不依赖测试 fixture |
| C2/C3/C4 回归 | wire 字符串不变；业务生产 Go 无 >300 字符行，catalog/夹具数据保留。新增双语言错误身份、备份附件可操作提示、设备提示、轮换提示、未知包装不泄漏和本地文件扩展名回归通过 |
| staticcheck | PATH 中未安装，未执行、未自动安装；不能以 vet 通过替代它 |
| A1 spool | 全仓包含立即 unlink 和子进程退出回归；不能证明断电、SSD 擦除或同用户 fd 访问隔离 |
| A2 文件权限 | 保留用户选择文件/目录、最终 O_NOFOLLOW、固定目录 fd、不覆盖发布回归；本阶段未执行签名沙盒 NSOpenPanel/NSSavePanel 端到端探针，也未宣称跨重启 bookmark |
| A3/A4 KDF | 弱在线 PBKDF2 拒绝及 Argon2id 上界测试通过；表单显示 16–1024 MiB；未实际进行 1 GiB 派生 |
| A5 内存 | 测试只覆盖可控缓冲区及生命周期；Go/Swift 隐式副本、交换区、休眠与崩溃转储仍在保证范围外 |
| A6 空闲锁定 | 注入时钟/活动源、后台不续期回归通过；未实机等待 15 分钟或验证睡眠、锁屏，其他应用的键鼠活动会续期，UI 阻塞可能推迟锁定 |
| C1 结构 | 部分完成；真实领域提取及 app 68 字段/163 方法、Session 25 字段/246 方法的残余拆分清单见 [架构](architecture.md#c1-本轮接缝与后续演进) |
| 未执行 | Linux runtime、live Docker/真实服务器、GitHub hosted CI、Touch ID/Safari/签名安装；独立 reviewer 由父任务安排，当前没有自签 PASS |

## 独立审查后的第一轮整改

审查基准 `4cef772` 的两项阻塞均有源码依据。本轮保持原功能范围：

- A4：修复 Swift `PasswordUnlockKDF.valid` 仍为16–256的遗漏，与Go同步至16–1024。MemoryKeys真实 publish、password unlock 和 accountRecoveryResolve 覆盖15/16/256/257/1024/1025：合法参数可发布和完成恢复，越界拒绝且保留原恢复屏障/密钥。使用合成包装密钥，未执行1GiB派生。
- C1：按确认的三个接缝落实组织 host、拥有完整异步导入生命周期的备份控制器、个人备份导出窄接口服务；新增无需完整app/Session的fake回归。仍有其他编辑、组织与恢复编排留在app/Session，不宣称全部解耦；具体边界及薄适配器见架构文档。
- 实际重跑受影响检查：Swift主包 **105项通过**；重新构建MemoryKeys harness后，app/vaultwarden/localstore普通测试、race和vet均通过；fixture生产依赖与diff检查通过。Authentication、未受影响的Go包、live、签名GUI、Linux及hosted CI未在本轮重跑。独立复审仍待父任务安排。

## 本轮重新执行记录（Board #44）

- 本卡是用户明确要求的 #14 打回后重新执行。固定来源为候选 `63756e4a533253258385eb2d908519377f4b7d28`，已在本卡独立分支以 `--no-ff` 合入（不 reset、不拷旧树文件），未修改主工作区或 recovery 分支。
- 旧 #14 原生 run `cb8b2ed1-c0ad-4c9d-bd49-bf78a9665277` 的 process-terminal 一直 pending，reconcile/CreateReview/Reject 均被框架拒绝；本记录不把它视为已退出或已审查。旧工作树、分支与状态文件按要求原样保留作现场，未清理。
- 本轮实际执行（本卡树）：Go 1.27.1 `go test`/`go vet`/`go build -tags headless`、gofmt 干净；隔离 Swift C ABI 下 `go test -race -tags headless ./...` 全包通过；Swift 主包 99 项、Authentication 9 项通过；无签名 Debug 主App（`MyGo Vaultwarden`）与 AutoFill.appex 及生产桥 `libSnapshotBridge.dylib` 均为 x86_64+arm64，`nm` 确认三个公开 C 符号；`REGISTER_APP_WITH_LAUNCH_SERVICES=NO`，未执行 lsregister 登记。
- 本轮实际执行的固定 1.37.4 live 回环（自有容器，结束后按 label 核对无残留）：`TestLivePersonalRelease`、`TestLiveVaultFinishing`（个人范围）、`TestDeviceLoginLive1374`、`TestDeviceNotificationLive1374`、`TestSendLive1374`、`TestLiveRecoveryLifecycle`、附件相关 live 与单元测试，均通过（race）。
- 未在本轮重跑：大库 10,000 条基准、许可证收集、账号完整轮换 live 与其它组织历史 live（组织产品不在本版门槛），沿用前序检查点证据，已在下文标注为继承。
- 无代码修复：重新验证中未发现需要修改产品代码的真实问题。

## 本版范围

| 范围 | 当前实现与证据 |
|---|---|
| 个人八类型、保存/编辑/复制、文件夹、搜索、同步与锁定 | 原生主入口；完整 Go 测试及 race、个人1.37.4回环覆盖 PBKDF2/Argon2id/TOTP、字段/历史/URI、逐字段冲突、状态和批量流程 |
| 个人备份、附件、完整资源续接 | MyGo/官方 JSON 区分；实际主controller的多文件上传→认证Sync→下载核验；固定1.37.4个人完整资源回环通过，未知结果不自动重放 |
| 认证、临时在线库和持久保存 | LoginMFA、SSO解包、设备发起/审批；实际临时CRUD/秘密/附件测试；BindPassword→新Sync→持久发布；foreign账号原子切换及未知回执检查 |
| 账号安全、MFA、Send、通知 | 设置页入口及已合模块；账户变更使用持久恢复日志，provider8警告绑定原账号；最终服务回环结果见下方 |
| 紧急访问 | 设置页独立入口；联系人生命周期、受控只读查看与接管；BeforeDispatch先落盘，迟到结果仅更新原操作日志；真实C ABI主controller确认/取消回归 |
| 目标恢复安全路径 | 本人fresh LoginMFA→真实Sync/keys/MFA读取→逐项核验→专用Resolve；多操作全部匹配才发布；foreign账号需明确同意原子切换；旧记录/未知效果保留屏障 |
| 持久 AutoFill | 共享 Swift 策略/URI/快照验证、扩展构建和隔离桥测试；临时运行期不注册AutoFill；真实签名启用和Safari验证尚未执行 |

## 延期到下一版本

组织/成员/群组/集合管理、策略编辑、组织共享/复制/导入导出/审计/API key/Public目录，以及管理员账号恢复动作的主UI均不开放，没有占位按钮。已经实现的模块和检查点 `bc8b7ea` 保留供下一版本继续，不以它们尚未完成的产品回环卡住本版。

`release_scope.go` 集中控制本版组织UI范围；范围回归验证导航/共享入口不可达，个人列表不混入组织条目，同时原始加密sync与组织元数据仍保留。已有政策、pending和隔离、当前账户权限、全资源key轮换约束继续生效。无法证明的组织恢复资源仍会阻止相关个人敏感变更，不能删资源、传空adapter或假造true。已存在的跨账号安全屏障可以通过本人核验处理，这不是管理员动作入口。

## 已执行的候选验证

- Go 1.27.1 `go test -tags headless ./...`、`go vet -tags headless ./...`、正常Darwin `go build` 通过。
- `SNAPSHOT_TEST_HARNESS=… go test -race -tags headless ./...` 通过。使用重新编译的真实Swift C ABI，底层为隔离目录/MemoryKeys，没有读取用户App Group或Keychain。
- Swift主包99项、Authentication包9项通过。
- Xcode Debug、`CODE_SIGNING_ALLOWED=NO`、`ARCHS='arm64 x86_64'` 的主App与AutoFill构建通过；`lipo -info`实际确认App、SnapshotBridge、AutoFill均包含arm64和x86_64。
- 固定Vaultwarden镜像：`sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`，容器报告1.37.4 / `7c188967e7a467b19b2757bc3326f9cf3ccae327`。
- `TestLivePersonalRelease` 在自有loopback/SMTP fixture下通过：PBKDF2、Argon2id、TOTP以及个人编辑/复制/比较/备份等。官方CLI **2026.5.0** 实际导入/解密七种兼容类型，导出结果被MyGo解析并回导。CLI独立appdata与会话环境，不输出token。
- `TestLiveVaultFinishing` 使用 `MYGO_PERSONAL_RELEASE_ONLY=1` 通过个人完整资源备份、解析、分阶段复制与实际二进制核验；组织产品段未作为本版门槛运行。
- 真实附件回环通过0字节及8,388,611字节文件；现有测试顺带执行了组织权限负例，不代表组织主UI交付。
- 当前账号轮换与nondispatch固定1.37.4证据已在前序检查点执行，详见开发记录；全量单元/race覆盖其当前代码。它不是隐藏恢复wrapper的独立生产读回证明。
- 许可证收集脚本成功，保留GPL、MyGo v0.2.15、goja、zxcvbn及实际链接模块的声明；未升级这些依赖。

- 固定1.37.4的 `TestDeviceLoginLive1374`、`TestDeviceNotificationLive1374`、`TestSendLive1374` 全部通过（race）：设备批准/绑定、认证和匿名MessagePack通知、文本/文件Send与受控发布。
- `TestLiveRecoveryLifecycle` 使用个人版本范围开关通过（race）：自有SMTP邀请/重发、过期token与错误身份拒绝、可信公钥确认、等待期拒绝、请求/批准/拒绝、只读查看、接管和userKey保留；关闭功能时历史授权仍在且轮换探针阻止误判空清单，恢复开关后历史再次可见。使用人工批准，不声称自然等待天数已实测；管理员流程未作为本版门槛执行。
- 新主入口的隔离真实C ABI回归验证目标fresh登录、同账号发布、foreign明确同意后原子切换、多操作屏障、nondispatch、部分结果拒绝与晚回执不重开UI；紧急邀请验证敏感HTTP之前确有同op持久记录，取消后的未知结果仍记回原actor，无重放。
- 各owned fixture按容器ID与所有权label清理；最后 `docker ps -a --filter label=mygo.fixture` 无残留。没有清理其它用户容器。

## 大库测量与边界

`BenchmarkPersonalVault10000` 在Apple M5、darwin/arm64、Go 1.27.1上处理10,000条实际加密个人Login。单次认证快照接受＋个人metadata解密：**342.61 ms**；原始vault **10,780,198 bytes**；约 **31.46 MB/s**；累计分配 **397,604,408 bytes / 3,177,868 allocations**。

独立测试进程 `/usr/bin/time -l` 最大RSS **129,990,656 bytes（约124 MiB）**，包含夹具加密构造和Go运行时；不是单次操作净内存，也不是真实窗口滚动帧率。此测量没有覆盖1GiB资源包、十万条目或所有组织场景；保留既有资源/状态大小限制，不据此放宽。

## 平台限制

本轮没有启动或替换用户正在运行的app/watch，没有访问真实密码库/Keychain。unsigned双架构构建、MemoryKeys和真实C ABI证明编译与调用契约，不能替代实际Touch ID、签名安装、系统剪贴板、AutoFill/Safari、IdP/Duo/WebAuthn/AASA系统窗口测试。最终交接必须保留这些未验证项。

工作证据暂存于本卡scratch `/tmp/pi/01a11893-e965-715b-aff9-308f5e8ffd0b`，包括 `final-go-tests.log`、`final-go-vet.log`、`final-go-build.log`、`final-race-all.log`、`final-swift-all.log`、`final-auth-swift.log`、`final-xcode.log`、`final-personal-live.log`、`final-personal-resources.log`、`final-large-vault.log`。日志属于运行工件，不能作为永久仓库文件依赖。
