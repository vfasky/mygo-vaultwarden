# 最终集成 #14 工作记录

**当前范围变更：用户要求组织产品UI延期。** 下文为按时间追加的历史检查点，不应把旧状态当作当前未完成清单。组织模块/主controller成果保留但本版撤下入口；个人版本当前范围与验证以 [本版验收矩阵](../personal-release-acceptance.md) 为准。加密组织数据、政策/pending/隔离、权限及全资源轮换约束继续保留。

本卡从 `69047c2` 启动，只修改独立 Board 工作树。当前为开发中检查点，**不是最终候选，不表示完整客户端已完成或已合并**。最终需包含后续已审查的 #38/#39/#40 接口并重新验收。

本轮主 controller 已接：统一 UI epoch 推进及原子 worker 时钟；短锁 scope/revision/snapshot lease；Session 锁内只保存/校验 checkpoint，UI dispatch 后才采用；退出撤销网络、组件与通知。主登录改用 LoginMFA，主密码直到认证后 policy 检查完成才清除；普通 MFA/provider8 的账号级警告、生产 Duo/WebAuthn 桥及 SSO→UnlockSSOVault 使用同一认证同步流程。账号注册/资料/敏感变更 Begin/Result、Send、设备审批、MFA 管理和通知有主窗口接线。入口位于原生“账号与设置”的账号服务区，以保留用户现有侧栏布局与截图对应行为。

检查点新增运行期 authority：只从实际设备 Session 完整 Sync 的私有摘要铸造，一次消费；独立 runtime revision 从不作为 Swift 持久 revision 使用。Sync/Close/授权变更/令牌期限撤销旧能力，临时会话不刷新 token。可继承同账号的真实本地 pending/org 隔离；再次验证主密码不隐式安装密码包装。普通读取/编辑/附件/备份/秘密展示的 controller 已增加按 epoch 捕获的存储后端路由。生产设备发起端、原生 runtime secret ABI、跨账号 target 阻断检查仍在接线中，当前不能宣称运行期主库已完整可用。

本轮实际执行通过：

- `go test -tags headless ./... -count=1 -timeout=120s`（resolve-go.sh 的 Go 1.27.1）；
- `go vet -tags headless ./...`（在运行期权限后续改动之前的一轮，最终须重跑）；
- `go test -race -tags headless . -run 'TestController|TestResourceController|TestLogin' -count=1 -timeout=120s`；
- `go test -race -tags headless ./internal/vaultwarden -run '^TestRuntime' -count=1 -timeout=120s`。

新增测试验证后台 lease 在 storage 调用期间撤销、并发检查/lock、真实主视图 Send 页面及迟到结果清理、MFA 提交确认/原账号警告/迟到 prompt；运行期测试使用真实 DeviceLogin grant+sync HTTP fixture，验证伪造/重放拒绝、secret callback不借磁盘key、不绑定密码的reprompt、到期零refresh和type15 pending。它们不是 Keychain/原生窗口/真实服务端集成验收。

实际出现并已修复的测试失败：LoginMFA remembered/RememberToken是string而非slice；新lease测试夹具缺snapshot ID/device ID最短长度；新增侧栏行挤压既有导航，已把新增服务入口放入设置；新增登录链接挤出700px窗口返回按钮，已收拢为同一操作行。没有将这些首轮失败记为通过。

协调者追加业务卡：#38 目标恢复持久化与独立 Swift runtime secret；#39 cipher/folder轮换转换/核验；#40 Send轮换转换/核验。最终必须消费已独立审查合入的接口。账号恢复不得用任意 bool/HTTP200清屏障。

固定源已核验：1.37.4 `/api/version` 是实际 Vaultwarden VERSION；`/api/config.version=2026.6.0` 是兼容版本。轮换端点按 folder→EA→组织recovery→Send→cipher 逐项 await? 后，最后保存 account private-key/master-user-key 包装。grantor不能独立读回EA wrapper，普通组织成员不能读自己的reset-password-details；协调者批准在精确版本/commit、已核验生成与收件人身份、唯一最终双包装见证及全部可读资源核验均满足时使用明确的 protocol-ordered commit evidence。尚未实现或执行该完整证据链，不把它写成独立读回核验。

真实 Keychain/Touch ID、签名安装、系统AutoFill、IdP/Duo/AASA、完整1.37.4主入口回环、Swift/双架构最终构建、CLI与大库RSS/许可证检查仍待本卡最终轮次，不借用历史模块证据替代。

## 后续开发检查点：追加适配已合入与本轮新增证据

已在本卡树合入独立审查后的 #38/#39/#40，主线至少 `bb6a40a`。本节仍不是最终候选声明。

- 运行期设备发起端已接主登录/锁定页。provisional能力只从实际设备 grant→Sync创建；认证本机同scope保护投影、独立原生只读 `targetRecoveryRuntimePending` 查询和来源CAS均通过后才安装。原runtime Pending按单operation过滤，不能用于bootstrap；新增只读操作返回scope为actor或target的完整认证记录，不接写binding/summary/resolution。未决/verified目标记录阻断；resolved/其它target不误阻断。resolved保护投影在无同scope当前认证缓存时合并，当前缓存中的正式策略解除可更新历史投影，避免丢保护或无条件复活旧限制。
- 主controller实际临时库→metadata导入→两文件各上传、正式Sync续接、下载核验，以及主界面secret/history/复制、再次验证不隐式保存主密码、来源失效拒绝、退出保留原磁盘缓存、BindPassword→新Sync→真实持久后端采用与发布失败，新增 `TestRuntimeController*` / `TestRuntimeTarget*` headless race通过。使用真实Go Session/HTTP fixture和排队dispatcher，磁盘与native fake用于隔离，不称为真实Keychain。
- 已消费真实 `mygo_runtime_secret_execute` ABI，独立授权代号单调增长，绑定scope、短期限与用途。Go在新授权前清旧显示；没有nil key调用磁盘copySecret。新增隔离实际C ABI `TestNativeRuntimeBootstrapForeignTargetCannotBeMissed` 通过，证明无旧actor unlock的foreign-target记录不能遗漏，查询不改持久状态。
- foreign BindPassword采用新的系统认证原子切换入口，普通publish仍拒wrongScope。新state format=3使旧reader拒绝；旧账户原AES密文和原Keychain key在确认前保留，切换记录用独立域分隔的既有元数据AES密钥加密，不形成旧vault非认证解锁后门。未决#17、target阻断、旧pending/组织隔离先拒绝；旧保护不合给新scope。96MiB状态/64MiB恢复记录界限未放宽，双副本超限明确失败。write-ahead可能推进revision；不宣称所有error都使整个文件字节不变。rename/fsync或回执未知只认证查询同op，新状态不自动回滚、不删除可能活跃的新key。显式确认后才退休旧key；主界面有未知切换检查/确认入口。
- `AccountSwitchTests` 5项与 `TargetRecoveryTests` 10项实际通过，含认证取消、CAS、旧保护拒绝、写前失败、rename后注入未知、确认回执未知、重复确认、加密恢复篡改和旧key退休。测试使用MemoryKeys，不访问用户钥匙串。隔离Swift真实动态库 `TestNativeBoundAccountSwitchConfirmedAndUnknownReceipts` 的正常/丢回执分支通过；尚待最终双架构/平台轮次。
- 已将完整cipher/folder、Send、EA/组织恢复转换器组成 `PrepareVerifiedAccountRotation`，加密journal记录版本/commit、实际请求摘要、原收件人身份与独立可信SPKI。`SyncVerifiedAccountRecovery` 自己执行新Session完整Sync，核验实际key、唯一最终双包装和RSA关系、每类可读资源及重读收件人身份/公钥，输出明确的read-back与protocol-ordered证据。核验中refresh只走专用checkpoint，最终返回最新savedSession，不发布过期refresh材料。
- `MYGO_VERIFIED_ROTATION_TEST=1 ... -run '^TestLiveVerifiedRotationEvidence$' -race` 自有固定1.37.4回环通过：非空个人cipher/folder、文本和文件Send、EA、普通成员组织恢复。正常与丢最终响应两例完整见证通过；EA/recovery/cipher阶段真实故障均无最终见证、不可解除。每例恰好一个rotation POST。fixture另以自有grantee/admin独立核对隐藏wrapper；生产没有要求其它用户发起紧急访问。容器 `88b4c900...72f48` 精确label清理，后续ps/docker核对无残留。
- 经协调者批准，认证journal的 `not-dispatched` 独立分支使用精确未进入敏感transport证据+全新认证原key+完整当前资源核验，允许其它客户端合法增改删，明确标为外部当前变化；不恢复OldSession，不把hidden wrapper称为读回核验。prepared/缺Result/HTTP失败/unknown/空phase不可借此放行。新增自有1.37.4 `... -run '^TestLiveVerifiedRotationEvidence$/not-dispatched' -race` 通过，rotation POST=0，原Session关闭后新登录增改删仍可核验，prepared/unknown/空phase拒绝。容器 `59fd8af3...3c70` 已由fixture精确清理。

## 组织业务主controller检查点

设置页已接组织业务：批量状态、复制/完整资源、集合分配、MyGo/官方JSON/资源导入导出、组织/成员/条目事件、API key和Public目录导入。组件worker计数与锁定/导航取消接主生命周期；组织隔离回执在UI dispatcher采用，不在Session回调中重入。完整资源显式正常Sync后只由认证发布回执推进原continuation，提供重新打开文件仅继续附件恢复；host前置拒绝不伪装为已提交，未知提交不自动重放。

新增 `TestOrgControllerRoutesRealComponentsAndCancelsStaleWorker` 与 `TestOrgControllerResourceContinuationAdoptsOnlyNormalPublication`，使用实际Session/HTTP fixture与排队dispatcher，定向race通过：入口连接、worker取消/计数、正常认证续接、发布失败不采用、Sync零mutation重放。仍不是实服务器组织全流程或真实Keychain证明。

## 目标恢复核验基础检查点（主流程尚未接完）

获协调者批准的最小#12/#38接缝：`RecoveryDispatch.Verification`以值类型保存Prepare真实目标userKey和最终wrapper摘要、实际请求位与固定效果矩阵；不保存密码/OTP/masterPasswordAuthenticationHash。准备与提交前重新确认固定1.37.4兼容声明，Summary值复制不暴露可变指针。新Swift严格解析与Go严格解码；旧记录可查但无预期不能自动核验或借旧verified自动发布。

`InspectFreshTargetRecovery`仅接受五分钟内无remembered授权的全新LoginMFA Session，自己读取完整Sync、本人accounts/keys和MFA清单，检查当前个人cipher/folder/Send密码学与组织身份/策略/key链。完整fresh材料摘要包含Credentials、password配置、session、vault与unlock；普通采用、过期或改动均失效。二进制文件及服务端隐藏remember-device凭据没有独立读回声明。

原生加密record新增版本化`originalResult`，只在真实Result首次阶段记录，不从verified/resolved倒推、不能unknown升级confirmed。discovery、可见效果、真实nondispatch和confirmed管理员Email回退具有不同证据kind并由native再次核对来源：unknown/旧Email不走回退例外；takeover无例外；nondispatch只解除本机预隔离，不声称远端已执行。当前管理员组织成员授权丢失会追加隔离，专用Resolve仍合并旧保护。

`TestTargetRecovery*`、`TestRecoveryExpectationSchemaAndValueCopies`及管理员恢复定向race通过；Swift `TargetRecoveryTests` 13项通过，包括来源跨verify/resolve/重开保留、未知来源不可升级、证据用途不能互换、旧/缺失/非法预期拒绝。均为隔离fixture，当前增补之后的真实C ABI和1.37.4邮件/策略回环仍待最终恢复主controller验证，不借以前动态库测试充数。

仍待完成：紧急/管理员恢复与#38目标验证主流程、完整最终导航/矩阵、最终Go/Swift/Xcode/实际bridge/CLI/许可证/大库评估。尚无实际签名安装、Keychain、系统剪贴板、AutoFill、SSO/Duo/WebAuthn系统窗口实测声明。
