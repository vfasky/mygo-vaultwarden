# Board #12：紧急访问与管理员账号恢复

本卡是独立客户端模块和原生业务组件，等待独立 Review。**尚未接入主窗口导航、真实持久屏障、Keychain 或 AutoFill，不等于已完成整机产品。** 当前工作树以 main `4ee0023` 为基础，没有回退、没有子代理、没有修改主工作区。

## 固定协议与来源

- Vaultwarden **1.37.4**，commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`；核对本地固定源码 `src/api/core/emergency_access.rs`、`organizations.rs`、`accounts.rs`、`db/models/emergency_access.rs` 及 `error.rs`。
- Bitwarden clients commit **5983f56ce0cf924eea56c7d8f066f7885825a7ce**，已实际下载并读取 [emergency-access.service.ts](https://raw.githubusercontent.com/bitwarden/clients/5983f56ce0cf924eea56c7d8f066f7885825a7ce/apps/web/src/app/auth/emergency-access/services/emergency-access.service.ts)；核对 confirm/view/takeover 及 rotation trustedPublicKeys，确认 user key 的 RSA 包装和等待状态。官方客户端最新盐字段在固定 VW 响应中不存在，当前保留 VW 的规范化 email 盐和原 KDF。
- [organization-user-reset-password.request.ts](https://raw.githubusercontent.com/bitwarden/clients/5983f56ce0cf924eea56c7d8f066f7885825a7ce/libs/admin-console/src/common/organization-user/models/requests/organization-user-reset-password.request.ts) 的 `newMasterPasswordHash`、`key`、`resetMasterPassword`、`resetTwoFactor` 对照固定 VW `recover-account` DTO；路由事实来自 VW `organizations.rs:2790`，不把搜索结果未找到的官方 API 字符串当作已验证。
- 已读 `docs/parallel/accounts.md`、`organizations.md`，邀请文档实际路径为 `docs/organization-invitation-recovery.md`（parallel 下没有同名文件）。

| 客户端入口 | 固定服务端路由 / 行为 |
|---|---|
| `Session.EmergencyContacts` | GET `/api/emergency-access/trusted`（本人授予）与 `/granted`（授予本人）。验证完整列表、分页、重复、ID、状态、type、对象种类。关闭功能时服务端返回空数组，普通列表空不能作为轮换完整性证明。 |
| `PrepareEmergencyOperation` | invite/reinvite/accept/confirm/initiate/approve/reject；POST 官方路由，update 使用 PUT `/{id}`，delete 使用 DELETE `/{id}`。accept token 只在 JSON body，不解析 JWT 授权；服务器负责签名、收件人、过期与 ID。 |
| `WithEmergencyView` | POST `/{id}/view`。只有 granted、type=0、status=4。当前账户 RSA 私钥解开目标 user key，只读解密个人条目；不读他人 sync，不安装他人会话，不接 AutoFill。借用回调结束后清理 key/buffer。 |
| `PrepareEmergencyTakeover` | POST `/{id}/takeover` + GET `/{id}/policies`，再准备 POST `/{id}/password`。保持目标原 KDF 与 user key，用目标邮箱盐生成新认证 hash 和 type2 wrapper。最终会删除目标全部 MFA 及非 owner 组织成员关系。 |
| `PrepareRecoveryEnrollment` | PUT `/api/organizations/{org}/users/{GLOBAL userID}/reset-password-enrollment`。当前已确认成员；从自身认证 fresh sync 核对身份、wrapped key、登记状态及 type8。登记复用 `AccountSensitiveInput` 当前密码或 protected-action 邮件 OTP；退出发送 null，自动登记策略禁止退出。 |
| `PrepareAdministratorRecovery` | GET `/api/organizations/{org}/users/{MEMBERSHIP ID}/reset-password-details`，最终 PUT 同前缀 `/recover-account`。通过真实成员目录核对 actor role/confirmed 与目标 ID/email/state；服务器再检查恢复策略/角色。组织64B key → 组织 RSA 私钥 → 目标64B user key → 新密码 wrapper。私钥与独立可信 SPKI 必须匹配。支持密码、MFA 或二者。 |

状态数值固定为 invited=0、accepted=1、confirmed=2、recoveryInitiated=3、recoveryApproved=4；类型 view=0、takeover=1。UI 展示中文状态，等待天数限制为本客户端 0–365 天。**没有本地计时放行**；等待结束由服务器任务推进到4，或 grantor 显式批准。服务端没有多读取到提交的 CAS，重新核对不是事务保证。

用户密码策略复用 `AccountPasswordPolicy.Check`；新密码至少12 UTF-16单元。管理员可读取当前组织 type1，无法读取其他组织/对方完整 MFA 或隐藏角色状态；最终服务器校验，不读取他人 sync、不从未经验证 JWT 猜权限。紧急 policies 在 VW 返回目标全部 confirmed 组织政策，客户端保守检查返回的 type1，不假定与官方 Bitwarden 注释中“只有 owner 政策”完全相同。

## 确认、派发、未知结果与目标失效合同

所有写入都必须先 prepare，返回字段私有的 `RecoveryPlan`；绑定具体 Session、scope、revision、authorization epoch。确认展示采用 `plan.Summary()` 的服务器核验目标/联系人/type/等待天数及 `Impact()`，不能只显示旧列表行。`ConfirmationText()` 是具体操作种类；提交后计划单次消费，`Close()` 取消并清理请求材料。prepare/commit 都使用现有 Session operation cancellation、refresh/checkpoint 与 guard。

```go
func (*Session) CommitRecoveryOperation(
    ctx context.Context, plan *RecoveryPlan, confirmation string,
    persist func(SessionCheckpoint) error,
    before RecoveryBeforeDispatch,
) (RecoveryOperationResult, error)

type RecoveryBeforeDispatch func(RecoveryDispatch) error
```

`RecoveryDispatch` 包含随机128bit `OperationID`、`Actor` 与 `Target`（独立 Scope）、`Kind`、`ResourceID`、`OrganizationID`、`MembershipID`、`PreviousRevision`、`AuthorizationEpoch`、`ConfirmedImpact`、`TargetEmail`、联系人 ID/email、紧急类型/等待天数、`RequireTargetLogin`。没有主密码、OTP、恢复密钥、目标旧 token 或伪造旧 Session。

`before` 在敏感网络派发前执行，持有 Session 锁，**不得重入 Session 公共方法**。集成必须同步完成以下工作后返回 nil：

1. 核对当前 actor scope、revision、UI epoch 与已确认计划；按 operationId 保存本次操作状态，防止 UI 重建后盲重试。
2. 若 `RequireTargetLogin=true`，识别目标是否存在本机授权。撤销实际目标旧会话/offline/AutoFill 能力，并持久记录需重新登录/核验的状态。不能撤错管理员自己的个人库。
3. 若目标就是本机当前已解锁账号，可使用 #17 的本账号屏障；若目标是另外存储的账号，不能把 actor 的 oldUnlock/oldSession 填入目标 journal。缺少目标失效能力时必须返回错误，零敏感 HTTP。没有本机目标时记录这一事实，不能声称目标 journal 已落盘。
4. 回调结果本身不确定时必须 query 同一 operationId。计划在调用回调前即消费；`IsolationAttempted=true, Dispatched=false` 仍要求检查持久状态，不能自动新建计划重放。

`RecoveryOperationResult` 带同一描述及 `IsolationAttempted/Dispatched/Confirmed/Unknown`。所有 HTTP 失败、断线、派发后取消都按可能部分执行；不返回未经确认的成功，也不自动重发。成功或未知的目标密码/MFA恢复都需宿主继续保持目标屏障。只有目标新登录、完整 sync、密钥/成员关系/MFA核验与安全发布完成后，才走存储自己的 clear 契约。管理员自身 Session 不被当成目标清除；若合法操作目标就是 actor，模块在派发后调用已有 `accountInvalidateLocked`。

**新增 callback 是模块边界，不是已经实现的跨账号持久化。** 本卡不伪造 `AccountRecovery`：管理员并没有目标 oldSession/oldUnlock。主窗口 #14 和存储 #17 必须接上真实实现；未接上则不能启用恢复提交按钮。

## 用户密钥轮换 adapter

`RewrapRecoveryRotation(ctx, AccountRotationInput, RecoveryRotationTrust)` 返回 `AccountRotationConversion` 的 **Emergency/Recovery/Coverage/Revalidate 部分**。最终 adapter 仍需组合 #6/#13 的 cipher/folder/Send 转换，不能覆盖或丢弃这些 Data。信任输入按具体 global userID/orgID 映射到独立核验的完整 SPKI，不把即时网络 public-key 回包自动作为可信输入。

- 实际枚举 trusted 清单；重包所有 status≥2（包括正在等待/已批准）的授权。核对 ID→grantee、状态、重复、分页和已知字段，核对用户公钥端点返回 userId 与可信公钥；RSA-OAEP-SHA256 type3 包装新的64B user key。
- 从账号层提供的认证 fresh sync 读取 `resetPasswordEnrolled`、成员/组织/账号身份；已登记组织必须 confirmed/enabled、公钥已独立信任，再重包新 user key。账号层 commit 前再次逐字义比较 fresh profile，包含登记与成员身份；本 helper 再读公钥和紧急清单/开关，变化拒绝。
- 空数组只有真实枚举后才输出非 nil 空集合。未知分页、未知紧急字段、损坏/不同公钥或无法证明启用均失败关闭。
- **协调者已明确批准的唯一范围外修改**：`internal/vaultwarden/account_rotation.go` 的受限 GET Read 回调新增3行固定探针分类。没有扩展 URL 前缀/HTTP方法。保留原 mutex/refresh/checkpoint；adapter 不重入 Session。
- 探针：GET `/api/emergency-access/00000000-0000-0000-0000-000000000000`。固定源码在查记录前检查功能开关。仅 HTTP400 且顶层 `message` 与 `errorModel.message` 都精确等于 `Emergency access not valid.` 时返回内部启用哨兵。disabled 的 `Emergency access is not enabled.`、普通400/401、未知 JSON、代理错误均拒绝；意外200（保留 UUID 碰撞）也安全拒绝，不读取或采用该条目。
- `accounts.rs validate_keydata` 还会在写 folder/EA/其他资源前从数据库查询全部已确认 EA，检查是否遗漏；这是真实写前兜底，不是跳过本地枚举的理由，也不是整体事务保证。测试故意遗漏时收到拒绝，本地仍返回 Unknown 并要求核验。开关和列表之间仍有并发窗口。

## 原生组件与 #14 接线

- `newEmergencyPanel(contacts, trusted, prepare, commit, dispatch)`：邀请、重发、token接受、可信确认、等待/type选择、initiate/approve/reject/update/delete/takeover。两种列表分别传入来自 `EmergencyContacts` 的数据，组件明确显示授予方向。
- `newRecoveryPanel(memberChoices, prepare, commit, dispatch)`：自身登记/退出、管理员恢复目标、密码/MFA选择、当前密码/邮件 OTP二选一、新密码重复输入、独立 SPKI与服务器核验摘要。
- `prepareRecoveryForm(ctx, session, vault, request, checkpoint)`：已提供各 prepare API 的具体 scheduler adapter。`request.Close()` 在 worker 完成时清除借用密码 bytes。
- `newEmergencyViewer(contact, fetch, dispatch)`：单独只读查看组件，显式同意后才 fetch；fetch 调用 `WithEmergencyView` 并复制需要显示的 fields。列表只显示名称，敏感字段默认隐藏、逐项显式显示，不能编辑、导入或进入 AutoFill。附件下载、passkey使用不属于该查看器能力。
- commit 回调调用 `CommitRecoveryOperation` 并将结果交真实操作记录/target失效处理；不把 Confirmed 当成新会话授权。`dispatch` 必须回到 UI 线程，并检查宿主 scope/epoch。锁定、切换账号、重新接受 snapshot 时关闭所有组件。Close 取消在途、丢弃迟到结果；计划与 worker 各自独占，避免并发清除。
- 组件没有改 main/network/storage；没有真实导航入口，因此不得在发布说明里写成已向用户开放。Go string/UI历史/GC副本无法证明物理归零；借用 byte buffer 清理不应被宣传为完整内存擦除。

## Review 退回修复：取消与派发队列窗口

本轮只修改独立 UI、永久回归测试及本文，未修改协议、账号核心或主应用。准备和只读查看取消现在同时取消 context、推进 generation、退出 running 并清理当前持有秘密；排队中的旧成功/错误结果不能覆盖新尝试。迟到 RecoveryPlan 必须 Close；迟到查看 rows 清除引用，不能恢复内容或展开状态。锁定仍由宿主调用 Close，关闭后不再接纳 UI 结果。

提交阶段单独标记 submitting：取消不推进 generation、不退出运行态、不开放重新准备；等待提交 adapter 返回 Confirmed/Unknown 后冻结流程。宿主仍必须在 commit callback 内按 actor/target/operationId 记录结果，不能把持久处理放在可能因锁定丢弃的 UI dispatch 中。Close 只丢弃迟到 UI 展示，不阻止宿主结果处理。

永久测试 `recovery_cancel_ui_test.go` 用可控 dispatch 队列精确暂停在 worker 完成与 UI 接纳之间，覆盖取消、重新开始、Close/锁定、迟到成功/错误、旧 plan Close 与旧 rows 清理；另覆盖取消提交和锁定后 Confirmed/Unknown 仍到达宿主，身份字段保留且 UI 不开放重试。

本轮实际通过：

- `go test -race -tags headless . -run 'TestRecovery|TestEmergency' -count=1`
- `go test -tags headless ./...`
- `go vet -tags headless ./...`
- `git diff --check`

本轮没有重跑真实 SMTP/1.37.4 回环，协议未变；前文真实回环证据属于原实现验证。未运行真实平台窗口/系统锁定，锁定测试验证宿主调用 Close 的契约。新提交仍须新独立 Review，不能沿用旧 HEAD 的审查。

## 已执行验证与边界

新增测试位于本 lane 的 `account_recovery*test.go`、`emergency*test.go` 和 `recovery_ui_test.go`。

已实际通过：

- `go test -tags headless ./...`：全包。
- `go test -race -tags headless ./...`：全包，无 race。
- 后续补充目标摘要及 checkpoint/派发中 Close 用例后，`go test -race -tags headless ./... -run 'TestRecovery|TestEmergency|TestAdministratorRecovery' -count=1` 通过。
- `go vet -tags headless ./...`：通过。
- `MYGO_RECOVERY_SMTP_TEST=1 go test ./internal/vaultwarden -run '^TestLiveRecoveryLifecycle$' -count=1 -v`：完整真实固定版本回环通过。
- 补充非空个人条目查看后，`MYGO_RECOVERY_SMTP_TEST=1 go test -race ./internal/vaultwarden -run '^TestLiveRecoveryLifecycle$' -count=1 -v`：21.61秒完整回环通过，无 race。

真实容器使用固定 image digest `vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`（1.37.4），仅127.0.0.1随机端口和 `/recovery-fixture` base path；纯 Go SMTP sink 仅容器内回环1025，仅 example.invalid，不外发。临时 SMTP binary/spool/受控过期 JWT签名材料都在会话 TMPDIR 下的 t.TempDir，未入仓库。测试创建 full ID+唯一 ownership label；清理前核对 full ID/label，再 `docker rm -fv` 自有容器及匿名卷。

最后完整 race 回环容器 `fd0bc02d53e4ffe3f889583fde227338c40daf7f77e59fa7f77411f50345cbf2` 已清理。实测：SMTP invite/reinvite；错误收件人、真实签名过期token；坏公钥拒绝；确认 user key 包装；等待中view拒绝；reject/initiate/人工approve；非空个人登录条目view解密并强制只读；takeover新密码登录保留user key；组织既有成员登记/退出/重新登记；组织RSA链；管理员密码+MFA恢复SMTP与重新登录完整sync；非空EA和恢复登记分别真实轮换；漏EA密钥服务器写前拒绝且旧user key未变。

另在**同一自有容器**写受控 `/data/config.json` 并重启，验证关闭EA时隐藏历史清单、adapter拒绝虚假空覆盖；再启用并确认原授权 ID仍存在。没有停止/重启任何用户实例。回环没有等待完整自然天数，使用人工批准；不能声称自然等待期已实际通过。设置了2秒检查schedule但本测试不依赖它放行。

故障/角色测试覆盖 owner、admin→member、admin→owner拒绝、member/custom拒绝；损坏公钥、跨membership、准备后详情变化、状态矩阵、跨Session、过期会话、真实refresh后checkpoint失败零mutation、存储callback失败、派发中锁定未知、HTTP503部分失败不重放、完整/非空轮换公钥变化、缺字段/重复/分页/未知探针、UI准备不提交、密码不匹配、迟到结果/关闭/未知冻结。

开发中实际发现并修复：旧测试夹具仅 BindSnapshotRevision 不满足当前完整snapshot授权合同（首次回环在invite预检即拒绝，零invite写）；改用 AcceptAuthenticatedSnapshot；轮换helper最初输出nil空切片被账号schema校验拒绝，改为真实枚举后的非nil空数组。首个单测编译曾使用不存在的 ErrStorage，已改本地fixture错误。没有将失败检查冒称通过。

未验证：真实平台窗口视觉、Keychain/Swift/AutoFill持久撤权、系统级多账号target journal、附件/passkey专用查看、跨组织隐藏政策/真实已配置MFA提供者的所有组合、自然等待结束。个人密钥轮换组合仍需 #14 把本helper与 #6/#13完整转换器连接；本测试用空个人cipher/folder/Send做非空恢复密钥验证，不冒充其他lane转换验收。
