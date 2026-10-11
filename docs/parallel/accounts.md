# 账号组件与跨 lane 契约（Card #7）

本卡是可独立编译、可测试的账号组件；主应用导航/网络任务接线由 #14 完成，真实加密 journal/屏障由 #17 完成。**这些组件尚不等于已接通的产品。** 不改 Session struct、main/ui/network/storage/Swift、MFA 或 Send 模块；根 `account_rotation_storage.go` 留给 #17。

来源：Vaultwarden **1.37.4** commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`，固定缓存 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/` 中 `src/api/identity.rs`、`core/accounts.rs`、`api/mod.rs`、`core/ciphers.rs`。策略字符语义核对 Bitwarden clients `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 的 `libs/common/src/admin-console/services/policy/default-policy.service.ts:evaluateMasterPassword`；评分复用已有官方 zxcvbn4.4.2/goja，不升级依赖/MyGo。

## 实际组件能力

| 能力 | 入口与边界 |
| --- | --- |
| 注册 | `Client.AccountSendRegistrationEmail` → `/identity/accounts/register/send-verification-email`，204 表示邮件、200 JSON string 表示直接返回 token；`AccountRegister` → `/identity/accounts/register/finish`。本地随机64B user key、RSA2048 PKCS8/SPKI、认证hash与type2包装。不使用旧 `/api/accounts/register`，成功后走正常登录。 |
| 邮件/提示 | `AccountPasswordHint`、`AccountVerifyEmailToken`、`Session.AccountSendVerificationEmail`；token为秘密，不解析JWT授许。 |
| 资料/头像 | `AccountProfile`、`AccountUpdateProfile`、`AccountUpdateAvatar`。验证scope账号/email/wrapped key，名称50字节，颜色#RRGGBB或null。 |
| 敏感验证/API key | `AccountSensitiveInput{Password []byte; OTP string}`必须且仅能选一个；password先按当前KDF解包验证user key，再发认证hash；OTP为**protected action邮件OTP**，不是登录TOTP。`AccountVerifyPassword`返回真实合并主密码policy。`AccountAPIKey`需明确确认，read也可能首次生成key；错误不自动重试。OTP发放/独立核验由后续认证lane负责，本卡不伪造通用OTP成功能力。 |
| 密码/邮箱/KDF | `PrepareAccountCredentials`只重新包装原user key。改邮箱用新规范化email盐；改KDF用authenticationData/unlockData；改密码保持KDF。当前密码先本地再服务器验证，实际type1策略约束新密码；commit前重新读取profile和policy，变化要求重新准备。 |
| 清库/删除/security stamp | `PrepareAccountDestructive`，第二次确认后才调用`CommitAccountChange`；所有派发先持久恢复材料+屏障；HTTP400也保守标未知（上游部分操作非事务）。 |
| 轮换 | `PrepareAccountRotation` → 完整新版`rotate-user-account-keys` DTO。强制提供adapter，完整新sync与认证snapshot相符、5类资源覆盖、RSA公私钥一致、保持KDF/email/原非对称keypair。新增helper重包装独立item key、folder名称、Send seed。legacy keyless/非空encryptedByKeyId交 #13，不猜字段。 |
| 原生组件 | 根`account_ui.go`：独立`newAccountForm`/`accountFormView`，密码遮掩、强度/策略说明、注册结果、各业务字段、二次确认/取消、scope+UI epoch+sequence拒绝迟到结果。回调交主应用scheduler，未改共享app。 |

在线认证与新设置均要求 PBKDF2 100000–2000000；旧离线快照仍支持 5000–2000000。Argon2id 支持 2–10 次/16–1024 MiB/1–16 并行。服务器提供低于 100000 次的 PBKDF2 时阻止在线派生，需先通过可信官方客户端提高账号参数。密码最少12 UTF-16单元；type1使用真实0–4评分、UTF-16长度、Unicode大小写映射、ASCII数字及固定客户端集合`!@#$%^&*`。服务器`verify-password`负责合并适用组织/SSO policy，本卡不猜不可见目标角色。`AccountPasswordPolicy.Check(ctx,password,email,login)`的login=true仅在EnforceOnLogin时执行，供后续MFA/SSO lane在完成认证前调用；它不是通用登录凭据或policy来源证明。

## 准备、确认、存储与会话生命周期

代码精确类型在 `internal/vaultwarden/account_change.go`：

```go
type AccountRecoveryPersistence func(AccountRecovery) error
func (*Session) CommitAccountChange(ctx context.Context,
    plan *AccountChangePlan, confirmation string,
    persist func(SessionCheckpoint) error,
    saveRecovery AccountRecoveryPersistence) (AccountChangeResult, error)
```

Plan只能由对应Session准备，绑定当前epoch/revision，私有完整请求，单次消费；取消`Close()`清除材料。confirmation必须等于该plan的`ConfirmationText()`，UI必须先展示影响再调用。刷新checkpoint失败阻止派发；刷新/快照epoch变化令plan失效，需要重新准备。API read/profile结果不安装新会话或新vault。

`AccountRecovery` **全部视作秘密**，精确JSON schema v1：

| JSON字段 | Go类型/含义 |
| --- | --- |
| version | int，固定1 |
| operationId | string，随机128bit hex，此次操作唯一ID |
| scope | 现有Scope，server+account |
| kind | AccountChangeKind：password/kdf/email/security-stamp/delete/purge/rotate-user-key |
| oldRevision | string，准备时已认证快照revision |
| oldSession | []byte，JSON自动base64，完整旧savedSession（含旧user key/refresh/旧wrapped key） |
| oldUnlock | *PasswordUnlock，旧config与旧32B快照解锁key |
| oldVault | []byte，JSON自动base64，**完整原VaultData JSON**，包含unknown、quarantine与pending policies |
| newUnlock | *PasswordUnlock，仅凭据变更有新config/key；email变更config含新email |
| newUserKey | []byte，仅用户key轮换有新64B key |
| newWrappedKey | string，新主key包装的user key；单纯stamp/purge/delete为空 |
| request | []byte，完整已加密服务器DTO，含认证hash/OTP，仍属秘密；仅用于核验/恢复，绝不自动重放 |

`AccountRecovery.Close()`清除借用秘密。回调持有Session锁，**不得调用任何再锁Session的公共方法**；如需异步I/O，回调应同步等待受信存储完成，并且只能深拷贝到受控缓冲。禁止保留借用slice指针，禁止明文落普通文件、docs或日志。Go/JS字符串及GC副本不能证明物理清零。

`AccountChangeResult`字段：`OperationID, Scope, Kind, PreviousRevision, Dispatched, Confirmed, Unknown, RequireLogin`。没有伪造NewSession/refresh token；派发后旧Session清key/token、closed=true、推进epoch、撤policy/item授权。成功要求重新登录、完整sync、新scope/email/KDF与解密核验、安全快照回执后才允许替换当前账号。服务器成功不代表本机已持久完成；失败未知也不能回用旧网络会话。OldSession是恢复旧数据的材料，禁止拿它重新授权未核验旧快照/AutoFill。

### #17 storage hook 的 begin/query/complete/recover/clear 语义

这些是**待 #17 实现的持久化操作语义**，本卡不创建存储文件/调用Swift。最终具体桥函数由 #17 定义并与 #14接线。

1. **begin**：在`saveRecovery`回调中验证当前storage lease、UI epoch、scope、oldRevision与当前认证完整vault相符；加密持久保存v1 recovery并原子安装pending barrier、撤销旧离线/AutoFill lease。确认落盘后才返回nil。失败零敏感POST。不得先把current vault换成新key数据；不能丢旧解密材料。若持久化结果未知，先query同operationId，不另建操作、不继续POST。
2. **query**：仅当前已认证账号的恢复UI可读取同scope的operationId、kind、状态和恢复材料；状态不得以普通JSON/公开status泄露session/key。重启后pending屏障仍有效。普通sync、token checkpoint或新登录不能自行清屏障。
3. **complete**：接收AccountChangeResult，以operationId/scope/previousRevision/current UI epoch比对记录。Confirmed仅记录“服务器确认，等待重新登录核验”；Unknown/取消后派发保持“可能部分执行”。结果不能直接恢复离线许可，迟到的其他账号结果不能替换当前账号。记录写回失败仍保留begin状态。
4. **recover**：用户显式选择恢复后新登录与完整sync；按实际服务器wrapper尝试旧/新材料核验，逐项检测partial rotation，保留旧+新key和原全vault。禁止盲重放request、重生key或按一次HTTP失败声称回滚。存储和转换lane须提供部分数据恢复流程；本卡提供材料与屏障契约，不宣称已完成所有部分轮换修复UI。
5. **clear**：仅在当前scope/operationId、完整新vault解密、组织/紧急/Send转换核验、已认证安全publish回执与显式用户确认都通过后清理journal/barrier/旧材料。删除账号是明确例外：服务端删除确认后，由用户显式确认删除本机恢复副本。失败、取消、锁定、普通同步、过时receipt都不能clear。

begin成功但随后取消/guard失败（Dispatched=false）也可能已有持久屏障；#17通过query识别，再由明确的“确认未派发”恢复步骤解除，不能假定没有记录。由于begin后至网络派发之间不可与服务端事务绑定，记录一律保守保留。

## #6/#12/#13 轮换 adapter 精确合同

定义在 `internal/vaultwarden/account_rotation.go`、`account_rotation_cipher.go`：

```go
type AccountRotationAdapter interface {
    Convert(context.Context, AccountRotationInput) (AccountRotationConversion, error)
}
```

Input：`Scope Scope; Revision string; Epoch uint64; SnapshotHash [32]byte; Sync json.RawMessage; OldUserKey, NewUserKey []byte; Read func(context.Context,string)(json.RawMessage,error)`。它由账号层在同一Session锁下从已认证snapshot与fresh sync创建，不接收UI自称身份。所有slice临时借用，不得持有/改写/写日志。Read是同Session的已认证GET运输，限定`/api/emergency-access/`、`/api/organizations/`、`/api/users/`，复用refresh/checkpoint；不能绕过它读取别的账号或递归公共Session方法。

Conversion：

- `Data AccountRotationData{Ciphers []json.RawMessage; Folders []AccountRotationFolder; Sends []json.RawMessage}`。
- `Emergency []AccountRotationEmergency{ID string; KeyEncrypted string}`。
- `Recovery []AccountRotationRecovery{OrganizationID string; ResetPasswordKey string}`。
- `Coverage AccountRotationCoverage{Scope,Revision,Epoch,SnapshotHash; EmergencyComplete,RecoveryComplete bool; EmergencyIDs,RecoveryOrganizationIDs []string}`。
- **必需** `Revalidate func(context.Context, func(context.Context,string)(json.RawMessage,error)) error`：在commit前用传入Read重新核验emergency/recovery清单、身份、状态及公钥，发生变化返回ErrConflict。闭包只保留非秘密核验元数据，不能捕获临时借用Sync/key。账号层另外重新GET sync比对profile/ciphers/folders/sends；仍不把GET→POST当CAS。

#12必须通过Read实际枚举当前grantor已confirmed的emergency和已登记reset-password key的组织，核对资源ID→受托用户/成员/组织、当前状态、原公钥与可信公钥，再包装新user key；返回可核验的完整清单。Coverage是**受信schema adapter对完成这些工作的声明**，不是抵御任意恶意同进程Go代码的证明。UI不能创建adapter或设置Complete=true。空数组只有实际读清单为空后合法；未知分页、缺字段、隐含条目、身份不一致都拒绝。服务器功能开关隐藏资源时不得把隐藏误认成不存在。

#6负责Send DTO schema与seed16包装，#13负责legacy无item key和附件/特殊schema转换；不能只核ID并漏加密字段。账号层校验完整个人cipher/folder/send ID集合、无重复无跨org、匹配coverage，以及包装非空。加密schema正确性由对应adapter验证；未知字段按RawMessage保留大整数，不能识别是否旧user key加密的扩展则拒绝整个prepare。

`AccountRewrapRotationCipher`支持有独立64B item key的个人cipher：只重包key，原字段/附件/unknown沿同item key保留；补服务器必需而sync不含的`encryptedFor`和`lastKnownRevisionDate`。`AccountRewrapRotationObject(...,16)`只做Send seed wrapper转换，不冒充完整Send DTO验证。`AccountRewrapRotationFolder`重加密folder名称。空/不完整/失败adapter阻止POST。固定服务端非事务，snapshot读取至POST仍有并发窗口；本地epoch不能当服务器CAS。

## 测试证据（持续更新）

本卡新增 `account_change_test.go`、`account_registration_test.go`、`account_rotation_test.go`、`account_integration_test.go` 与根`account_ui_test.go`。涵盖当前/新主密码及邮箱盐/Argon2包装，旧完整vault/session恢复，错误密码/OTP输入互斥，资源限额，scope/epoch/revision、取消、存储失败零POST、服务器换key、HTTP400/500与断线未知结果、轮换缺adapter/覆盖/ID、opaque大整数与keyless拒绝、RSA包装，原生密码遮掩、两步API key确认、迟到与未知结果禁重试。既有官方crypto固定向量及passwordstrength 28向量复用。

已执行独占容器`mygo-account-7-01a116ff`（label `mygo.account.card=7`），镜像`vaultwarden/server:1.37.4` image ID `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`，仅127.0.0.1随机端口/新建example.invalid账号。真实注册→profile/avatar→API key读/轮换→创建加密条目→改密码/KDF/email→每次重新登录解密→security stamp→purge→delete已通过。初次容器未配置volatile选项被1.37.4拒绝启动，按独占测试配置修正后成功。真实用户key轮换也已通过：新建自有账号的独立item-key条目实际重包装，原RSA pair保持，重新登录成功解密；该live adapter真实读取空紧急授权清单并核对无组织成员，**不是非空emergency/recovery/Send/legacy最终adapter证据**。一次真实轮换最初因CipherData缺encryptedFor被422拒绝，改用完整`AccountRewrapRotationCipher`后通过；连续多次登录触发默认10次burst限制，独占测试容器改为LOGIN_RATELIMIT_MAX_BURST=100后完整回环通过。


最终验证命令（已实际执行）：

- `go test -tags headless ./...`：全包通过，包括新增账号和原生组件测试。
- `go test -race -tags headless ./...`：全包通过，无race报告。
- `MYGO_ACCOUNT_TEST_URL=http://127.0.0.1:32791 go test ./internal/vaultwarden -run '^TestLiveAccountLifecycle$' -count=1 -v`：1.37.4完整账号与用户key轮换回环通过。
- `go vet -tags headless ./...`、`git diff --cached --check`：通过。
- 独占容器`mygo-account-7-01a116ff`已删除，易失数据库与其中所有测试账号/秘密随容器清理；没有用户账号或持久卷被操作。
- 故障证据包含真实refresh返回新token但checkpoint失败零敏感POST；关闭Session中断已派发请求标未知且恢复材料可用；准备后policy/identity变化阻止commit；恢复adapter缺revalidate/收件人变化阻断轮换；文件夹先写而后失败仍可分别用旧/新key解密。

原生回调请求`accountFormRequest`转交scheduler后由其`Close()`释放Password/NewPassword，`.prepared/.completed/.registration/.apiKeyCompleted`仅在匹配scope/epoch/sequence的UI线程结果上采用。未知结果不显示“未提交”、禁重复请求。API key需两步确认，默认遮掩，单独显示/隐藏，离开清除。#14应在lock/account switch时调用form.Close()，并在投递状态前验证真实存储receipt；组件不会修改共享app状态。

未验证：真实SMTP邮箱投递（协议分支httptest覆盖，真实回环SMTP禁用）、真实Keychain/Touch ID/Swift journal、签名系统窗口/AutoFill、完整所有权/非空紧急授权/组织恢复/Send/legacy adapter最终装配。这些边界不能描述为测试通过或完整产品交付。
