# Send 用户密钥轮换与只读恢复核验（Card #40）

基线 `69047c2`，仅新增 `rotation_send_resources*.go` 与本文件。代码不改 Session、公共账号编排、cipher/folder、UI 或存储。公开函数已可供 #14 组合，尚需 Board 独立 Review 与合入。

## 固定 1.37.4 协议依据

审计源码固定在 Vaultwarden commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`：

- [accounts.rs](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/accounts.rs)：`validate_keydata` 验证全部 owner Send ID 被覆盖；`post_rotatekey` 按 folder → emergency → organization reset key → Send → cipher → user 顺序执行，无整体事务。Send 分支只执行 `send.akey = send_data.key; send.save(...)`，不调用普通 Send 更新函数。
- [sends.rs](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/sends.rs)：`SendData` 的 required 字段包含 type/key/name/deletionDate/disabled；普通更新的 `password: None` 表示保持密码，file 数据不可变。
- [模型 send.rs](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/db/models/send.rs)：owner `password` 是服务端 salt/hash 后的32B Base64URL hash，**不是可提交的 Send password 输入**。owner `authType` 为 password=1、none=2，file.size 输出 string。

因此本转换提供完整 RawMessage SendData，而不是只有 id/key 的泛 wrapper。除重新包装的 key 外，password 显式置 null，所有其他字段保留，包括 owner 的只读字段（该固定 endpoint 的 serde 忽略额外顶层字段）。**输出专用于 rotate-user-account-keys，禁止用于普通 PUT /sends/{id}。** 不输出或重算访问口令 hash，不更改 seed、正文、文件名密文、文件 descriptor 或 binary。

保留未知字段的依据限于固定 endpoint 只消费 id/key 的事实；它们作为不透明原值保留，恢复时严格比较，不能解释为支持未来版本中的新加密 schema。明确出现非 null `keyId`、`encryptedByKeyId`、`emails`、`organizationId`，未知 type/authType、缺少标准字段、重复 ID 等拒绝转换。未知的语义无法获得独立 MAC 保证；不得将此 helper 当服务器版本探测器或未来协议适配器。

## #14 组合接口

```go
func ConvertSendRotationResources(ctx context.Context,
    in AccountRotationInput) ([]json.RawMessage, error)

func VerifySendRotationResources(ctx context.Context,
    in SendRotationVerificationInput) (SendRotationVerification, error)
```

转换示例（在 adapter 的 Convert 中）：

```go
sends, err := vaultwarden.ConvertSendRotationResources(ctx, in)
if err != nil { return vaultwarden.AccountRotationConversion{}, err }
// c 的其他资源、Coverage、Revalidate 来自对应 owner 的受信枚举。
c.Data.Sends = sends
return c, nil
```

`in.Sync` 必须是账号层提供的完整已认证 fresh sync，`profile.id` 必须与规范化 Scope 匹配。sends 必须非 null，空数组返回非 nil slice；禁用、过期、访问次数已满等 Send 不会过滤。旧/新 key 均须64B且不同。函数验证 owner schema、ID/accessId、日期/计数/密码保护、类型对应的 text/file 必要字段；复用 `DecryptString`/`sendKey`/`EncryptString` 的 type2 MAC 和16B seed/HKDF格式，验证名称/备注/正文或文件名全部 MAC 与 UTF-8 后仅重包 seed。

所有输入仅借用，函数既不保留 input、也不调用 Read 或 Session；可在既有 Session mutex 内安全调用。返回新分配的加密 JSON。解密的 plaintext bytes、seed 和派生 key 在所有成功/失败路径 clear；不创建不可变 plaintext string。没有自定义加密算法、seed 再生成或 binary 上传。

恢复输入：

```go
report, err := vaultwarden.VerifySendRotationResources(ctx,
    vaultwarden.SendRotationVerificationInput{
        Scope: journalScope, FreshScope: authenticatedFreshScope,
        OldSync: journalOldVault.Sync,
        FreshSync: freshVault.Sync,
        RequestSends: savedRotationRequest.Data.Sends,
        OldUserKey: oldKey, NewUserKey: journalNewUserKey,
    })
```

`OldSync` 来自 journal 的旧 VaultData.Sync，不能把整个 VaultData JSON 传入；`RequestSends` 必须来自持久化原 request，不能重新运行 Convert 来生成。核验先证明原请求只按上述规则改变 wrapper/password，并解包验证目标仍是原16B seed；然后逐 ID 对照 fresh owner 数据。重新随机包装的密文可以不同，状态依据 key 解包/MAC/seed 相等，而不是重加密后的字符串相等。

`SendRotationVerification` 包含 `State`、`Enumerated`、`Empty`、逐项 `Resources{ID,State,Reason}`，以及恒为 false 的 `BinaryContentVerified`。Reason 仅固定诊断码。返回 error 时一律不能采用部分报告完成恢复。

| State | 含义 |
| --- | --- |
| old | 所有预期 Send 仍以旧 key 认证解包相同 seed，数据未改变 |
| new | 所有预期 Send 可用新 key 认证解包原 seed，数据未改变 |
| mixed | 同一集合同时存在 old 与 new |
| externally-changed | 出现额外 ID、内容/metadata/unknown 改变，或服务端计数/时间回退 |
| missing | 缺少 journal 预期 ID；不会因过期/自动删除而忽略 |
| indeterminate | fresh schema 不支持、wrapper/MAC/seed不能验证，或空集合不能证明 key 状态 |

整体优先级是 indeterminate → externally-changed → missing → mixed → new/old；逐项仍保留各状态。空集合为 `Enumerated=true, Empty=true, State=indeterminate`，#14 可将其视作已枚举且不适用的资源，但不得当作 Send 证明已轮换。

只允许 `revisionDate` 非递减、`accessCount` 非递减的自然变化：服务器保存、接收访问都会推进这些字段。其余标准字段、unknown、嵌套对象与大整数用 UseNumber 精确比较，成员顺序不影响比较。时间的其他表达变化、数字不同拼写保守视作变化，不广泛忽略 server 字段。无法区分一次合法接收导致的计数增加与外部人为增加计数；报告只证明允许的关系。

## 证明边界与秘密清理

- 纯函数无法证明传入 raw 是服务端 fresh authority。#14 必须负责新登录、完整 sync、scope/epoch/operationId、journal 来源与其他资源核验；本模块不覆盖 Data 其他集合、Coverage 或 Revalidate，不修改/清除 journal，不产生发布许可。
- sync 只有加密文件名、文件 ID/size 等 metadata，没有 binary bytes。seed 与 file descriptor 保持不变证明原文件仍可由同一 Send key 解密的条件，**不证明当前服务器 binary 未损坏、仍存在或已验证文件 MAC**。因此生产只读 helper 的 BinaryContentVerified 恒为 false；需额外明确授权的文件读取流程才能获得 binary 证明。本模块不绕 GET 白名单下载、不消费 receiver 访问次数。
- 固定服务器的非事务顺序可造成混合状态；没有重放请求、重传文件或重新产生 seed 的恢复捷径。
- 所有 journal、request、sync 和加密 JSON 仍按敏感材料处理；调用者负责自己拥有的缓冲与存储生命周期。Go 字符串、JSON parser/GC 历史副本和 OS 缓存无法证明物理擦除。测试仅使用生成的 example.invalid 账号及 fixture 内容，没有真实 Send 或日志秘密。

## 实际验证

已执行：

- `go test ./internal/vaultwarden -run '^TestSendRotation' -count=1`：纯转换/恢复测试通过；默认 opt-in live 用例跳过。
- `go test -race ./internal/vaultwarden -run '^TestSendRotation|^TestSend|^TestAccountRotation' -count=1`：Send 与账号轮换定向回归通过。
- `MYGO_VW_SEND_ROTATION_TEST=1 go test -race ./internal/vaultwarden -run '^TestSendRotationLive1374$' -count=1 -v`：固定 `vaultwarden/server:1.37.4` 独占 loopback 容器内真实注册、自有带密码文本+无密码文件、userKey轮换、新登录、新key owner名称/正文/文件名解密、原 receiver链接/文本密码保护、文件MAC与原始内容一致、receiver访问后恢复核验通过。其他资源在此自有账号实际枚举为空，不是最终全资源 adapter 验证。
- `go vet ./internal/vaultwarden`、`git diff --check`：通过；定向测试编译整个 vaultwarden 包。

单元用例覆盖文本/文件、disabled/expired/hideEmail、计数/日期、密码保留/变化、原seed长度、每个密文字段坏MAC、缺字段/重复ID/跨scope/未知schema、空与null清单、旧新/混合/缺失/外改/不可判定、unknown与大整数、取消、原请求篡改、随机IV差异不误判。已增加每个支持密文字段真实翻转MAC的回归用例。

首次 live 尝试的容器 `72257557ce0f53446b1d18492dc997763681b90c35c617635a2e2bc692f34281` 在文件发布阶段因 macOS 临时目录 symlink 被既有安全策略拒绝；已清理。fixture 采用现有 Send live 测试的 EvalSymlinks 处理后，上述 race live 通过；成功容器 `f66d333519a8a6d9b616e959cc0f6931286119dd3178d360690f97ae6994e88a` 的 label 为 `mygo.fixture=mygo-send-rotation-6af62dab-af13-84f0-5772-ee6a5f6678ea`。两次 cleanup 均核对精确 container ID+label 后删除容器与易失数据，未触及其他容器或账号。

未验证生产外部存储、真实UI/Swift/Keychain与最终账号恢复编排；这些不属于本卡写入范围。
