# Cipher / Folder 用户密钥轮换资源适配（Board #39）

本卡只负责 cipher/folder 资源转换、准备分析及只读核验。协调者在本卡会话明确追加授权 `account_rotation.go` 的 prepare/commit preflight **两处** freshness 比较调用替换，其他公共编排不改。复用 #13 的 `validateCopyObject`、`transformCompleteCipher`、`rekeyLegacyShare`；不复制字段转换器，不调用 Session 或 Read，不上传、删除、恢复条目。数据由 `AccountRotationInput` 临时借用，返回只含新的密文或非秘密 ID/状态，不保留输入 slice/key。Go string/GC 临时副本不能保证物理清零。

## 可调用接口

```go
AnalyzeAccountRotationCipherResources(context.Context, AccountRotationInput) (RotationCipherReadiness, error)
ConvertAccountRotationCipherResources(context.Context, AccountRotationInput) (RotationCipherResources, error)
VerifyAccountRotationCipherResources(context.Context, RotationCipherVerificationInput) (RotationCipherVerification, error)
AccountRotationCipherInventoryEqual(a, b json.RawMessage) bool
```

`RotationCipherResources{Ciphers []json.RawMessage, Folders []AccountRotationFolder}` 只负责这两个资源集合，空集合仍返回非 nil 数组。组合示例：

```go
// 在已有 AccountRotationAdapter.Convert 的 Session 锁内调用。
resources, err := vaultwarden.ConvertAccountRotationCipherResources(ctx, input)
if err != nil { return vaultwarden.AccountRotationConversion{}, err }
// combined 是 Send 和恢复收件人各 lane 已实际验证构造的结果。
combined.Data.Ciphers = resources.Ciphers
combined.Data.Folders = resources.Folders
return combined, nil
```

不能以此创建空 Send、Coverage 或 Revalidate 占位结果。本卡不替代 #12 的枚举/身份核验，不接管 #14 的 controller、fresh auth、journal、epoch 和完整 inventory 权限证明。

`RotationCipherReadiness` 为 `{Ready bool, Preparations []RotationCipherPreparation}`，每项包含 `CipherID, AttachmentID, Reason string; Deleted bool`。Convert 遇准备项返回 `*RotationCipherPreparationError`，可用 `errors.As` 取列表；其 Unwrap 为 `ErrUnsupportedEdit`。列表按原 sync 顺序，不含文件名、明文或 key。

## 实际准备流程和权限边界

真正没有 attachment key 的文件始终以 owner userKey 加密，即便其 cipher 已有独立 item key。不能把旧 userKey 包装成 attachment key；本适配也拒绝已有 wrapper 解出当前 owner key 的危险伪迁移结果。

UI 在轮换 adapter 外明确执行：

1. 根据准备清单准确 ID 调用 `UpgradeLegacyCipherAttachment`。完整验证旧二进制 MAC 后，上传独立随机 attachment-key 替代件，保留旧件。
2. 正常 fresh sync、认证快照安装和重新授权；明确原/新 ID，调用 `VerifyAndDeleteLegacyCipherAttachment`。服务器下载两件并验证 MAC/长度/内容摘要后，才明确删除旧件。
3. 再 fresh sync，清单应不再含旧件，然后重新 prepare 用户 key 轮换。

取消、未知上传/删除、额度或政策拒绝都保留材料，不自动重试，不先删唯一来源。`Deleted=true` 的旧无 key 文件目前不能通过公开 Upload/Delete 在 trash 内就地升级；本接口精确指出该文件，不自动恢复、不绕过权限。用户若明确决定恢复，需在正常独立条目恢复 UI 操作、重新同步后再走上述准备，并按其意图重新放回 trash；若不能/不愿恢复则轮换保持阻断。已有独立附件 key 的 trash 可直接转换并保持 deletedDate，无文件的 legacy 也直接支持。

## DTO 和加密契约

固定 [accounts.rs 1.37.4](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/accounts.rs) `RotateAccountData` / `validate_keydata` / `post_rotatekey`，以及 [ciphers.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/ciphers.rs) `CipherData:260–326`、`update_cipher_from_data:429–609`：

- 精确个人 cipher/folder ID 集合，拒绝缺数组、重复、非法 ID、错 profile account。组织条目不进入个人提交 DTO。
- 按 CipherData 白名单构造请求，必含 encryptedFor、lastKnownRevisionDate 和 attachments2[id]={fileName,key}；sync 的 attachments 原数组、权限、creationDate/deletedDate 等不误作请求字段。
- 用户 key 轮换不改变 deleted_at；原 deletedDate 留在 recovery 的原 sync，核验要求保持。归档/folder/favorite 等按 DTO 保留。
- 现代条目逐一验证 wrapper 和全部已知加密字段 MAC；保留 item key 与其密文字段，只重新包装 item key。无 item key legacy 转换全部八类、FIDO2、custom/history、URI alias/checksum、文件名和独立附件 key wrapper。
- 所有 JSON 用 UseNumber，已知 Value 字段的数值 token 不经 float64。未知 schema，包括 unknown:null，统一写前拒绝；本版本不承诺不识别的新扩展能轮换。这也避免服务器忽略顶层 unknown 导致静默丢失。
- 输入不可由 UI 自称 scope 授权。借用 input 来自已认证 controller；纯函数无法独自证明 server URL 的来源。

## 只读恢复核验

`RotationCipherVerificationInput`：

```go
Scope, CurrentScope Scope
OriginalSync, CurrentSync json.RawMessage
Target RotationCipherResources
OldUserKey, NewUserKey []byte
```

原 sync/目标请求来自加密 journal，CurrentSync/CurrentScope 必须来自同账号的新登录完整 sync。首先对原/目标逐字段解密验证及语义比较，证明记录中的新请求保留内容与独立文件 key；不随机重新加密。随后精确比较实际服务器密文字段与旧/目标，检测单字段和单附件包装的混合。结果 `State` 及 `Resources[]{Kind,ID,State}` 使用 `old/new/mixed/external/missing/unverifiable`。结构/材料/取消错误伴随 error，State 保持 unverifiable。任何 error 或非 new 均不得清 journal。

比较覆盖全部个人、组织条目和 folder ID，外部新增/删除/未知字段变化都不静默放过。组织条目保持原样核对，不尝试用个人 key 解密。服务器派生字段仅固定以下规范化：

- cipher.save / folder.save 更新 revisionDate；个人轮换核验忽略这一时间戳，不忽略 creationDate、deletedDate、archivedDate 或其他未知字段。
- [cipher.rs:259–279](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/db/models/cipher.rs) 将 login.uri 派生为首个 uris.uri 或 null；只正规化此 alias。
- [attachment.rs:57–75](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/db/models/attachment.rs) 每次生成 JWT/presigned URL；只忽略 attachment.url。名称、key、size、sizeName、object、unknown 等仍精确。

`AccountRotationCipherInventoryEqual` 专用于账号 prepare/preflight 两次读取的 freshness 比较，**只**排除动态 URL，不忽略修订、alias 或任何其他字段；不是恢复完成证明。本卡已在授权范围内修复 account_rotation.go 的这两处调用；原先用完整 rawJSONEqual 比较 ciphers，会因 URL 每次变化在含附件账号上 ErrConflict。

此资源核验不下载二进制，依据准备阶段已有完整 MAC/内容核验和轮换仅更改 wrapper 的协议。非事务 partial 只报告，不修复、不重放；旧/新全材料与 pending 屏障由 controller/storage 保留。它不是 fresh-auth、Send/紧急授权/组织恢复公钥、跨账号权限或整个账号完成证明。

## 验证记录

- `go test -race ./internal/vaultwarden -run '^TestRotationCipherResources|^TestAccountRotation' -count=1`：通过。八类现代/legacy、FIDO2、null、unknown、已知 linkedId 大整数 9007199254740993 精确保留、独立文件 key、folder/trash、无文件/URI alias、准备后可成功转换、坏 MAC、跨账号/org 排除、缺失/重复/混合字段、取消；Read 哨兵保证资源函数无网络。
- `go vet ./internal/vaultwarden`、`go test -tags headless ./...`：通过。
- `MYGO_ROTATION_CIPHER_TEST=1 go test -race ./internal/vaultwarden -run '^TestLiveRotationCipherResources$' -count=1 -v -timeout=160s`：真实 1.37.4 回环通过。自有虚构账号 legacy v1 owner-key 文件→Prepare 返回准备错误且 rotation POST=0→Upgrade→服务器双件 MAC/内容核验并明确删除原件→fresh sync；随后 legacy FIDO2/custom/history/文件、现代条目、folder，且 legacy 已处于 trash，一并用户 key 轮换。prepare 前及 commit 前分别主动等待1100ms跨签名 URL 时间边界。新登录完整资源核验 State=new，FIDO2 密文字段可解密且 counter/keyValue 正确，trash 保持，新 key 下载附件 MAC/完整内容一致，独立附件 key 长度64且不等于旧 userKey。整个成功链恰好一次 rotation POST。
- 镜像 digest `sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`，实际 image `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`，版本 `1.37.4`，revision `7c188967e7a467b19b2757bc3326f9cf3ccae327`。最终独占容器 ID `9e5cf74925e8a6ff7e64d65c5473a277b0a2ed326ecd95e140ae6f8df58deffe`，随机 loopback 端口、volatile 数据、example.invalid 账号；测试 cleanup 验完整 ID+独占 label 后删除，无用户库或他人容器被操作。
- 真实首次执行在原 account_rotation.go 的全 ciphers freshness 比较报 ErrConflict，未伪报成功。授权修复两处调用后回环通过；新增零POST计数与owner-as-item-key拒绝后再次执行也通过。一次 unit 检查把 []byte 和 json.RawMessage 用 reflect.DeepEqual 比较导致测试自身误报，改为 bytes.Equal 后通过。

未验证：实际 Keychain/Swift journal、生产 UI 完整组合、非空 Send/紧急授权/组织恢复、真实 OS passkey assertion、断电恢复。live 持久回调采用 Go 内存记录，只验证本 lane 密码学/协议，不冒充持久屏障端到端证据。非事务 partial 的精确报告用 unit 覆盖，本卡不实施自动服务器修复。
