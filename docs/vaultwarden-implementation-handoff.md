# 完整 Vaultwarden 实现：第八轮组织闭环交接

**INCOMPLETE — 整卡未完成，禁止据此启动 Review 或合并。** 本轮通过 `contact_supervisor(need_decision)` 获得明确批准：完成本阶段必要安全回归、分模块提交、自有资源准确清理、精确交接后退出，下一轮继续同一卡的组织管理产品；整卡范围不缩减。此文件替换第七轮交接，历史全文保存在 `434681a:docs/vaultwarden-implementation-handoff.md`，不得回退、重导入或重做已有个人基线。

## 分支、提交与隔离

- 唯一项目写入目录：分配的 `board-2-vaultwarden-api`，分支 `waku/board-2-vaultwarden-api`。起点 **434681a15a0b5aa9e49c57ba77fce9fefac6686b**，完整保留8c064fc/fe18500及更早成果。
- **d3ad954**：组织RSA/权限/读写共享/秘密与AutoFill协议、固定OpenSSL向量、owner+member真实隔离回环。
- **5a398db**：原生组织/集合导航、新增类型选择、编辑/共享确认、只读与reprompt、成功sync清组织草稿/授权，个人bulk/export明确排除组织候选。
- 最终文档提交也包括一条组织编辑页“同步会关闭表单并清未保存更改”的提示；最终HEAD用 `git log -1` 查证，不能把本文历史提交号当HEAD。
- 主目录 `/Users/vfasky/code/mygo-vaultwarden` 未写入、暂存、commit、stash/reset/clean；没有用户app/watch操作、没有读取真实凭据/快照、没有生产vault请求、没有启动子代理。容器与数据只属本轮，见清理证据。

## 当前已形成的产品闭环

详细功能和限制见 [组织密码库](organization-vault.md) 与 [覆盖矩阵](vaultwarden-api-coverage.md)。

1. `organizations.go`：从认证 `VaultData.Sync.profile` 读旧privateKey和新accountKeys；同时存在必须一致。type-2包装的PKCS8私钥只接受2048–4096位RSA/指数65537、完整ASN.1无尾随；SPKI公钥须匹配。`3.` OAEP SHA256与`4.` OAEP SHA1组织密钥，输出64字节；其他格式/错误长度/错误哈希拒绝。组织名称实际是明文，集合名才加密。
2. `Organization`明确ID/org ID、OrganizationUserID/member ID、UserID/global account；只confirmed(status2)+enabled、已知角色0/1/2/4，当前user必须匹配，org/member重复和混淆拒绝；organizationsNew单独accepted不授权，两份组织DTO同时存在需一致。每次操作短暂派生keys并clear，不新增持久解密org key缓存。RSA内部大整数历史副本不能保证清零，不能宣称完整内存清除证明。
3. 读取现有cipher尊重服务器sync已算好的`edit/viewPassword`（必须存在）；它含full-access、每集合直接用户优先group和多集合AND结果，不能按role编号或raw group OR重算。新增/共享目的集合要求相同org、明确readOnly=false且hidePasswords=false。集合权限字段缺失失败关闭；跨org集合引用拒绝。
4. 侧栏组织/集合导航、个人库独立过滤；组织项目进入原有八类编辑器；只读且viewPassword=true有独立受限详情与Login密码/TOTP认证操作；viewPassword=false保持受保护占位，不能打开秘密表单。组织reprompt复用真正主密码派生、30秒/单文档/epoch/revision绑定grant，个人API组织拒绝仍保留。
5. 可写集合→新增→1–8类型选择，`POST /api/ciphers/create`产生随机item key包给org key；编辑`PUT /api/ciphers/{id}`保持item key/unknown/FIDO2、历史/checksum/revision/encryptedFor；个人编辑器→目标org/集合→确认→`PUT /api/ciphers/{id}/share`，把**独立item key**重包装，附件包装key/FIDO2/unknown保持。无独立key的legacy共享明确拒绝，不把user key交组织。share/create非事务错误一律结果未知，需要sync，不能盲重试。
6. 原生保存后的原有sync/CAS发布继续复用；checkpoint失败无请求、取消/Close在途write结果未知。`WithOrganizationSecret`走同一Swift认证copy/display桥。`appendOrganizationCredentialsLocked`仅把confirmed+enabled/viewPassword=true、未deleted/archived、reprompt0的Login变为最小投影，不含org key/member/collection。
7. 新sync绑定新snapshot revision撤grant、尽力清应用拥有的秘密剪贴板；任何旧组织编辑/创建/共享/reprompt草稿被清除，不能沿用个人冲突保稿规则留住撤权明文。编辑页提示sync将清未保存改动。锁定清组织列表/集合；无在途操作时立即清草稿，在途完成后清私有草稿，迟到结果不能复活UI。个人bulk/export候选过滤组织，避免扩大原来的个人API授权。

## 安全与支持边界（不能隐瞒）

- **离线无法知道服务器刚发生的撤销**：离线读取/AutoFill以最后认证快照、scope/revision/lease及本地锁为界。成功新sync才撤回远端权限/候选；本轮未实现实时通知/远端撤权证明。
- 特殊管理角色可管理但集合readOnly/hidePasswords仍为真的目的集合，当前保守拒绝新增/共享；完整管理授权与policy执行尚缺，不能称全部组织能力实现。
- 组织conflict/unknown禁止重试；组织尚无个人式字段比较重基。sync关闭旧组织草稿，这是撤权边界，不是假称冲突合并完成。个人双改URI/custom逐行对应仍缺，仍拒绝有损全数组覆盖。
- legacy无item-key共享、组织项目复制/import/export、组织状态/批量操作、隐藏密码模式的有限详情、只读八类完整敏感详情尚缺。组织新增可选八类，协议复用八类型实现；本轮组织真实回环专门测Login，不能声称组织八类各自官方互操作通过。
- 同key共享附件包装/FIDO2/unknown由httptest证实保持；真实共享测标准Login，不代表真实附件/FIDO2官方互操作。附件二阶段上传/下载本身仍未实现。
- Go/Swift字符串和RSA内部缓存的历史副本不能证明全部清零；有显式生命周期撤销与byte slice清除，但不夸大保证。

## 本轮验证与发现

所有Go命令使用 `GO_BIN="$(bash scripts/resolve-go.sh)"`。

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race ./...
swift test --package-path macos
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
MYGO_VW_TEST_URL=http://127.0.0.1:32784 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
git diff --check
```

- 最后Go全量（个人bulk/export过滤回归后）：root **1.042s**，协议及dev-debug cached；race root **4.034s**，协议及dev-debug cached；前一轮最终协议实际 **0.958s**、race **3.826s**，所有包通过。build/vet/diff check退出0。随后仅编辑器提示文字与文档，定向 `go test ./ -run TestNativeOrganization -count=1` **0.953s**通过；未无理由重跑Swift。
- Swift **50 XCTest、0 failures**，测试0.187s/wall0.190s；bridge typecheck退出0。Swift源码本轮未改，认证snapshot/index/clipboard机制复用既有实现。
- 最后隔离1.37.4：PBKDF2 **3.33s**、Argon2id **0.30s**、TOTP **0.60s**，总 **4.23s**/package **4.340s**通过。之后只有个人候选过滤与UI提示/文档变更，未重复无关真实服务回环。
- 新协议测试包括RSA OpenSSL固定向量、PKCS8尾随/PKCS1/畸形长度、SHA1/SHA256交叉拒绝、兼容字段不一致、账号/member混淆、accepted/disabled/revoked、只读/隐藏/reprompt、缺集合flags、checkpoint失败、取消/Close在途写入、真实主密码派生grant与旧revision、隐藏密码/TOTP回调拒绝、独立key重包装/附件/FIDO2/opaque大整数保持、跨org/legacy拒绝、非事务错误。
- 新headless测试包括导航过滤、创建类型选择、组织编辑、只读/hidden/reprompt、共享目标确认取消、成功sync和锁定清组织草稿/导航、个人backup/bulk排除组织候选。没有运行真实窗口视觉。
- 固定向量 `internal/vaultwarden/testdata/organization-rsa.json` 是**本轮生成的公开测试专用**2048位RSA，不是凭据。OpenSSL genpkey→pkcs8 DER→pkeyutl，明文bytes0…63，OAEP/MGF1都分别指定sha256/sha1，详见组织专文命令；固定密文由OpenSSL而非被测Go函数生成。
- 真实owner fixture：创建组织→解PKCS8/组织key/集合→新增Login→更新密码/history→个人Login共享→sync解密；然后设置org reprompt→AutoFill排除→正确主密码授权后更新。
- 真实member fixture：测试SMTP未配置，利用上游“已有账号邀请自动accepted”→accepted不授keys→owner确认→成员编辑；直接用户只读/隐藏覆盖同集合可写group；移除direct后group生效；第二集合可写时多集合AND给有效edit/viewPassword；移除第二集合权限撤读/候选→revoke成员撤回。完整fixture组织最终DELETE（真实masterPasswordHash），其他随机example.invalid测试账号随自有容器数据删除。
- 本轮失败修正：OpenSSL畸形DER测试发现Go PKCS8解析接受尾随，增加ASN.1完整消费验证；清UI列表一度误清旧版nil-vault离线metadata，恢复旧版兼容并全量通过；headless共享取消按钮展开后移出可视范围，测试滚动后确认取消无请求，动作添加稳定key。
- **没跑**：官方客户端/CLI组织互操作、真实窗口/签名安装、真实Keychain/Touch ID/系统AutoFill、SMTP邀请接受、SSO/WebAuthn。输出明确 `official CLI interoperability not requested`；不能把headless、named pasteboard或协议回环说成这些验证通过。

## 自有资源（已经清理）

- 名称 `mygo-card2-01a11503-organizations`；label `mygo-test-owner=01a11503`。镜像ID **sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216**，arm64；inspect版本1.37.4、commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`。
- 初始容器ID **7c321547b7d35b33843580b5720d86fd13f18a1dad98de1207135dc3d9f85401**、loopback32783；owner初次回环通过后只删除该ID，重建同一自有fixture并开启 `ORG_GROUPS_ENABLED=true`。
- 最终容器ID **f37a2f771ddb2b75769e1b801cb231e6de8929619f16ed11906a72d95a4bed10**、loopback32784。bind `/tmp/pi/01a11503-2cba-7259-b2a5-4625ea204991/vw-organization-data` → `/data`；无其他mount。LOGIN/ADMIN_RATELIMIT_MAX_BURST=100，未接生产SMTP或外部vault。
- 清理前按完整ID再次inspect核对label/image/版本/mount；随后 `docker rm -fv <最终完整ID>` 成功，删除精确scratch数据目录，`test ! -e "$TMPDIR/vw-organization-data"`成功，`docker ps -a --filter 'name=^/mygo-card2-01a11503-organizations$'` 无输出。未删其他容器、镜像或用户资源。

## 下一轮直接组织管理产品，不重查已定位基础

已获批准的下一步：组织创建/资料/退出删除、collections访问管理、成员invite/accept/confirm/revoke/restore/role、groups/policies等逐项接真实UI与权限；legacy共享需完整重加密及字段保留。随后继续附件/Send/账号/通知/大库桥、组织导入导出和原整卡逐注册路由矩阵，不能自审或提前结束整卡。

当前适配点：

- `Session.organizationVaultLocked` 每操作派生key，`organizationDocumentLocked`使用内部文档map；`Organizations`返回无wrapped-key的metadata、`ReadOrganizationCipher`/`UpdateOrganizationCipher`、`CreateOrganizationCipher`/`SharePersonalCipher`。`authorizeItem(...,organization bool)`与`withItemSecret`共用验证逻辑，外部个人/组织API仍分开。**不要删除personalDocumentLocked的组织拒绝。**
- `SyncWithCheckpoint`在完整VaultData验证后调用 `appendOrganizationCredentialsLocked`，成功后才返回给现有Swift CAS发布。snapshot/bridge schema本轮未扩展；4MiB桥仍是实际大库限制。
- `cipher_editor.go:adoptVault`新增组织entries、绑定revision和组织草稿清除；`mutateCipher`捕获vault并分派组织create/update/share；`organization_ui.go`类型选择/共享/只读；`item_authorization.go`按条目组织身份调用组织授权；`personal_secret.go`按字段所有权选秘密API；`network.go`锁定/撤销清元数据；`bulk_editor.go/backup_editor.go`过滤组织。

固定源码根仍可复用 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`。tag对象54a40806c990da2def7acd5a3152edc530c59b79、commit7c188967e7a467b19b2757bc3326f9cf3ccae327、归档SHA256d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7。

- `src/api/core/organizations.rs:101` OrgData `{billingEmail,collectionName,key,name,keys?,planType}`；`:183` POST `/organizations`创建owner已confirmed，collectionName必须org-key密文。`:224` DELETE `/organizations/{orgId}`需要PasswordOrOtpData验证；`:237` POST `/{orgId}/leave`禁止最后owner退出。创建并非事务，需后续产品故障处理。
- 同文件`:466` POST `/{orgId}/collections` FullCollectionData `{name,groups:[{id,readOnly,hidePasswords,manage}],users:[{id:membershipID,...}],externalId?}`；成员字段不能用globalUserID。读取/更新路由见顶部routes，不猜路径。
- `:962` InviteData `{emails,groups,type,collections?,permissions}`；`:989` POST `/{orgId}/users/invite`，无SMTP现有账号自动accepted；`:1239` POST `/{orgId}/users/{memberId}/accept`需真实invite token；`:1352` POST `.../confirm` `{key}`是用目标用户公钥包装的org key。用户公钥验证/信任流程产品尚未实现，不能把test fixture的直接公钥访问当产品方案。
- `:1475` EditUserData `{type,collections?,groups?,permissions}`；`:1483` PUT `.../users/{memberId}`；`:2195` PUT `.../revoke`；`:2288/:2300` restore/vnext与restore；`:2451` GroupRequest `{name,accessAll,externalId?,collections,users:[membershipID]}`；`:2507/:2540` POST groups/PUT group。测试仅用于证实协议，尚非正式管理服务API。
- `src/api/core/ciphers.rs:347` POST `/ciphers/create`使用ShareCipherData `{cipher,collectionIds}`；`:985–1115` PUT/POST `/ciphers/{id}/share`，先链接collections再更新cipher，非事务错误必须sync；`:819` PUT `/ciphers/{id}/collections`用于fixture多集合，`:791` collections_v2返回optionalCipherDetails壳。
- `src/db/models/cipher.rs:385/587–656`有效edit/viewPassword和多集合AND/direct优先group；`collection.rs:69–152`实际collectionDetails；`organization.rs:438–534/784`profile字段/has_full_access；`user.rs:264–330`新旧keys兼容字段。

仍完整保留未实现：组织全管理和policy执行；完整legacy/share/copy/附件/FIDO2跨key转换；组织import/export；附件binary/MAC/外部URL禁Bearer/补偿；文本/文件Send seed/HKDF/fragment/send_access；注册/profile/keys/邮箱/主密码/KDF/user-key轮换非事务恢复/账号删除清库/stamp/MFA各provider/SSO/WebAuthn/devices/auth requests/domains/emergency；SignalR MessagePack通知；大库桥/query/binary/Retry-After；完整逐注册路由矩阵；个人双改数组逐行UI与reprompt批量/导出。全部是客户端剩余范围，不可伪装上游不支持。

继续同一卡；本阶段通过不代表整卡完成，不启动Review、不合并。
