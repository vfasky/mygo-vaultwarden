# Board #13：密码库迁移、完整资源备份与编辑边界交接

基线 `0ca1a9973e7502f238ebaebb395f745707a280f2`，工作树 `waku/board-13-new-worktree`。附件 #3、组织 #8、存储 #9 的接口已读并复用。本候选完成下述实现与验证，**提交不等于合并，仍须独立 Review**。公共主导航与组织模块宿主接线归最终集成 #14；这里没有改主窗口注册、账号、Send、MFA、通知、Swift 存储 schema/ABI 或主目录恢复引用，没有子代理。

协调者明确追加授权的路径：`internal/vaultwarden/org_transfer*.go` 的字段转换/资源复制及必要 reconciliation 适配；`attachments.go`、`attachment_access.go` 的独立只读回收站读取用途；根 `org_business_ui.go`、`org_transfer_files.go`、`org_resource_ui.go` 的资源表单与安全文件适配；`sync.go`、`client_test.go`、`macos/Shared/VaultCredential.swift`、`macos/Tests/VaultURITests.swift` 的 StartsWith 支持。原默认 URI 共享向量的两个 Go 测试与一个 Swift 测试同步把 2 加入支持集，新增共用向量文件。没有重写附件 crypto/multipart/signed transport，也没有更改存储格式。

## 已完成的迁移与加密边界

`cipher_migration.go` 提供独立的完整转换器。常规同 item-key 编辑仍使用原转换器，保留 opaque FIDO2/未知扩展；跨 key 复制、legacy 共享与 MyGo 明文备份才使用经过 schema 审计的完整转换器。

- 标准八类、name/notes、URI/派生 alias/checksum、custom name/value、全部 passwordHistory 逐字段转换；不把账户 user key 包装给组织。
- FIDO2 的 `credentialId/keyType/keyAlgorithm/keyCurve/keyValue/rpId/userHandle/userName/counter/rpName/userDisplayName/discoverable` 都按 EncString 转换，`creationDate` 保持原字符串。可选字段 absent/null 保留。每项最多 100 个凭据；未知 schema、坏 MAC/类型和超限在写前具体失败。这里是通行密钥**数据**的保全，不是系统 passkey 注册/认证实现。
- 只有 legacy `login.uri` 而没有 `uris` 的已知格式会在跨 key 写入时形成首条 URI 与可重建 checksum；冲突 alias 不静默丢弃。1.37.4 响应总把 `login.uri` 设为首条 `uris.uri` 或 null，恢复分类及组织 import reconciliation 仅对这一官方派生字段做规范化；其他字段及未知 null 扩展仍参加精确比较。
- legacy 无 item key 的个人共享生成独立随机 item key。已有 attachment key 的二进制不重加密，只转换 filename 与 key wrapper。真正写入使用官方 `attachments2[id]={fileName,key}`；响应中每个 wrapper 必须一致，否则保留未知结果。
- 即使已有独立 item key，**没有 attachment key 的文件仍按 owner user/org key 加密**。这种附件不能直接随所有权改变；旧直接 share 入口现在也会阻止该损坏路径。同 item-key 且附件有独立 key 的 opaque 保持路径继续保留。

## 无 key 文件升级与非事务共享恢复

个人原生编辑页有“准备旧附件的安全共享迁移”。`CipherAttachmentMigrationInfo` 返回已认证的完整文件名和准确 ID。文件名相同不代表同一文件。

1. `UpgradeLegacyCipherAttachment` 在原个人条目下调用公开 Download，完整 MAC 后暂存到本次 0600 私有 spool，再调用公开 Upload 创建独立 attachment-key 的替代文件。始终保留原件，不自动删、不自动 share。
2. 用户同步并重新打开、取得新 reprompt 授权后，明确选择原、新两个 ID，调用 `VerifyAndDeleteLegacyCipherAttachment`。它从服务器下载两份、验证 MAC、比较长度和 SHA256，及时消费各自短能力，再由公开 Delete 的新权限/精确文档检查发一次 DELETE。`OriginalDeleted` 表示 DELETE 回执；UI 标注“删除回执”，仍要求同步核对。`DeleteAttempted` 不冒称请求一定已到服务器。
3. 中断、关闭、上传响应未知时保留已知 attachment ID 和阶段。旧、新服务端文件是恢复依据，不依赖重开后仍存在的临时明文。所有旧件处理完后才进入共享。组织旧无 key 文件的复制/备份则经同一公开下载接口使用已确认的 org key，再以新 attachment key 恢复到目标；不授予组织账户 key。

固定 1.37.4 在 `cipher.save` 前逐个保存 `attachments2`，不是事务。因此 legacy 带附件的最终 share 还需要独立的持久恢复材料：

- `SharePersonalCipherWithRecovery` 要求 `persistRecovery` 成功，才派发 share。文件为 `mygo-legacy-share-recovery` v1，扩展名 `.mygoshare-recovery`；完整旧文档、目标 DTO/attachments2、额外 user-key 包装的新 item key、prepared 阶段均在 type-2 认证密文内。外 header 与内 payload 的 server/account/cipher/目标 org/opID/原 revision 必须一致。
- payload 最大 16 MiB，文件最大 32 MiB，JSON 深度 32；严格拒绝重复键、错版本、篡改、错 scope/key。编码后用重新解包出的 key 校验材料可读。生产原生 Save 走逐目录 no-follow、0600、文件 fsync、原子不覆盖 link、目录 fsync；落盘/取消/租约检查失败是零 share。目录 fsync 失败时文件可能已存在，但仍不发 share，也不删除该目标。
- 旧无恢复回调 API 对 legacy 带附件仍拒绝；原生共享已接新 API，并在保存前后查当前存储 lease。测试中的借用回调不代表生产可以使用 no-op 持久化。
- 导入导出页可打开恢复文件。`InspectCipherShareRecovery` 先验证文件和当前认证快照，再新读 `/sync`，逐项分类旧个人/新组织/外部修改/缺失及旧/新包装/远端新增。签名 URL 可变化；附件 size/未知扩展等变化不会被忽略。
- `RepairCipherShareRecovery` 只有用户明确确认、最新快照与新读取一致、当前权限/reprompt/policy/pending 有效、整条 cipher 与原/目标版本相符时才修包装：仍属旧个人则修回旧 wrapper，已属新组织则修向新 wrapper。保留当前全部 cipher 内容，不强抢组织所有权，不盲覆外部修改，不自动重发/删除文件。修复回执后必须再 sync/分类。
- **文件依赖当时的 user key**，未实现旧主密码/旧 master-wrapped user key 独立解锁。账号 key 轮换或删除后不保证可恢复；UI 已要求先处理未决迁移，最终账号集成须保留此限制。文件不自动删除。

## 完整资源备份与恢复

自有 `.mygoresources` 为 `mygo-vaultwarden-resource-backup` v1，未压缩 ZIP，明确不是官方 Bitwarden JSON。内含既有 MyGo 个人/组织 metadata 与独立 `files/000000.bin` 等数据条目；manifest 保存 source cipher/attachment ID、原文件名、长度、SHA256。组织资源复制另有明确 copy source ID/digest，不能伪装组织导入文件。

硬界限：最多 10,000 个文件、每文件 512 MiB、文件合计 1 GiB、manifest 32 MiB，外文件最多 1 GiB + 36 MiB；只接受 Store、普通文件、确定编号路径、全部且唯一的清单引用。拒绝压缩炸弹、symlink、重复/未声明条目、错哈希/CRC、跨组织 header/metadata、越界/缺失引用。现有上传接口不接受路径分隔符、NUL/CR/LF 或过长 filename；这种名称会具体报错，不做静默 basename 降级。

`WriteResourceBackup` → 私有 stream stage → `PublishResourceBackup`：

- 单个下载仍完整验证 MAC、大小、快照、权限、政策、reprompt，再即时消费短发布能力；文件不进入 JSON/native 桥。
- 所有文件结束后，另起一次新的认证 sync，核对全部所选源 ID、精确文档、viewPassword、组织成员身份/角色、policy/pending，再发 30 秒整体发布能力。不会把首个文件能力续期，也不驻留每文件一份完整 cipher。
- 最终提交仍核对 Session、epoch/revision、整库来源 hash、所有保护项 grant 的最早到期时间、取消/关闭。个人原生提交前再核对当前 Swift storage lease；组织安全适配器显式要求 `lease` 回调，在暂存前与提交时核对。只保存新文件，不覆盖。
- `DownloadAttachmentForBackup` 是单独的只读用途，可读当前有权的回收站文件；普通列表/下载及上传/删除仍保持原 trash 限制。不能 restore 源条目来偷做导出。

`ParseResourceImport` 接管并关闭输入，拷入本次私有不可变 spool，**预检所有 metadata/文件/hash/CRC 后**才返回 plan。关闭、取消及结束精确清理自己的 spool；不使用清单路径解压到用户目录。

恢复是可见多步骤流程：

- 个人 `PersonalRestoreMetadata` 创建 metadata，含附件的 trash 状态延后；`ImportEntry.SourceID` 明确关联可确认的新服务器 ID。错误/未知创建不重试，也不按名称猜对应关系。
- `UploadResource` 每次仅向明确选择且当前有权的目标上传一个文件，返回可确认的 attachment ID/阶段；之后正常 sync，再用 `VerifyRestoredResource` 下载核验真实文件名、大小和完整内容。响应未知可同步后填入核对过的 ID，不能重复上传。
- 恢复原回收站/组织元数据状态前再核验对应源的全部文件。个人 trash 的成功回执不直接标为最终完成，等待新 sync 的已认证条目 metadata。组织 folder/archive/trash 各有独立恢复、sync 和检查动作。
- 组织 `OrganizationRestoreMetadata` 暂缓 folder/archive/trash；资源 plan 保留原值，并在原生预览显示。组织 folder 是当前用户的个人分类引用，须明确映射到现存目标 folder ID，不把此引用假称组织集合或自动创建其他用户的个人文件夹。
- 关闭后可重新打开原资源文件并选择“仅继续附件恢复”，明确填写已创建目标 ID。复制的临时计划关闭后清理，但源记录与文件始终保留；可重新从源导出资源文件，再恢复到已存在目标，不能再次盲创建副本。
- `CopyPersonalResourceMetadata`、`CopyOrganizationResourceMetadata` **只开始**完整复制；要求完整文件 plan 与当前源一致，创建新随机 item key，后续所有文件必须恢复/核验才算完成。个人编辑页已进入实际资源恢复界面；组织提供对应组件/适配器，供 #14 宿主注册。

## 原生组件与 #14 接线契约

个人已有导入导出入口扩展资源格式、逐项 reprompt、保护的历史/冲突显示、legacy 升级和共享恢复；没有另造主导航。

组织宿主应使用：

| 组件/适配器 | 要求 |
|---|---|
| `newOrgExportPanelWithResources` + `exportOrgResourceFile` | 区分普通 MyGo/官方 JSON/完整资源；session/vault/org/grants/confirm、真实 checkpoint 持久化，**非 nil 且真实的 storage scope/revision lease 回调**。不做生产 no-op。 |
| `newOrgCopyPanelWithResources` + `prepareOrgResourceCopy` | 先全文件验证，再创建 metadata；准备与派发前核对真实 lease。`resourcesReady` 接管 plan，包括“已有计划但创建结果未知”情况，转到资源恢复面板；原件保持。 |
| `readOrgResourceImportPlan` / `newOrgResourceImportPanel` | 完整文件预检、集合映射、明确状态延后。metadata 新读取确认后，只自动使用 `ImportReconciliation.Items` 中 `Verified=true` 的 SourceID→ServerID，其余保留人工核对。回调接管资源 plan。 |
| `newOrgResourceRestorePanel` | 单次上传、取消、未知 ID 保留、刷新门控、逐文件下载核验、folder/archive/trash 的显式恢复与独立检查。copyOnly 不恢复源的归档/回收站/个人 folder。 |
| `executeOrgResourceFile` / `executeOrgResourceState` | 回调绑定**明确 targetOrgID**，先验证目标确属该组织；当前 vault/grant/persist 来自宿主真实认证状态。刷新必须正常 sync→持久 publish→接纳 receipt，不能只调裸 Sync 或复用旧快照。 |

dispatch 必须回 UI 线程；lock/scope/revision 变化 Close 当前表单、取消操作、丢弃迟到结果。运行期 worker 独占 plan，Close 等回调后清理，不能并发 Clear。资源步骤/适配器有 5 分钟上下文；30 秒 reprompt 不因网络/保存窗口延长，过期必须重新授权。大量保护项可分批，不能把某个 item grant 当作整库授权。

## 导出授权、历史和无 ID 数组冲突

- `ExportPersonalBackupAuthorized` 接 per-item grants，逐项和返回前检查；`PublishPersonalBackup` 在短原子文件提交前重新核对。原有无 grants API 对 reprompt 项继续拒绝。原生选择单项或批量均走相同保护流程。
- 历史显示改为 `WithCipherPasswordHistory` 借用已保存内容、同 `authorizeSecretDisplay` native lease、30 秒与 reprompt 的较早期限。隐藏、到期、失去当前快照、锁定会撤销显示；未保存删除不伪装成服务端历史变化。
- URI/custom 双版本数组不自动按 index 配对。比较面板默认隐藏秘密，可经同 native display lease 短时显示双方真实逐行内容；N 个本地行逐一明确选择“不应用 / 独立追加 / 对应远端第 N 行”。未选远端行及新 unknown 保留，重复/越界对应拒绝，unknown 冲突拒绝而不覆盖。删除留到最新表单明确执行。
- `ApplyPersonalCipherComparisonRows` 只产生新草稿，不发送写请求；绑定 Session/revision/文档 hash/当前 grant，结果与可复用 plan 脱离。字段级旧比较 API 保持兼容。

## URI 执行范围与官方依据

StartsWith=2 已实际支持，官方固定代码是 `targetUri.startsWith(this.uri)`：原始字符串、大小写敏感、无 trim/lowercase/补 scheme/slash、无 percent decode、无 fragment/port 改写。

Go 保留非空合法 UTF-8 原始前缀，不给予 host/baseDomain/快捷候选。Swift 仅在系统明确标为完整 URL、目标属于现有 http(s)/无 userinfo 范围时执行 UTF-8 **字节**前缀比较；不用 Swift `String.hasPrefix` 的 Unicode 规范等价比较。prefix 和 target 均限制 8192 UTF-8 字节，ASCII 空白/控制符拒绝。部分 scheme/host/percent 字符串作为字面前缀保留，不能用更严格 host 匹配偷换含义。domain 标记及 quick identity 不降级。

0/1/3 保持既有行为，Never=5 始终不产生匹配；Regex=4 与等价域名**尚未新增执行支持**。协调者明确将这两项交 #14 评估：不拿 ICU/RE2 冒充官方 JS 正则，也不单边扩 Go 候选而跳过 Swift 的受信来源复核。0–5 的原始规则继续在编辑、复制、备份里保留。新 Prefix 仍需真实 sourceIndex、显式/继承 match 对应和 policy/pending 复核。

固定来源：

- FIDO2 字段模型：[clients 5983f56c fido2-credential.ts](https://github.com/bitwarden/clients/blob/5983f56ce0cf924eea56c7d8f066f7885825a7ce/libs/common/src/vault/models/domain/fido2-credential.ts)，并核对 [SDK 39dbb510 login.rs](https://github.com/bitwarden/sdk-internal/blob/39dbb510f5eae82f5cbfd527b0f70a01d5626ec1/crates/bitwarden-vault/src/cipher/login.rs)。
- legacy MAC 独立向量沿用已验证 [SDK 39dbb510 attachment.rs](https://github.com/bitwarden/sdk-internal/blob/39dbb510f5eae82f5cbfd527b0f70a01d5626ec1/crates/bitwarden-vault/src/cipher/attachment.rs) 的 `test_attachment_without_key`；本卡未改其 crypto。
- attachments2 先于 cipher.save、GET 附件读取授权：[Vaultwarden 1.37.4 ciphers.rs](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/ciphers.rs)，特别 517–576、1034–1052、legacy `save_attachment` 分支；GET 只读且不排除 deleted。
- 派生 URI alias：[Vaultwarden 1.37.4 cipher.rs 259–279](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/db/models/cipher.rs)。
- 精确 StartsWith/Regex/Never 语义：[clients 5983f56c login-uri.view.ts 149–189](https://github.com/bitwarden/clients/blob/5983f56ce0cf924eea56c7d8f066f7885825a7ce/libs/common/src/vault/models/view/login-uri.view.ts)；产品说明：[URI match detection](https://bitwarden.com/help/uri-match-detection/)。

## 验证证据

工具链由 `bash scripts/resolve-go.sh` 解析为 Go 1.27.1；构建、npm/CLI、测试容器日志与临时产物只在本会话 scratch。已执行：

- `go test -tags headless ./...`、`go test -race -tags headless ./... -count=1`、`go vet -tags headless ./...`、`go build -o "$TMPDIR/mygo-vault-finishing" .`。
- `swift test --package-path macos --scratch-path "$TMPDIR/swift-finishing"`：73 tests / 0 failures；`xcrun swiftc -typecheck -swift-version 5 -module-cache-path "$TMPDIR/swift-finishing-modules" macos/Shared/*.swift macos/AutoFill/*.swift` 通过。
- `uri-prefix-cases.json` 的 26 个向量由 Node 原生 `startsWith` 按固定官方 guard 独立核对。Go/Swift共用这些向量，另有 8192/8193 字节、多字节边界、NFC/NFD、非 BMP/ZWJ、escape/port/fragment、sourceIndex/默认政策/pending 等测试。
- `MYGO_VW_FINISHING_TEST=1 go test -race ./internal/vaultwarden -run '^TestLiveVaultFinishing$' -count=1 -v`：自有固定 **Vaultwarden 1.37.4**，个人 legacy 无 item-key + FIDO2/custom/history/URI、空 attachment-key v1 文件→安全升级→attachments2 share；个人/组织资源 copy、组织 staged import、逐文件真实 MAC/内容验证、个人/组织 trash 只读导出且源仍 trash。组织额外构造 owner-org-key legacy 二进制、与独立 item key 不同的文件名密钥，并使用同名不同内容文件验证 ID 对应。
- 镜像固定 `vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`；实际 image `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`，version `1.37.4` / revision `7c188967e7a467b19b2757bc3326f9cf3ccae327`。每次 create 独占 name/label、loopback 临时端口、volatile 数据、example.invalid 账号；按完整 ID + label 验证后 `docker rm -fv`，没有操作他人容器。
- CLI 仅以 `npm --prefix "$TMPDIR/bitwarden-cli" ... @bitwarden/cli@2026.5.0` 安装到 scratch，实际 `bw --version` 为 2026.5.0。设置 `MYGO_BW_CLI="$TMPDIR/bitwarden-cli/node_modules/.bin/bw"` 的同一 live 测试通过七种官方兼容类型的 CLI import/list 解密/export/MyGo 回导。CLI 使用独立测试账号、隔离 appdata、临时 TLS relay 与会话环境变量，不向参数/日志写 token。资源 ZIP/FIDO2 扩展没有冒称官方 JSON 能往返。
- 新增测试覆盖：FIDO2 字段/新旧 key/MAC/null/普通编辑 opaque；备份逐 item grant、到期/取消/发布一次性；新文件 ZIP 预检与最终 fresh 权限撤销；legacy 上传未知不删、坏旧/新 MAC、不同内容、取消/撤权；attachments2 已存而 cipher.save 失败、响应丢失、Session 重建、旧/新/混合分类、外部变化/未知 null/缺失/篡改；真实 headless 表单确认/取消/plan 生命周期/明确行对应/短时敏感显示；资源文件 8 MiB 以上流、0600、不覆盖、取消清理、保留源权限错误。

过程中确实出现并修正了失败，未把失败记为通过：legacy fixture 的 v1 multipart 需要显式空 key 字段；服务端附件包含已知 `object:"attachment"`；服务端派生 URI alias 造成恢复/import 比较误报；FIDO 测试期望值被 fixture 自身加密修改；旧 CLI helper 漏了每次 Sync 后的 Go-only receipt；新增 UI fixture 漏 custom type；一次编译期 unused import/同名常量。修正后重新运行相关回环与全量检查。

## Review #35 后的资源表单续接修复

本次仅针对 `10cb58f` 的 P1 回归增量，保留上文迁移成果。协调者明确批准 `network.go` 的最小同步续接接线及可注入 dispatcher/storage 的 controller 测试入口；生产仍使用原生 `window.Update` 和 `callStorage`。未改附件协议、Swift、账号或主导航。

- 在 UI 线程发起同步时捕获现有资源表单、不可变资源计划、具体 Session、账号 scope、原 revision/snapshot ID 和 epoch。只有原生命周期有效、既有存储发布回执检查及 `AcceptAuthenticatedSnapshot` 成功、应用正式采用新 vault 后，`reconcileImport` 才消费该续接。裸 reconciliation/status、发布失败、旧计划、锁定、换账号/Session/表单、迟到回调均不授予新 revision。已认证且同 snapshot 的 token checkpoint 单独经既有 adopter 续接，不把 checkpoint 当文件核验。
- 保留 SourceID→TargetID、已知附件 ID、未知/待同步/已核验阶段；同步不会创建 metadata、上传文件或把待核验变成已核验。续接清除密码输入及旧导出 grants。每次显式文件操作仍重新读取当前个人目标、校验归属/权限/policy，并为 reprompt 取得新授权；权限错误显示在对应文件行，不被随后全局同步状态掩盖。
- controller 自身拒绝重复上传已执行/未知结果的行，不能只依赖按钮 disabled。没有附件 ID 时不会核验；用户明确核对 ID 后才下载校验。授权阶段尚未调用上传的失败不伪装成已上传。
- 永久 `backup_resource_controller_test.go` 使用真实 Session 和 HTTP 测试服务器、排队 UI dispatcher、模拟 CAS 存储回执，执行真实 `importBackup` / 完整 copy / `runResourceRestore` / `syncVault` / `reconcileImport` controller。个人创建（含 token checkpoint）→采用 sync→第一个上传→采用 sync→下载校验→第二文件完整链，重新打开仅恢复和复制均覆盖。另覆盖未知结果/ID/不重放、真实表单继续/取消/错误显示、发布失败、清除或失效计划、epoch/账号/Session/外部变化、锁定迟到回调，以及目标缺失/组织迁移/只读/隐藏/reprompt 的重新检查。
- 本次执行：`go test -race . -run 'TestResourceController|TestResourceForm|TestNativeEditor|TestReprompt|TestStale|TestRefreshCheckpoint' -count=1`；`go test ./...`；`go vet ./...`；`go build -o "$TMPDIR/board13-resource-fix" .`。所有最终检查通过。测试最初暴露重新解锁 Session 尚未完成首次 online sync 的夹具错误，已改为恢复表单从已接纳 online sync 开始；个人 metadata 导入另保留首次 token checkpoint 覆盖。测试没有把模拟存储当作真实 Keychain/Swift 端到端验证。

本增量未重新执行无关 CLI、Vaultwarden 容器及 Swift 全套，未新增平台或硬件支持声明；上述旧轮次证据仍仅代表旧轮次实际执行。

## 尚未声称的结果与最终集成边界

- 真实窗口/Open/Save 视觉、Keychain/Touch ID、签名安装、系统 AutoFill 实填及硬件 passkey 均未实测。headless、Swift 测试存储与 Go-only receipt 不替代这些平台验收；#14 还需注册组织新组件和真实 lease/持久化/刷新回调。
- Regex 与等价域名按协调决定留后续；没有宣称所有 URI 模式已实装。StartsWith 的 domain/quick 限制是实际执行边界。
- 私有格式与 restore 是多请求过程，不能声称原子或自动回滚。服务端不是严格 CAS：检查到请求间仍有竞争窗口；同 ID/同 key/同 size 的二进制被其他客户端并发替换，服务器无原子 compare-and-delete 协议。必须保留源/备份与逐阶段核对，不能据 HTTP 错误猜删除/创建结果。
- 资源硬界限不等于满 1 GiB 的实测 RSS/吞吐保证。长操作仍受 grant、整体上下文及服务器能力限制；临时明文只保证访问权限和生命周期清理，不保证 SSD 安全擦除。Go/UI 字符串也不承诺物理归零。
- 全局旧 coverage/README 的历史 INCOMPLETE 描述由最终集成统一更新。本页为本卡增量：legacy/FIDO2/附件完整数据流程、reprompt 导出与历史保护、显式无 ID 行冲突、StartsWith 已实现；整应用最终目标仍由主导航和平台验收统一判断。
