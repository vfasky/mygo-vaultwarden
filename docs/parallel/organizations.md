# Board #8：组织条目、导入导出、目录与审计交接

候选状态：本模块已实现并完成下述验证，待独立 Review；尚未合并，也不代表主窗口已完成接线。**主窗口注册归 #14，附件/FIDO2/legacy 完整跨 key 转换归 #13**。没有实现服务器或额外 Public API。

## 分支与范围

本轮从干净 `waku/board-8-new-worktree` / `242f88c97083fc5efff8a93bcad9fbc969da3b35` 开始，按明确授权 merge 固定 `f32f28c29b7bf011fd9e7c48cc1781a6b9732390`，无冲突、保留原提交。该 merge 带入已审查的账号/Send/附件/存储实现；本轮作者改动仅 `internal/vaultwarden/org_*.go`、根 `org_*.go` 和本文。未编辑主工作区、其他工作树、恢复引用、已有 organization/member/collection/group/policy/存储/网络核心。没有子代理。

## 后端契约

| 接口 | 行为与限制 |
|---|---|
| `ChangeOrganizationCiphers` | 单项/批量软删、恢复、永久删、归档、取消归档。官方 `/api/ciphers/delete`、`restore`、`archive`、`unarchive` 和 DELETE `/api/ciphers`。校验组织/成员/账号不同身份、live policy、版本、edit/viewPassword、reprompt。非事务；不从错误推断回滚，不自动重发。 |
| `AssignOrganizationCipherCollections` | 官方单条 PUT `/api/ciphers/{id}/collections`，支持可见集合的选择/取消（移动或分配）。差异集合必须明确可写。任何 HTTP 前必须完成持久 isolate；失败零 HTTP。服务器可能保留不可见关联。结果不得自动撤隔离。不另造 bulk collections API。 |
| `CopyOrganizationCipher` | 官方 POST `/api/ciphers/create`。源/目标组织权限与政策检查、跨 key 完整标准字段转换、新随机 item key；清除副本身份与生命周期，保留源。八种标准类型、custom fields、history、兼容 URI/checksum。附件/FIDO2/未知字段/encryptedByKeyId 在写前拒绝，待 #13 adapter。只读源保守禁止复制。 |
| `WithOrganizationBackup` | GET `/api/organizations/{id}/export`，owner/admin；完整权限、版本、policy、reprompt 检查，借用明文 save 回调后清 byte buffer。输出 `mygo-organization-backup` v1，明确为自有格式。未知/附件/FIDO2 不静默丢弃。 |
| `WithBitwardenOrganizationJSON` | 同一真实 export API 与授权路径，输出官方 `encrypted:false / collections / items` 明文组织 JSON。仅删除可推导的 legacy URI 别名和验证正确、可重建的 URI checksum；非空额外元数据、冲突别名、超出格式支持的字段失败关闭。不是个人 export，不是加密备份。 |
| `ParseOrganizationImport` / `ParseBitwardenOrganizationJSON` | 两种格式独立、严格解析；未知字段、加密文件、重复 ID、跨组织或缺失集合关系拒绝。官方文件允许缺 organizationId，使用仅限预览的内部命名空间，目标授权始终来自明确选择的真实组织。私有 plan 提供复制的集合/条目预览，取消/结束 `Clear()`。 |
| `ImportOrganizationBackup` | POST `/api/ciphers/import-organization?organizationId=...`；显式逐集合映射（已有 ID 或空值新建），类型/政策/权限预检与新 key；归档/删除/folder 元数据不能由官方接口保留，因此写前拒绝。源 ID 不是服务器新 ID。 |
| `OrganizationEvents` | 组织 `/api/organizations/{id}/events`、成员 `/api/organizations/{id}/users/{membershipID}/events`、条目 `/api/ciphers/{id}/events`；owner/admin；显式分页和取消，未知事件数字保留，校验时间/token/返回组织。成员参数不是 global userID。空结果不证明服务器已启用日志。 |
| `CollectOrganizationEvents` | POST **`/events/collect`**；仅真实客户端动作对应的支持事件；不是 `/api/events/collect`。成功不证明服务器保存审计。 |
| `WithOrganizationAPIKey` | owner、主密码 proof、显式确认；官方 api-key/rotate-api-key。secret 仅借给回调；clientID=`organization.{id}`。首次读取可能创建，轮换撤销旧 key。 |
| `ImportOrganizationDirectory` | 官方组织 client credentials → 唯一 Public POST `/api/public/organization/import`，不向 Public route 发送 user token。owner/UseGroups、邮箱/externalID/群组引用检查，明确 overwrite。任何 HTTP（含管理读取/token）前持久 isolate，失败零 HTTP。 |

状态操作 refresh 后再次验证快照 authority；本模块派发 guard 同时检查 epoch/revision。缺失、过期或失败 checkpoint receipt 不复活旧快照；同内容且有效的新 receipt 可继续无 reprompt 操作，旧 reprompt grant 始终失效。

## 派发后的真实核对

`OrganizationOperationResult.ImportReconciliation` 含 `ReadCompleted / BeforeIDs / AfterIDs / AddedIDs / Items`。派发后执行**新的认证 GET /api/sync**，独立解析并叠加 pending policy；不能调用会复用操作内缓存的 `operationPoliciesLocked` 冒充新读取，也不接纳 snapshot/发行 offline receipt/撤隔离。

逐项仅在新增服务器 ID、唯一生成 key、完整内容字段、类型、reprompt、明确映射的集合全部一致且仍有权限时 `Verified=true`。重复源内容、缺少新建集合映射、读失败/取消/撤权/无法匹配保持 unknown。HTTP 200 可能逐项失败；HTTP 错误后仍在未取消的上下文中尝试读差异。`Applied` 不据 HTTP200 置 true，`ReconcileRequired` 保留。并发写入可产生额外 AddedIDs；不是事务 receipt，不能自动重发。

`OrganizationDirectoryResult.Reconciliation` 含 `Before/After` 管理快照和逐成员/群组/overwrite 行。隔离后只借用本次操作初始已认证 owner 身份，用既有内部管理读取 GET users、GET groups、GET group/users；再次核对自身 membership/global user/owner/confirmed，所有成员和群组身份分开。前后快照核对邮箱、externalID、成员状态、群组名称及完整成员关系；overwrite 缺席成员也显示，owner 受服务器保护时不能冒充撤权成功。读失败或状态不符保持 unknown。管理读取不清 marker/pending、不调用普通 Sync 接纳逻辑。

## #14 原生接线

所有构造器均无全局 app 映射，提供 `View(*ui.Context)` / `Close()`；操作回调绑定当前 Session、认证 VaultData、scope/revision lease 和真正的 checkpoint/isolation 持久实现。`dispatch` 必须回到 UI 线程，并由宿主触发刷新。锁定、sync 或 scope 变化统一 Close，丢弃迟到回调。

| 组件 | 宿主注入 |
|---|---|
| `newOrgOperationsPanel` | 当前组织列表与状态 execute；reprompt 条目走单项授权入口。 |
| `newOrgEventsPanel` | 来自业务目录选择的组织/成员/条目 query、fetch；时间和分页表单。 |
| `newOrgCopyPanel` | 已认证 source、目标组织集合 choices、复制回调；回调在执行前获取所需单项 reprompt 授权，取消则零写。choices.Name 应提供用户可区分的组织/集合名称。 |
| `newOrgCollectionPanel` | 已认证条目、同组织可见集合、当前关联、分配回调；显示持久隔离与失去访问后果。 |
| `newOrgImportPanel` | 由文件入口读取并独占移交的 plan、准确格式名、仅目标组织的集合 choices、建集合权限、import execute。显示类型/名称预览、逐集合映射、归档/回收站阻止提交、确认、取消与新读取逐项结果。运行期间 worker 独占并 Clear plan，Close 不并发 Clear。 |
| `newOrgExportPanel` | 组织名称、owner/admin 可用性、安全保存回调。明确选择 MyGo 或官方 JSON，路径、明文风险与确认；不要接普通 os.WriteFile。 |
| `newOrgAPIKeyPanel` | owner 可用性、`WithOrganizationAPIKey` adapter；密码输入、读取/轮换确认、隐藏默认/显式显示/清除，关闭与迟到回调清除密钥。禁止日志/持久保存。 |
| `newOrgDirectoryPanel` | owner/UseGroups、目录回调；邮箱/externalID/撤权行、群组名称/成员选择、删除预览行、overwrite 明确确认、临时 key、进行中/取消/部分结果。 |

文件 adapter：`readOrgImportFormatPlan(ctx,path,official)` 使用现有受限安全文件读取；`exportOrgBackupFormatFile(...,confirmed,official,...)` 使用已有目录 descriptor/no-follow、0600 暂存、原子 no-replace 发布，不覆盖已有文件。旧 `readOrgImportPlan` / `exportOrgBackupFile` 保留为 MyGo 格式 wrapper。宿主原生文件选择器传入路径。回调不可在 Session 锁内重入 Session。

所有表单完成或不确定失败后冻结，不自动重试；新构造器必须使用新认证状态。Go string 和 UI 字符串历史副本不能保证物理归零；密码/key 的借用 byte slice 均清除。

## 验证证据

已通过：

- `go test -tags headless ./...`
- `go test -race -tags headless ./... -run 'TestOrg' -count=1`
- `go vet -tags headless ./...`
- `MYGO_ORG_MODULE_TEST_URL=http://127.0.0.1:32797 go test ./internal/vaultwarden -run '^TestLiveOrgModule$' -count=1 -v`
- `MYGO_ORG_MODULE_TEST_URL=http://127.0.0.1:32797 go test -race ./internal/vaultwarden -run '^TestLiveOrgModule$' -count=1 -v`（同一自有实例，race 回环也通过）

新增/扩展测试覆盖：官方明文严格解析/字段/集合/unknown/FIDO2，真实新读取、唯一项确认/重复内容 unknown、HTTP200缺项不能全绿，目录部分结果/overwrite/读取撤权/身份歧义、refresh/checkpoint失败/旧receipt/有效receipt、reprompt有效/过期/跨条目、表单确认/取消/late key/运行期间plan寿命/部分结果/不自动重发。本轮测试发现并修正了操作内 policy 缓存不能用作新读取，以及 refresh 后旧 authority 检查不足。

真实镜像：`vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055`，镜像标签 version=1.37.4 / revision=7c188967e7a467b19b2757bc3326f9cf3ccae327。使用 create→记录完整ID→start→inspect/port，ownership label 和仅 loopback 随机端口，volatile 自有数据，无外发邮件或生产账号。

第一次受控实例 `be8b14ecc256d5b8db7eb35007e0e7a004e4a1d8ef90d19083d19bbf2f097f08` 启动成功，owner 回环通过；扩展群组测试时因默认 ORG_GROUPS_ENABLED=false 得到服务器 400。按协调者额外明确授权核验 ownership、保存有界日志并按完整 ID 清理（含匿名卷），以同 digest 新建 `1493719d78abbb67fd69d6d8f9b3eb61d452ec62549e1aaddc45cf8c65771177`，name/label=`mygo-board8-groups-01a1174d`，启用 ORG_GROUPS_ENABLED 与 ORG_EVENTS_ENABLED。

真实通过场景：owner 状态/复制/导出导入/集合分配/永久删；member/admin 可写、只读/隐藏拒绝、群组继承复制、撤权后旧快照拒绝；admin 导出和事件、member 入口拒绝；MyGo 与官方明文 JSON 经真实 export/官方 import 回环；新读取确认唯一安全笔记及重复登录项 unknown；组织/成员/条目审计、collect；API key读取及轮换；Public目录成员+群组导入并新读取验证完整关系。一次性 fixture 的 isolate 为 no-op，仅证明本模块调用协议；产品必须接持久隔离适配器。

两实例均已按完整 ID 执行 `docker rm -fv` 清理自有容器及匿名卷。最终有界日志保存在本会话 scratch 的 `org-fixture-final.log`；未将凭据、密钥或测试账号数据提交到仓库。

**未验证/边界**：本机 `command -v bw` 无可执行文件，未执行 CLI 互操作；未运行真实窗口视觉/Keychain/AutoFill。附件/FIDO2/legacy完整跨key转换交 #13，当前安全拒绝；主窗口接线与真实持久隔离交 #14。导入新建集合无服务器新ID映射时保留 unknown，需用户检查新快照。权限校验到写入间仍存在服务端非 CAS 的并发窗口。
