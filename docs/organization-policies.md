# 组织策略执行迁移

**INCOMPLETE — 整卡未完成，禁止Review/merge。** type5/15的已实现保存与读取路径不等于完整12类策略消费或原生管理；原完整API范围保持不变。

## 当前生产路径与能力来源

| 路径 | 生产入口和约束 |
| --- | --- |
| 在线写入策略 | `policy_execution.go`从本Session认证GET `/api/sync`建立私有`operationPolicies`，仅活在单次操作。个人create/update/copy/import、个人state/bulk/partial与组织create/update/share已接；个人type5保存限制按owner/admin豁免，type15个人并集/组织自身范围，state核对服务器真实ID/type/归属/权限。其它适用策略仍待迁移。 |
| 同步预投影 | `SyncWithCheckpoint`先撤旧离线许可、推进epoch，再校验profile/key/完整policy/成员数组，解密前排除受限Login。`decodeOrganizationVaultLocked`与`organizationDocumentWithPolicies`仅为内部认证解码；不能授权公开VaultData读取。原始加密sync完整保留。 |
| 认证解锁 | `main.go:completeStorage`核验list/listPassword operation、UI epoch、available、scope、expected revision后，`restoreUnlockedSession`调用`RestoreSessionFromAuthenticatedSnapshot`。缺policy/旧schema不能安装离线许可；可仅恢复网络Session以成功sync迁移。绝不采用未经策略约束的`reply.Items`兜底。 |
| 发布与采用 | `network.go:syncVault`核验publishVault回执的新revision、scope、SnapshotID非空及旧隔离标记，在当前UI epoch回调中安装`AcceptAuthenticatedSnapshot(reply.Vault, revision)`；不以未经回执校验的公开sync对象授权。失败关闭/撤销会话显示。`cipher_editor.go:adoptVault`只调用`ValidateAuthenticatedSnapshot`后读取，不能自行签许可。 |
| 离线读取 | `vault_data.go`、`item_authorization.go:personalDocumentLocked`、`organizations.go`、`folders.go`、`organization_isolation.go`、`backup.go`、`cipher_bulk.go`统一校验完整快照许可。列表解密前过滤type15；单项拒绝受限类型。秘密/TOTP/历史与reprompt经同一读取链，type5不禁旧个人读取。导出/bulk继续拒绝reprompt，完整逐项授权产品流程仍缺。只读组织仍按viewPassword/reprompt与集合权限限制。 |
| token checkpoint | Swift `saveSession`保持SnapshotID与vault内容，仅更换session和revision；真实bridge在`withCurrentLease`中返回vault。Go `saveSessionCheckpoint`核验同SnapshotID/scope、新revision后调用借用checkpoint的`AcceptAuthenticatedReceipt`。内部摘要和previous revision匹配才可续接已有policy，回调不取得Session.mu；`persistPendingLocked`等待安全落盘后更新revision/epoch，旧item grant一律失效。公开binder、无回执、异内容、坏scope/revision不能创建许可。无旧许可的网络迁移checkpoint只保存token。 |
| 隔离/恢复 | 通用`checkpointLocked(isolate)`无论成功/失败都撤旧policy与item grant，不能充当token续接。群组修改在隔离前取得本次操作授权key，隔离后仅用于同一次目录核对，结束清除；不重新授离线读。`adoptOrganizationSnapshot`核验scope/new revision/新SnapshotID、目标marker及其它marker后安装回执。普通sync保留隔离。恢复使用`ValidateOrganizationRecoveryCandidate`，私有候选绑定session/epoch/完整内容hash，只证明网络同步中的目标成员确认，不授离线权；真正restore持久回执才恢复。 |
| Swift旧候选/独立AutoFill | `SnapshotPolicy.swift`严格检查重复JSON key/深度、profile、完整成员/policy数组一致性与type15。个人使用所有confirmed组织并集（本机隔离和server disabled不豁免个人），组织仅自身且confirmed/enabled；deleted/archived/reprompt/viewPassword=false与隔离排除。非demo旧payload缺vault/完整policy返回零候选，保留加密payload供主应用网络迁移。`SnapshotPayload.safeCandidates`同时用于主应用解锁、扩展lease和`openSnapshot`；publish明确保存过滤后的空数组；既有current lease/锁定边界保留。Xcode扩展源列表已包含新文件。 |

`snapshot_policy.go`的构造器是**受信控制器特权跨包入口**，不会自行验证Swift凭据，也不是抵御任意同进程Go代码的沙箱。复制sync/quarantine后解析policy和组织key链，完整VaultData哈希、scope/revision/epoch与解析树只保存在Session私有上下文；失败先撤旧、对象后改无效。普通RestoreSession只恢复网络凭据，BindSnapshotRevision不创建权限。Close/Revoke/替换sync撤旧；网络失败不删除上一份加密磁盘快照，但不能把旧快照当新授权。

## 协议依据与仍存在的竞争窗口

- Vaultwarden1.37.4 commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`：`src/api/core/ciphers.rs:162–169` confirmed policies与accepted+confirmed policiesNew；`:409–426`个人所有权禁止create/update但允许delete/share；`src/db/models/org_policy.rs:275–304`按confirmed成员角色；`src/db/models/organization.rs:438–532`profile成员与权限。
- Bitwarden clients commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce`：`default-policy.service.ts`角色豁免；`restricted-item-types.service.ts`type15全角色适用，null默认Card(3)，个人并集/组织自身范围，含既有项目读取。SDK固定commit `39dbb510f5eae82f5cbfd527b0f70a01d5626ec1`。
- profile账号/email/wrappedKey须匹配本Session；policies/policiesNew/profile.organizations/ciphers必须显式数组。固定服务器usePolicies=true、managePolicies=false；未知type、不完整字段、重复及跨组织关联失败关闭。资源上限沿32MiB、1024组织、32768政策和8种类型。
- policy GET只形成操作检查，不发布vault或解除隔离。policy读→写没有服务端事务/CAS；离线期间也无法发现尚未同步的远端撤销。不能宣称消除这些窗口。

## 验证证据与边界

新增`offline_policy_read_test.go`、`snapshot_policy_controller_test.go`覆盖认证/非认证恢复、错operation/epoch/revision、缺policy与篡改、adopt不签许可、个人/组织受限读取/列表、秘密回调零调用、reprompt/导出/bulk、文件夹/隔离元数据撤销、真实HTTP token refresh同内容receipt续接与坏receipt拒绝、无回执/磁盘失败/通用隔离不续接、旧item grant失效，以及网络恢复候选不可授离线许可、内容/epoch变更拒绝。原crypto、reprompt/历史、copy/backup/rebase、只读组织、锁定/取消、管理写入测试继续保留；授权fixture明确经受信receipt，负向对象后改不重授权。

Swift57项涵盖MemoryKeys加密快照、lease、隔离/重启/恢复、checkpoint的相同vault回执，以及新增旧缓存/完整policy/个人并集/组织自身/重复键/嵌套/候选过滤。真实桥动态库编译和独立AutoFill源码typecheck通过；**没有执行真实Keychain交互、Touch ID窗口、签名安装、Safari/系统AutoFill运行或用户剪贴板测试**。

`TestLivePolicyExecution`使用独有名称/label、回环端口的1.37.4 Docker及example.invalid账号，验证type5/15真实写入、reprompt、bulk缺ID拒绝/服务器部分执行，以及个人/组织同步投影与离线读取随type15启用拒绝、移除后恢复。bulk通过真实创建→认证缓存→服务器删除形成陈旧快照，未给生产guard注入假snapshot。受信Go receipt仅模拟已验证发布；fixture policy PUT和直接partial协议请求不是产品策略管理入口。最终命令/资源/结果见最新handoff。

## 下一步，范围不缩减

1. 完整12种固定服务器策略的原生业务表单、未知data保留、依赖/权限/确认/取消/错误处理，以及影响当前访问时先持久隔离；不能做raw JSON页。
2. type16默认URI匹配、生成器/Send/PIN/组织生命周期等已有与后续功能的实际政策消费；minComplexity按固定clients/SDK真实zxcvbn词典、用户输入、Unicode语义核对。
3. 原完整legacy共享、附件、Send、账号/MFA/SSO/通知、大库桥、组织批量/导出、逐项reprompt、无ID数组冲突等继续总矩阵。其余旧opt-in真实协议夹具仍可能使用BindSnapshotRevision或直接改VaultData，运行对应模块前按真实receipt迁移，不放宽生产读取边界。
