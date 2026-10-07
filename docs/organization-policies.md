# 组织策略执行迁移

**INCOMPLETE — 整卡未完成，禁止Review/merge。** 已新增固定12类策略产品API与原生业务表单，以及跨Go/Swift的持久待核验屏障和显式恢复；策略管理不等于全部策略消费。type16默认URI已接个人/组织投影、原生创建编辑默认说明与Swift旧候选来源核验；兼容zxcvbn、生成器/Send/PIN/账号及组织生命周期的剩余策略消费仍待完成，原完整API范围保持不变。

## 策略管理与恢复（本轮增量）

`policy_management.go`提供`OrganizationPolicies`、`OrganizationPolicy`、`SaveOrganizationPolicy`，使用GET `/api/organizations/{orgId}/policies`、GET/PUT `/api/organizations/{orgId}/policies/{type}`。产品管理入口仅向当前confirmed/enabled所有者和管理员显示；保存前还读取成员目录核对当前角色，服务器继续最终授权。列表路由上游允许成员读取，产品这里用于管理导航，不冒充服务器更窄的权限。PUT真实嵌套`{"policy":{"enabled":...,"data":...}}`；私有原值和显式确认草稿绑定scope/revision，未知data、未编辑值及大整数按RawMessage保留。修改字段按固定clients标量/范围验证，未知原值不静默重写。保存前重读全部策略及目标单项；不同则拒绝，GET→PUT不是CAS。

| 类型 | 原生控件/数据字段 | 实际消费边界 |
| --- | --- | --- |
| 0 双因素 | 启停 | 服务器可能先撤销成员；完整客户端MFA管理待接 |
| 1 主密码 | minComplexity、minLength、requireUpper/Lower/Numbers/Special、enforceOnLogin | 管理表单已接；兼容zxcvbn及主密码操作消费待接，不用字符类别假冒评分 |
| 2 生成器 | overridePasswordType、minLength、useUpper/Lower/Numbers/Special、minNumbers/Special、minNumberWords、capitalize、includeNumber | 管理表单已接；生成器产品待接 |
| 3 单一组织 | 启停 | 服务器可能先撤销其他组织成员；本机生命周期前置消费待补 |
| 5 个人所有权 | 启停 | 已有个人create/update/copy/import限制；不禁止已有个人读取/删除/共享 |
| 6 禁用Send | 启停 | Send产品待接 |
| 7 Send选项 | disableHideEmail | Send产品待接 |
| 8 账号恢复 | autoEnrollEnabled | 邀请自动登记已接；完整管理员恢复待接；服务器可配置要求type3，保存前检查策略变化，依赖拒绝由服务器反馈 |
| 14 PIN解锁 | 启停 | 本产品尚无PIN入口，无伪造消费 |
| 15 受限类型 | 启停；固定客户端无数据编辑控件，null默认Card及现有数组保留 | 写入/读取/AutoFill实际执行；待核验期间保守暂停全部个人条目读取及相应保存 |
| 16 URI默认 | 基础域名/主机/完全匹配/从不匹配；保留未编辑旧值 | 按首条适用策略、owner/admin豁免应用于个人及组织未显式规则；0域名/1主机/3精确/5从不，2前缀/4正则目前不投影且不降为域名；待核验期间继承规则暂停填充 |
| 20 用户通知 | 启停、原有扩展数据保留 | 固定服务器只发现类型保存，未发现通知执行器，不宣称已执行 |

控件来自固定clients `5983f56...`的`policy-edit-definitions/*.component.ts`。主密码长度12–128、生成密码长度5–128、数字/符号数0–9、短语词数3–20，分别核对`platform/misc/utils.ts`与`generator/core/src/metadata/password/{random-password,eff-word-list}.ts`。本轮只读取源码中的DTO与约束，没有新增依赖。type16消费依据：同commit `autofill/services/domain-settings.service.ts:225–246`使用`policiesByType$`后`getFirstPolicy`；`default-policy.service.ts:23–24,46–84,272–306`按角色豁免再取第一条；`models/domain/domain-service.ts`枚举0域名/1主机/2前缀/3精确/4正则/5从不。此次补核`platform/sync/default-sync.service.ts:423–448`确认旧PolicyService使用`response.policies`（`policiesNew`是另一个服务），以及`admin-console/models/domain/organization.ts:309–310`的canManagePolicies包含owner/admin。本应用无用户级默认设置，缺值/非法首条回退0；不继续选第二条。数值按JS JSON Number枚举语义核验，1e0/3.0允许，文本/小数/范围外不允许。

`sync.go`与`organization_autofill.go`在URI.match缺失或null时用已认证`operationPolicies.defaultURIMatch`，显式0–5不覆盖。`DefaultURIMatch`要求当前完整快照许可，原生创建/编辑显示有效默认并继续保存null，不把继承规则固化。Go投影新增`URI.sourceIndex`（原始密文login.uris索引），Swift从同一认证vault原始数组核对该位置的显式match或当前默认；旧候选缺来源、索引越界、规则变化均不填充，也不回退hosts/url。新规则可能因收窄而被暂时移除，成功同步才重新派生；2/4目前不投影。`pendingPolicyType16`将继承默认暂按Never处理，未知PUT结果期间也不能继续使用旧宽松默认；显式规则继续保留。恢复专用receipt后下一次同步重建继承候选。此来源索引是认证数据内部关联，不是对任意伪造同进程数据的密码学证明。

### 最新控制器与URI回归

`policy_recovery_two_stage_test.go`以受控HTTP服务器、模拟认证存储回执连接生产`adoptPolicyRecoveryPreview`→绑定→`SyncForPolicyRecovery`→验证→`adoptOrganizationSnapshot`，覆盖success/changed-policy/late-preview/wrong-preview-receipt/stale-preview/ordinary-sync/cancel/wrong-final-receipt/late-final。另一个controller测试核对完整org/type/mutation与原记录匹配、跨org错误记录、错误type/同type不同mutation、其它pending及marker/session保留、旧revision/snapshot和重放。发现并修复了专用清除记录未校验目标org的问题。此证据不是真实窗口、Swift持久化或Keychain端到端测试。

Go/Swift共享`uri-default-policy-cases.json`的21向量，覆盖全部枚举、数组顺序、role/disabled/accepted边界、非法首条、JSON数值表示；Go真实加密URI与RSA组织解密投影、同内容checkpoint及原生默认显示回归；Swift旧候选迁移、来源位置、域名旁路与pending16阻止继承规则。独有1.37.4回环新增`uri-default-projection`验证六种设置下成员个人URI继承/显式规则；服务器策略由fixture seed设置，不能称为原生管理窗口或Swift落盘证据。最新最终命令与结果见handoff。

### 持久屏障与因果顺序

`PendingPolicyMutation{organizationId,policyType,mutationId}`只在受认证加密VaultData中。第一次政策PUT前，`quarantineOrganization`原子保存该记录与组织隔离，旋转revision/candidate ID并撤旧lease。生产Go回调核对新scope/revision/SnapshotID、全部旧pending与此次完整记录，失败不发PUT。`checkpointLocked`撤旧离线授权；Session记录pending用于后续新网络sync预解密与操作内写guard。type15额外限制个人1–8类读取和填充，type5只限制个人保存；其他组织按自身策略与权限，不继承目标组织限制。

本地schema1无pending；带pending升级为schema2。Go/Swift拒绝v1带pending、v2丢pending、未知版本、重复组织/重复mutationID及非法type/ID；旧客户端仅支持v1，因此不能忽略新增字段再回写。普通publish将旧认证pending并入新vault，token checkpoint完整保留；普通组织restore只处理组织marker，不清pending。全部pending清除后专用恢复写回v1。pending完整内容进入Go快照hash。

恢复入口先新sync，`ReviewPendingPolicy`取得仅含策略/成员元数据的私有证明，然后普通publish保留pending及组织隔离。控制器采用新认证回执后，`BindPolicyRecoveryReview`校验完整快照许可、源sync摘要、紧随源候选的epoch、scope/revision/特定pending记录；这不是授予离线权限的通用binder。用户查看当前策略、成员状态并明确确认后，`SyncForPolicyRecovery`在同一Session锁内核对预览epoch/revision/快照/记录，发起独有的新sync；`ValidatePolicyRecovery`核对新候选、策略/成员一致性并单次消费。变更/旧确认/普通或在途旧sync/取消不能清记录。`restorePolicyAccess`只清指定完整pending；confirmed且key有效才可同时恢复组织，否则只恢复个人策略状态并保留组织marker和其他pending。恢复后再同步重建候选。

原HTTP调用在Session锁内结束后才可能进入恢复；关闭进程重启后需重新读取并确认当前状态。两次sync不证明未知PUT绝不迟到执行，界面明确提示并发窗口；type0/3可能撤销部分成员后保存失败，任何未知结果都保留屏障，不重试、不伪报回滚或自动恢复已撤成员。

### 本轮证据

Go协议/权限/确认/陈旧revision/取消/checkpoint失败零PUT/未知结果与0、3非事务模拟通过；恢复验证绑定发布后的revision/epoch与mutation，拒绝无绑定/旧revision/错误ID/普通sync/重复/策略变更，成员撤销后重新预览只能恢复个人。Go与Swift共享`testdata/pending-policy-cases.json`核对12类、跨组织并集、重复及降级范围。Swift MemoryKeys测试覆盖pending写前持久、旧lease撤销、重开store/解锁、普通sync/token保留、只清一条和保留其他组织隔离及session；独立候选函数拒绝旧/坏schema，type5仍可读。

独有1.37.4回环验证12类产品GET/list/PUT及Go-only显式恢复；它使用受信Go回执模拟，不验证真实Swift落盘、Keychain或安装。原生headless验证角色入口、状态标签与专用恢复入口、错误回执拒绝/锁定撤表单；不是实际窗口视觉检查。真实桥编译和独立AutoFill typecheck通过。最终命令结果见最新handoff。仍需补完整原生两阶段交互的自动故障注入、真实签名平台/系统运行、以及全部策略依赖产品流程，不能宣称整卡完成。

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

1. 12种固定服务器策略管理及待核验屏障已接；继续补真实原生两阶段完整交互、平台故障注入与完整策略消费，不能将管理等同执行。
2. 组织生命周期、生成器/Send/PIN等已有与后续功能的实际政策消费；minComplexity按固定clients/SDK真实zxcvbn词典、用户输入、Unicode语义核对；URI前缀/正则完整匹配仍在整卡范围。
3. 原完整legacy共享、附件、Send、账号/MFA/SSO/通知、大库桥、组织批量/导出、逐项reprompt、无ID数组冲突等继续总矩阵。其余旧opt-in真实协议夹具仍可能使用BindSnapshotRevision或直接改VaultData，运行对应模块前按真实receipt迁移，不放宽生产读取边界。
