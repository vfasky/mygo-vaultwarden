# 组织策略执行迁移

**INCOMPLETE — 这是逐入口迁移中的会话执行基础，不是全部策略或管理表单已完成。** 原完整API验收范围保持不变；未完成前禁止Review/merge。

## 已连接的生产路径

`policy_execution.go`只允许经过本Session认证HTTP读取的完整`GET /api/sync`建立私有`operationPolicies`，从不从调用方公开的`VaultData`或revision构造在线授权。上下文只活在单次`beginOperationLocked`到`finish`之间。当前已接入：

- 个人八类新增、个人复制（含reprompt已授权分支）：共同`createGuardedCipherDocumentLocked`。
- 个人更新、收藏/文件夹随完整编辑保存、冲突重新应用后的更新：`UpdatePersonalCipherAuthorized`。
- 个人备份导入：先完整加密预检，再取得一次权威策略并核验全部项目类型；在任何文件夹创建前拒绝不允许的导入。随后共用这一次操作授权；每步派发前重新检查取消/会话停止/epoch/revision。既有成功记录仍保留，发生中途失效会停止并报告，绝不重发已执行请求。

- 组织新增/更新/独立item-key共享：`organizationCipherPolicyGuardLocked`按目标组织的type15检查，不套用个人并集，也不以type5封禁共享。认证sync的memberID/globalUserID/role必须与已解密本地组织身份一致，服务器confirmed+enabled；仍需原来的组织key、集合可写性、revision/epoch和reprompt guard，不授予或恢复组织访问。
- 个人trash/restore/archive/unarchive/永久删除、bulk（含move）及尚仅供route测试的partial底层：`personalCipherStatePolicyLocked`从认证sync逐ID核对type/个人归属/edit/viewPassword/reprompt。不能通过调用方文档伪造类型或权限绕过type15；缺ID、重复或必要字段缺失在派发前失败。type5允许这些状态操作。单项reprompt需授权绑定服务器原始文档，批量继续拒绝reprompt；新GET与原快照文档不同需重新同步授权。

实际执行PersonalOwnership(5)与RestrictedItemTypes(15)对这些**个人保存**操作的限制。前者按组织分别豁免owner/admin，普通成员及manager受约束，已有条目普通读取与删除不因为type5被禁止。后者包括owner/admin；`data:null`按固定客户端默认为Card(3)，数组按多组织并集约束个人保存。中文策略错误说明会经现有原生新增/编辑/复制/导入错误状态展示，保留草稿；这些业务原生入口沿既有实现，本次没有新增策略管理界面。

## 认证、完整性和生命周期

服务器scope/basepath取自绑定Client，profile的account/email/wrapped user key必须与会话相同。`policies`、`policiesNew`、`profile.organizations`、`ciphers`必须显式为数组，缺失/null失败关闭；逐项检查组织ID、membershipID/globalUserID、角色/status/enabled/usePolicies、权限字段、政策ID/type/enabled/data、重复及跨组织关联。固定1.37.4始终声明usePolicies=true且managePolicies=false；不接受不一致的权限声明。`policiesNew`中的confirmed项目必须与`policies`完整一致；accepted-only政策不会冒充confirmed所有权限制。未知政策类型、重复JSON key、不完整或畸形的type15值都不能变成“无政策”。资源沿32MiB响应上限、1024组织和32768政策上限，类型数组上限8。

每次操作重新在线读取，不信任旧本地快照。刷新先持久checkpoint，然后才读取；包括未持久化的网络会话在内，每次成功刷新都会推进授权epoch。若操作中途再刷新/发布checkpoint使旧policy上下文失效，当前迁移选择**停止**，下一次显式操作才重新获取，不自动重发。已有reprompt guard会与policy guard组合，刷新、慢请求或授权过期不会延长短授权。

policy GET只形成操作内检查，不解密/发布新vault，不推进UI快照revision，不取消本机组织隔离。即便本机隔离某组织，该服务器确认的组织政策仍约束个人操作；不能通过过滤本机隔离组织获取政策豁免。仍须服务端执行最终权限校验。服务器没有读policy→写cipher的事务/CAS，期间以及批量中途远端政策变更仍有竞争窗口，不能宣称消除。

## 固定协议依据

- Vaultwarden1.37.4 commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`：`src/api/core/ciphers.rs:162–169` confirmed `policies`与accepted+confirmed `policiesNew`；`:409–426`个人所有权禁止个人create/update，但允许delete/share；`src/db/models/org_policy.rs:275–304`适用性检查按confirmed成员角色；`src/db/models/organization.rs:438–532`profile membership与权限字段。
- Bitwarden clients commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce`：`libs/common/src/admin-console/services/policy/default-policy.service.ts`按type应用角色豁免，type15适用于所有角色；`libs/common/src/vault/services/restricted-item-types.service.ts`定义type数组/null默认Card、个人多组织并集和组织各自受限范围。上述固定文件本轮从GitHub原站读取；没有改用main。
- type15还限制既有项目读取，允许未对该type设限的其它组织项目读取。这部分**尚未迁移**，不得把当前个人/组织保存及状态检查当作完整type15支持。type16是`data.uriMatchDetection`，也尚未接入实际消费路径。

## 验证证据与未验证边界

新增`policy_execution_test.go`、`policy_lifecycle_test.go`、`policy_import_test.go`覆盖：角色、null默认、多组织并集、不完整字段/错身份/错key/重复/未知类型、显式空数组、每次操作新GET、无公共revision旁路、读取失败零写、401/500、Close/取消、checkpoint失败阻断与恢复、basepath、所有刷新撤销旧上下文、先预检全部导入项目且单操作仅一份权威政策、原生复用写路径及type5不错误封禁既有读取。既有copy/backup/update/reprompt测试改为真实httptest提供完整`/api/sync`政策响应；没有添加生产绕过开关或直接注入policy状态。

`MYGO_VW_POLICY_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLivePolicyExecution$' -count=1 -v`使用独有`mygo-policy-UUID`名称/label的1.37.4 Docker回环实例及example.invalid账号：真实完整sync解析、普通成员create/update受type5限制、无UI resync即采用最新policy、owner豁免type5、owner受type15 Card限制、现有个人读取与未受限type仍可用。组织成员邀请确认沿产品API完成；policy PUT仅为fixture布置，**不算策略管理产品实现**。容器完整ID及label核验后清理，无真实生产服务、外发邮件、用户app/剪贴板或平台Keychain访问。

Go测试/build/vet/race最终执行结果见本轮交接。本轮未修改Swift/桥或真实UI窗口，不能据此声称新平台/视觉验证。

新增`policy_organization_test.go`覆盖create/update/share的30个跨组织/成员变更/缺policy/角色/type5/type15场景；`policy_organization_lifecycle_test.go`验证刷新先checkpoint、旧组织写guard停止、显式重试重新GET与Close中止policy读取；`policy_state_test.go`覆盖6种状态的60个场景、两类入口各自发起新权威读取，包含伪造type/org/reprompt/edit/viewPassword、缺/重复server记录。现有state/partial/bulk HTTP夹具补齐真实policy GET，无生产测试绕过开关。

扩展同一`TestLivePolicyExecution`独有1.37.4回环，验证组织受限Card create/update零写、允许Note；member type5仍可trash/restore/bulk archive，type15阻止bulk。真实reprompt授权删除通过。bulk缺server ID现在在派发前报冲突、已有项不移动；另以仅fixture直接请求确认服务器400仍可部分移动，派发后的未知结果规则不变。仅fixture policy PUT与直接partial协议请求不算产品API入口。完整Go build/test/vet/race通过，未改Swift/桥或运行真实窗口。

## 仍须迁移，不能长期保留旁路

1. 组织生命周期及后续Send/账号等其它生产写入口按实际适用政策继续迁移；不能把type5误用于删除/共享。当前组织cipher写入、个人状态/bulk与partial底层已迁移，但partial仍没有独立产品入口，原生收藏/文件夹采用完整编辑保存。
2. 真实桥认证的解锁返回/当前scope+revision lease处建立不可由公开文档伪造的离线snapshot策略上下文。纯`RestoreSession`没有可信vault时仍可恢复网络，但不能假设离线policy为空。RestrictedItemTypes读取、备份导出、秘密读取/再次验证与AutoFill投影需统一执行；type16默认URI匹配和其它已有功能消费方仍需落实。
3. 完整12种服务器策略管理原生业务表单、未知data保留、危险策略影响确认及先持久隔离、依赖控制和权限/取消/失败测试；不是raw JSON页面。其它政策消费依赖包括账号密码轮换、生成器、Send/PIN等，不能虚称已实现。
4. 主密码minComplexity必须与固定clients/SDK真实zxcvbn评分/词典/用户输入/Unicode语义核对，不能用字符种类替代。
5. 本卡其它完整未完范围继续以总覆盖矩阵与交接为准。
