# 同卡续作交接：权威策略执行基础已落地，继续剩余入口迁移

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 协调者本轮通过`contact_supervisor(need_decision)`批准：按可验证提交迁移；本次上下文不足以安全继续组织/离线/桥的跨模块迁移时，保存本单元、准确清理、干净提交后续启同卡。全部原验收范围不缩减。以本文之后`git log/status`最新HEAD为准，不回退或重新导入。

## 当前基线与提交

- 本轮开始HEAD `a71166e`，全部既有成果与用户baseline保留。实现提交 **`d88af8386f7de257be0b908a5c53a378eb8bdb58`**，本文随后以单独交接提交保存。未读真实凭据、未接生产、未改主目录/用户app/watch/剪贴板，未启动子代理。
- 新文件：`internal/vaultwarden/policy_execution.go`及6个`policy_*test.go`测试文件（execution、execution_integration、fixture、import、import_refresh、lifecycle）；专题`docs/organization-policies.md`。修改`client.go`、`authenticated.go`、`cipher_create.go`、`ciphers_api.go`、`backup_import.go`及相应copy/backup/reprompt/update夹具，README与coverage同步。
- 前序群组完整增量在`a71166e`及`docs/organization-groups.md`，不要重做群组/成员/SMTP调查。原手工策略方向和群组范围确认要求仍在git历史与专题。

## 本次实际实现边界

仅个人**create/update/copy/import**（包含已授权reprompt、完整编辑中的收藏/文件夹以及冲突重新应用后的更新）接入type5 PersonalOwnership和type15 RestrictedItemTypes的**保存约束**。原生既有新增/编辑/复制/导入入口复用这些方法，错误用中文政策原因说明。没有policy管理表单，不是其它政策已经执行。

- `Session.writePolicies *operationPolicies`完全私有，只有`operationPoliciesLocked(ctx,persist)`的认证`GET /api/sync`可安装。`parseOperationPolicies`内部解析不授予外部能力。`beginOperationLocked`开始/结束清空上下文，`Close`也清空。公开可变`VaultData`或`BindSnapshotRevision`不能构造在线policy许可。
- profile account/email/wrapped user key与会话一致；固定basepath沿Client。`policies`、`policiesNew`、organizations、ciphers必须显式数组，缺失/null失败。组织id/memberID/userID、role/status/enabled/usePolicies/permissions及policy id/type/enabled/data逐项验证，重复/跨组织/畸形拒绝。固定1.37.4的usePolicies=true/managePolicies=false已在真实fixture确认；confirmed的两个policy数组必须一致，accepted-only不能冒充confirmed所有权限制。
- 本地quarantine不能过滤权威服务器成员政策。policy GET不发布新vault、不替换UI revision、不解除本机隔离；server enabled=false也不绕过confirmed角色的PersonalOwnership检查。单元`TestPolicyUpdateRejectsOwnershipButPreservesExistingRead`带本地org隔离的vault仍允许type5已有个人读取、禁止更新；多组织测试确保owner在A不豁免B成员政策。
- 每次成功token refresh都推进authorizationEpoch，含无PasswordUnlock的临时网络会话；持久会话还在checkpoint成功时推进。先checkpoint再policy GET；失败阻断，pending保留，成功恢复后重新GET。派发前`checkOperationPoliciesLocked`复核ctx/stopping/epoch/revision/scope，与现有reprompt guard组合。
- **操作中途再次refresh/checkpoint选择中止，不自动重取后继续写，更不重发已执行项。** 下一次显式操作才取新上下文。导入全项加密预检后一次policy读取，全部type检查完成后才写第一folder；后续所有写通过authenticated派发前检查。`TestPolicyImportRefreshStopsAfterKnownPartialSuccess`确定性在第一个folder响应后使token过期，证明refresh+checkpoint后停止：只1次policy GET、1个已创建folder、0 cipher，ImportResult保留已创建ID与第二项停止/待核对状态。后续真实API写逻辑仍不得盲重试。
- type5按每组织owner/admin豁免、member/manager约束，允许既有个人读取/删除/共享（后两者没有因type5新增封禁）。type15包括owner/admin；null默认Card，数组在个人库上跨组织并集。**type15既有项目读取/投影、组织各自范围尚未执行，当前不能称完整type15支持。**
- `/sync`→写没有服务器事务/CAS，单次批量期间远端policy变化有竞争窗口，明确保留该风险。

## 实际验证与资源

通过`GO=$(bash scripts/resolve-go.sh)`执行：

- `"$GO" test ./... -count=1 -timeout=60s`通过。
- `"$GO" build ./...`通过。
- `"$GO" vet ./...`通过。
- `"$GO" test -race ./... -count=1 -timeout=60s`通过。
- 之后只新增确定性import中途刷新测试，执行`"$GO" test -race ./internal/vaultwarden -run '^TestPolicy' -count=1 -timeout=30s`通过；没有无理由重跑无关套件。
- `MYGO_VW_POLICY_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLivePolicyExecution$' -count=1 -v -timeout=120s`通过（1.39s test body）。独有1.37.4 Docker回环实例、example.invalid两账号；真实产品组织创建/邀请/公钥确认、member无UI resync即被新type5限制create/update、已有读取仍可用、owner豁免type5但受type15 Card保存限制。policy PUT只为fixture布置，**不算policy产品管理接口**。
- 每个容器使用独有`mygo-policy-UUID`名称及`mygo.fixture`label；cleanup核对完整ID+label后`docker rm -fv ID`。末次`docker ps -a --filter 'name=mygo-policy-' --format '{{.ID}} {{.Names}}'`无输出。未启动SMTP/CLI/窗口、未外发。
- `git diff --check`通过；实现提交后`git status --porcelain=v1`及`git diff --cached --name-only`均无输出。交接提交后再由最终报告记录最新HEAD和工作区状态。
- 本次未改Swift/桥，**未跑Swift/bridge**；历史52 Swift证据不是本次新验证，不声称真实安装/窗口/Keychain/AutoFill验证。
- 开发中先运行全套识别三个旧HTTP夹具缺policy GET，产生wrong-route/protocol失败；补真实HTTP空policy响应后全套与race通过。无生产绕过开关，无直接注入policy授权。一次精确edit旧文本重复签名匹配失败，后修正，无遗漏修改。

## 下一进程直接继续：批准方向，不再重查设计

协调者明确顺序：

1. **组织create/update/share等剩余生产写入口**策略迁移。可复用`personalCipherPolicyGuardLocked`/operation context机制，扩展实际组织适用集合；type15是本组织范围，不可把个人并集无差别用于其它组织。操作的真实成员/权限和key链仍需结合已有组织guard，policy读不授予访问或解除隔离。当前`organization_write.go`与`organizations.go`写入口还未迁移。
2. 个人metadata独立partial、单项状态/bulk、组织生命周期及未来Send/账号行为仍未接完整policy检查。按政策实际作用区分操作，type5不能错误封禁删除/共享；不能因为服务端存在部分强制就永久不接客户端策略。当前`authenticatedGuardedLocked`只在**已建立**policy context时统一复核有效性；其它入口没有context就是尚未迁移，不是完整执行层。
3. **type15离线读取与真实桥认证lease绑定**。现有`RestoreSession(data,scope,config)`只恢复网络session，公开`VaultData`不能当可信policy来源。协调者批准在真实桥认证解锁返回、当前scope+revision lease边界创建私有snapshot上下文，可新增受信恢复入口或独立封装；维持既有桥认证边界，不另造通用签名协议。纯session恢复若无认证vault，不能假定离线policy为空。统一读取/秘密显示/reprompt/备份导出/AutoFill投影/bulk策略边界，不能静默暴露受限项目；依旧保留personal与其它org/session隔离。
4. 再完整policy原生业务表单与其它policy真实执行。固定上游12种：0/1/2/3/5/6/7/8/14/15/16/20。GET list/单type、PUT`{"policy":{"enabled":bool,"data":...}}`，0/3启用可能先revoke成员、非事务；危险策略先持久隔离、说明影响/确认取消、重读状态/原值及unknown保留、权限/依赖/失败测试。不能raw JSON表单，不能声称账号/Send/PIN等未有功能已经执行。
5. master-password minComplexity仍须定向核对固定clients/SDK的zxcvbn词典/用户输入/Unicode评分，选择许可证兼容等价实现和独立向量，不能字符种类代替。此前批准约束不变。

协议证据已记录在`docs/organization-policies.md`：固定VW `ciphers.rs:162–169`双政策数组、`:409–426`PersonalOwnership语义，org_policy helper与profile组织字段；固定clients`default-policy.service.ts`角色豁免、`restricted-item-types.service.ts`数组/null和既有读取限制、`uri-match-default.component.ts`字段`data.uriMatchDetection`。本轮直接GitHub原站读成功文件在本轮scratch；一个restricted-item-types.component.ts抓取超时，没有拿到就没当作证据，也未回退main。

固定VW缓存 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/` commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`；clients固定`5983f56ce0cf924eea56c7d8f066f7885825a7ce`，SDK固定`39dbb510f5eae82f5cbfd527b0f70a01d5626ec1`。本轮scratch `/tmp/pi/01a115c4-99e9-7601-8f62-6509428092e0`，不保证进程结束后存活；协议锚点已入仓。GitHub原站失败才读既定mirror fallback skill。

## 完整其它剩余范围仍保留

policies/events/Public API/API keys/完整管理员recovery及既有accepted登记、legacy完整共享、组织import/export/复制/批量/冲突、附件/Send、注册账号轮换/MFA/SSO/platform/devices/emergency/通知、4MiB桥大库、安全离线迁移/AutoFill、个人双改数组逐行选择及reprompt批量/导出、含附件/FIDO2无损备份复制等继续原验收。矩阵与专题必须保留实际边界，未完成前不创建Review/merge。主目录dirty的最终合并协调由父进程处理，子进程不能触碰主目录或用户资源。
