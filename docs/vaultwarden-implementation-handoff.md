# 同卡续作交接：同步前 policy 投影过滤 + 私有可信 snapshot 基础

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 协调者已批准：本增量完成必要 Go 验证、准确交接并干净提交后续启同卡；原完整范围不缩减。开始 HEAD `14833c27e80fe808dc0a9895d1a7676dafda068d`，本次实现与本文一起提交，最新提交以 `git log -1` 为准。全部历史保留，不重新导入 baseline、不回退。只在本卡工作树写入。

## 本次实际新增

1. `internal/vaultwarden/client.go:SyncWithCheckpoint`在替换同步开始时清除私有 offline context、推进 authorization epoch；HTTP失败、缺policy、身份失败也撤旧。认证 `/api/sync` 解析完整 `parseOperationPolicies` 后才进行任何Login秘密解密。`sync.go:decryptSyncWithPolicies`按type15个人并集/组织自身范围预过滤；`organization_autofill.go:appendOrganizationCredentialsLocked`新增必需的 `*operationPolicies` 参数，在组织cipher秘密解密前检查自身组织type15。原始完整server-encrypted sync仍保留。type5不禁旧个人读取。无policy参数拒绝。无约束的`decryptSync`仅保留在`sync_test.go`作为crypto测试helper，没有生产旁路。
2. `policy_execution.go:operationPolicies.restricts`统一个人并集/组织自身范围判断，原写入口语义不变。
3. 新`snapshot_policy.go`，Session新增私有`offlinePolicies *snapshotPolicies`。`RestoreSessionFromAuthenticatedSnapshot(data, scope, config, vault, revision)`与`AcceptAuthenticatedSnapshot(vault, revision)`是已批准的受信app控制器特权跨包入口：先由调用方验证真实桥receipt的operation、UI epoch、scope、expected/new revision/state/隔离标记，再调用。**函数本身不验证Swift认证，Go exported不是同进程安全沙箱。** 深拷贝sync bytes/quarantine后独立解析policy；校验scope/profile/email/wrappedKey、完整policy、组织身份/key链与`organizationsNew`对应关系，隔离成员也不能跳过身份一致性。保存完整VaultData哈希、revision、epoch及私有policy树。失败先撤旧、不会安装部分能力。
4. `ValidateAuthenticatedSnapshot(vault, revision)`只验证已经安装的私有能力，不签发权限。普通`RestoreSession`没有此上下文；`BindSnapshotRevision`同revision不变，更换revision清除上下文；`RevokeItemAuthorizations`、Close、替换sync清除/撤销。refresh原有epoch推进也令已有context失效。

**严格未完成边界：构造器目前没有实际生产controller回执调用，只有定向测试与Go-only真服务fixture使用。现有列表/条目/历史/秘密/TOTP/reprompt/导出/bulk的离线read guard尚未统一接入。未修改Swift/桥、未接checkpoint同内容续接或隔离/恢复回执。不能声称离线type15、旧候选迁移或五链已完整保护。** 公开VaultData与普通RestoreSession沿旧读取API的缺口仍在，下轮必须联合接入，不把新增验证API当作完成。

## 验证与资源

通过`GO=$(bash scripts/resolve-go.sh)`取得工具链。本轮执行并通过：

- `"$GO" test ./... -count=1 -timeout=60s`：最终root 1.583s、internal 3.858s、dev-debug 4.878s，全通过。
- `"$GO" build ./...`、`"$GO" vet ./...`。
- `"$GO" test -race ./... -count=1 -timeout=60s`：最终root 5.677s、internal 10.131s、dev-debug 7.789s，全通过。
- `MYGO_VW_POLICY_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLivePolicyExecution$' -count=1 -v -timeout=90s`：最后真实回环test body 1.74s；既有protected-state 0.18s、bulk 0.09s，新增policy-sync-autofill 0.03s。后续将无policy的crypto helper移至`sync_test.go`、补构造器复制前资源上限与重复session JSON拒绝及测试、更新文档；最终Go全套再次通过，未无理由重复真服务。
- `git diff --check`通过。`docker ps -a --filter 'name=mygo-policy-' --format '{{.ID}} {{.Names}}'`无输出；每次实例由测试记录完整ID与唯一`mygo.fixture` label，cleanup核验后仅删除自有容器。没有SMTP、CLI、窗口、用户剪贴板或生产资源。

新`snapshot_policy_test.go`覆盖复制前资源边界与重复session key拒绝、公开binder无授许可、受信恢复/深拷贝、缺policy/错身份/错key/版本/revision/quarantine、对象后改、Revoke/Close、成功及失败sync撤销、受限损坏个人cipher在解密前排除、type5仍进行密码学读取。新`snapshot_policy_organization_test.go`覆盖完整组织恢复、隔离仍保留server限制、隔离组织`organizationsNew`错账号失败、坏receipt撤旧、显式恢复重建、组织自身范围与解密前排除、缺新成员数组拒绝。

旧sync HTTP夹具`client_test.go`、`login_challenge_test.go`、`session_state_test.go`补完整policy空数组；`emptyPolicySyncFixture`补`organizationsNew:[]`。`organization_vectors_test.go`显式用无约束的私有policy作为低层RSA/权限投影测试，不冒充认证入口。**未把`organizationFixture`等所有授权fixture改成可信来源，仍待联合guard迁移。** 开发中一次精确edit因原文两处相同被拒绝，随后已正确修改；第一次全量测试发现新fixture的organizationsNew与原成员不一致，补完整对应关系后通过。

真服务新增`TestLivePolicyExecution/policy-sync-autofill`在唯一1.37.4回环创建个人/组织Login，type15开启后两者候选消失，解除限制后恢复；sync helper通过`AcceptAuthenticatedSnapshot`模拟已验证发布receipt。**这是Go-only fixture，不验证Swift桥/平台认证/系统AutoFill安装。** 两次测试均自有example.invalid账号，无真实邮件或生产写入。未执行Swift/bridge检查，因本轮未改这些代码；历史平台证据不得冒充本轮。

## 下一进程直接实施顺序（不再重复接口方向决策）

### 1. controller解锁与publish回执安装

- `main.go:completeStorage`仍在`list/listPassword`核对OK/state.available/expectedRevision/scope/UI epoch后调用`session_storage.go:restoreUnlockedSession`；改用新增受信构造器。旧缓存缺完整policy时可恢复网络Session以便成功sync迁移，但不得装离线权限或采用reply.Items作为不受限列表。status/reindex/错误/迟到回执不能安装。
- `network.go`后台`SyncWithCheckpoint`→`publishVault`已核验scope/new revision和旧隔离标记。UI callback必须仍匹配captured epoch，在任何`adoptVault`之前用已核验reply安装上下文；不能用未经验证的公开`result.Vault`签发权限。新context不能取消旧组织隔离。
- 现有`snapshot_policy.go`构造器内部调用`organizationVaultLocked`验证key链；下一步给后者加guard前必须拆出**私有decoder**供认证sync/已校验receipt构造使用，避免构造器自锁或自己要求尚未安装的许可。`appendOrganizationCredentialsLocked`也需此明确内部路径。不得加`trusted=true`或公共绕过。

### 2. adoptVault之前读guard

- `cipher_editor.go:adoptVault`目前先读PersonalEntries/Folders/Organizations/IsolatedOrganizations/OrganizationEntries，最后BindSnapshotRevision。改成采用前只验证已经安装的上下文（新增`ValidateAuthenticatedSnapshot`）；adopt自身不能成为公共数据授权工厂。其它open editor的binder不能恢复旧context。
- `vault_data.go`、`item_authorization.go:personalDocumentLocked`、`organizations.go`、`folders.go`、`backup.go`、`cipher_bulk.go`统一适用guard，列表与单项都按type15，type5不禁止已有个人读取。秘密/历史/TOTP沿同一条授权读取。hash包含完整sync与quarantine，不能只比较单项ID/hash。

### 3. checkpoint可信同内容续接

- `session_storage.go:saveSessionCheckpoint`目前只验证new revision、same SnapshotID/scope；`adoptSessionCheckpoint`仍用普通binder，**新增offline context将因此失效，不能把这条路径误当已续接**。
- `macos/Bridge/SnapshotBridge.swift:saveSession`当前只返回state，`macos/Shared/SnapshotStore.swift:saveSession`lease不带vault。需让受认证回执证明same vault/hash+准确revision推进，Go在验证后续接私有context；异内容/错scope/hash/revision不得续接。
- `Session.mu`持锁调用persist。禁止从persist回调调用再次取得Session.mu的方法。`authenticated.go:persistPendingLocked`当前callback后再推进epoch，`refreshLocked`本身也推进epoch；续接必须协调这两处与旧grant撤销，并区分通用`checkpointLocked(isolate)`的改变vault场景。token一定先持久再后续网络，不可no-op。

### 4. quarantine/restore回执更新

- `organization_management_ui.go:adoptOrganizationSnapshot`/`adoptOrganizationIsolation`已有sessionOwnsSnapshot/new revision+SnapshotID/目标marker/其余marker检查；通过这些检查再安装新上下文、再采用vault。隔离改变hash撤旧许可，但完整原server policy继续约束个人与其它组织。
- 恢复后台目前在Sync返回后用`Organizations(synced.Vault)`核验目标。统一guard启用后这还不是已发布receipt，不能直接绕过；需受限内部认证sync候选校验路径/私有候选能力，然后真实restoreOrganizationAccess持久receipt安装。
- Swift publish/quarantine/restore已用`withCurrentLease`返回vault；继续保留普通sync不能取消隔离、跨重启有效、错误/迟到回执不能恢复的规则。

### 5. 全部读链、Swift投影与fixture回归

- 旧缓存缺完整policy不能当空限制，Swift自动填充旧候选也需受限拒绝/迁移；当前新sync投影正确不代表既有缓存安全。统一 deleted/archived/reprompt/无权限/组织隔离规则，仍需current lease与锁定撤销。
- Go授权fixture重点：`session_state_test.go:resumableFixture`仅网络会话；`organizations_test.go:organizationFixture/changeOrganizationFixture`仍缺完整profile/policy，修改文档不能自动重授；`backup_test.go:backupFixture`、`cipher_document_test.go:cipherDocumentFixture`、`item_authorization_test.go`、`cipher_rebase_test.go`按来源区分crypto与授权API。
- 根controller重点：`session_storage_test.go`、`personal_secret_test.go`、`personal_editor_safety_test.go`、`organization_ui_test.go`、`organization_management_ui_test.go`、`cipher_comparison_test.go`；常用`writableUIFixture`/`secretUIFixture`现在会直接改公开vault，需模拟真实已认证receipt生产链，不能往生产塞测试许可。
- Swift重点：`macos/Tests/SnapshotStoreTests.swift`现有lease/quarantine/recovery夹具、真实`SnapshotBridge.swift`返回。新增伪造/缺policy/对象后改/错误receipt、同内容checkpoint/异内容拒绝、sync替换、隔离/重启/旧候选、离线拒绝与成功sync恢复。按修改执行Go/race/Swift/bridge；真实平台安装不得用headless代替。

## 原完整范围与固定依据

其它尚缺policy十二类业务表单与消费、minComplexity兼容评分、legacy共享、附件/Send、账号/MFA/SSO/通知/大库桥等继续原整卡。完整边界与固定VW1.37.4/clients/SDK commit引用[API覆盖矩阵](vaultwarden-api-coverage.md)、[策略专题](organization-policies.md)及前序git交接；不重新审计或猜协议。主目录dirty交接/最终merge由协调者处理；本进程未读真实凭据、未改主目录、未启动子代理，未将本卡标为完成。
