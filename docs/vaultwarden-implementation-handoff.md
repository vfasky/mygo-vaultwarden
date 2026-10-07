# 同卡续作交接：认证离线策略五链联合迁移

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 本进程从`23414fa9d6f4a2b88b9c993b7450c44f2de43a7c`继续，保留全部前序/baseline成果；本文与实现一起提交，最新HEAD以`git log -1`为准。协调者已明确批准：完成本增量最终相关验证、精确交接和干净提交后续启同卡；原完整API范围不缩减。只写本卡工作树，没有读真实凭据、触碰主工作区、用户app/watch、生产vault或启动子代理。

## 本轮生产接线地图（不再重做基础设计）

| 链路 | 已落地的函数与行为 |
| --- | --- |
| 同步预投影 | 保留前轮解密前type15过滤；`client.go:SyncWithCheckpoint`进一步核对完整organizations/organizationsNew身份，开始sync清离线许可/pending续接、推进epoch。新增`sync_candidate.go`在成功sync生成私有候选：session/epoch/scope/完整vault摘要/确认组织ID。只允许`ValidateOrganizationRecoveryCandidate`证明恢复资格，不能读取离线vault；公开候选内容后改、旧epoch无效。 |
| 认证解锁/publish | `main.go:completeStorage`只接受当前list/listPassword的scope/expected revision/UI epoch/available回执，`session_storage.go:restoreUnlockedSession`接`RestoreSessionFromAuthenticatedSnapshot`。旧缓存缺policy/完整schema仅恢复网络Session，必须成功sync迁移；删除`reply.Items`兜底。`network.go:syncVault`要求publish回执带vault、新revision、非空SnapshotID并保留全部旧隔离marker，在当前UI epoch安装`AcceptAuthenticatedSnapshot(reply.Vault, ...)`，失败关闭会话显示；`cipher_editor.go:adoptVault`只Validate已安装许可，绝不签许可。 |
| 全读取guard | `vault_data.go`个人列表/单项，`item_authorization.go:personalDocumentLocked`及秘密/TOTP/历史/reprompt，`organizations.go`组织元数据/列表/单项，`folders.go`，`organization_isolation.go`，`backup.go`，`cipher_bulk.go`都核对私有snapshot上下文。type15按个人并集/组织自身；列表解密前排除，单项拒绝。type5不禁已有个人读取。导出在秘密解密前拒绝reprompt/无权限/受限类型。组织只读仍可依viewPassword授权读；hidden/reprompt原规则保留。组织列表和导出每批只核验一次整库hash，避免逐条重哈希导致平方开销。 |
| checkpoint续接 | `SessionCheckpoint.AcceptAuthenticatedReceipt(vault, previous, revision)`是受信控制器在持锁persist回调中调用的特权确认器，**不获取Session.mu**。Swift`SnapshotStore.saveSession`读取未改内容的vault；真实`SnapshotBridge.saveSession`在`withCurrentLease`中随state返回vault。Go`saveSessionCheckpoint`先核验same SnapshotID/scope/new revision，再核验私有旧context的vault hash/previous revision。`refreshLocked`把有效旧context暂存为仅可续接的私有指针并撤读，`persistPendingLocked`等token落盘后才续接新revision/epoch。item grant一律撤销；无/坏回执、异内容、binder不能授许。网络迁移无旧context时只保存token，不授离线许可。 |
| 隔离/恢复 | 通用`checkpointLocked(isolate)`无论返回成功还是失败都清旧offline/pending并推进epoch（存储可能已执行，不能保留旧权）。`group_management.go`在隔离前拿本次操作授权key，私有`groupDraftLocked`借用它完成同一次服务器目录复核，结束清除，不能重新解锁离线读取。`adoptOrganizationSnapshot`在现有scope/new revision/新SnapshotID/目标marker/其余marker检查后Accept再adopt。恢复后台以私有sync候选验证目标，真实restoreOrganizationAccess回执才安装新context；普通sync不能解除隔离。 |
| Swift旧候选/独立扩展 | 新`macos/Shared/SnapshotPolicy.swift`检查重复JSON key/32层深度、profile id/email/key、完整成员和policy数组一致性、type15范围；个人并集不因隔离或server disabled取消，组织须自身confirmed/enabled且未隔离。候选拒绝deleted/archived/reprompt/无viewPassword、空组织ID及受限类型。`SnapshotPayload.safeCandidates`接主应用和扩展unlock以及`openSnapshot`；非demo缺vault/完整policy为零候选，成功sync才迁移。publish保存过滤后的明确空数组，原current lease/lock/logout边界保留。`project.pbxproj`已包含新Swift源。demo仅保留既有本机演示路径，仍过滤隔离；生产bridge禁止demo scope。 |

`RestoreSessionFromAuthenticatedSnapshot/AcceptAuthenticatedSnapshot`仍是受信app控制器特权跨包接口，本身不会认证Swift用户，也不抵御任意同进程Go代码。深拷贝sync/quarantine、完整VaultData hash、profile/session key与可访问组织key链/隔离成员身份检查均保留。`decodeOrganizationVaultLocked`和`organizationDocumentWithPolicies`是私有sync/受信构造/批内解码入口，未增加trusted bool或公开绕过。同步失败保留上一份加密磁盘快照，但撤旧许可；不是自动恢复旧权限。

## 测试证据与最终命令

通过`GO=$(bash scripts/resolve-go.sh)`取得工具链。最后生产更改包括Swift完整profile字段/空组织拒绝、bulk真实陈旧fixture、群组隔离后操作内key传递及批内hash复用后，执行：

- `"$GO" test ./... -count=1 -timeout=60s`：root **1.614s**、internal **4.227s**、dev-debug **4.864s**，全部通过；`"$GO" build ./...`、`"$GO" vet ./...`通过。
- `"$GO" test -race ./... -count=1 -timeout=60s`：root **6.077s**、internal **10.306s**、dev-debug **7.789s**，全部通过。
- `swift test --package-path macos --scratch-path "$TMPDIR/swift-policy-build"`：**57 tests / 0 failures**，最后0.168s测试时间。
- `TARGET_BUILD_DIR="$TMPDIR/bridge-output" CONTENTS_FOLDER_PATH=PolicyCheck DERIVED_FILE_DIR="$TMPDIR/bridge-derived" ARCHS=arm64 MACOSX_DEPLOYMENT_TARGET=14.0 CODE_SIGNING_ALLOWED=NO bash scripts/xcode-build-bridge.sh`：真实桥动态库编译通过，日志0字节。
- `xcrun swiftc -typecheck -swift-version 5 -module-cache-path "$TMPDIR/autofill-module-cache" macos/Shared/*.swift macos/AutoFill/*.swift`：通过，日志0字节。没有签名、安装或启动窗口。
- `MYGO_VW_POLICY_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLivePolicyExecution$' -count=1 -v -timeout=90s`：最后body **1.61s**、package **1.818s**；protected-state **0.18s**、bulk-preflight/partial **0.12s**、policy-sync-autofill **0.04s**，全部通过。实际个人/组织候选与离线读取在type15开启后拒绝、解除后恢复。Go-only Accept模拟已经核验的发布回执，**不验证真实Swift认证/Keychain/AutoFill系统安装**。
- 随后仅加强通用隔离checkpoint必须同时撤旧revision的测试断言、保留旧缓存成功解锁后的明确“先同步迁移”提示（`restoreUnlockedSession`以bool告知是否可采用vault），并更新注释/文档；`"$GO" test ./internal/vaultwarden -run '^TestCheckpointPolicyContinuationRequiresSameContentReceipt$' -count=1`通过，0.427s；最后`"$GO" test -race . -count=1 -timeout=60s`通过，5.814s；build/vet再次通过。
- `git diff --check`通过；提交后以git status验证本卡工作树与暂存区干净。

新增`offline_policy_read_test.go`验证真实HTTP token轮换后同内容续接、内容/scope/旧revision/同revision/无receipt/磁盘失败、通用isolate不能续接、旧item grant失效；统一列表/读取/导出/bulk/秘密/reprompt拒绝；成功sync候选不能读、内容/epoch改变不可恢复。新增`snapshot_policy_controller_test.go`覆盖可信解锁与legacy迁移、错operation/epoch/revision/profile、未受限Items不能兜底、adopt/binder/revoke不能签许可。Swift新增5项policy测试覆盖缺policy旧密文候选、个人/组织范围、隔离、type5旧读取、删除归档权限/reprompt/空组织ID、policy/成员错配、重复键（含转义）和过深JSON。

既有授权测试夹具迁移为明确受信receipt（`snapshot_fixture_test.go`、`accepted_fixture_test.go`及root对应helper）；crypto helper仍只测试crypto，不代表生产权限。个人比较/导出/历史/reprompt、只读/hidden组织、成员/集合/群组/隔离错误与取消回归继续覆盖。开发中曾有旧fixture因直接改公开snapshot后读而失败、两次批量改测试位置不精确造成编译失败，均已修正；未修改生产guard为旧fixture兜底。live bulk原伪造缺ID改为真实创建→认证缓存→服务器删除，先验证产品preflight零写，再以fixture直接请求验证服务器400可能部分成功。

## 自有资源与未验证边界

每次live测试使用唯一`mygo-policy-UUID`名称、同值`mygo.fixture`label、回环随机端口、`vaultwarden/server:1.37.4`、虚构example.invalid账号；cleanup核对完整容器ID与label后仅删除该实例。包括前几次失败测试在内均完成cleanup；最后`docker ps -a --filter 'name=mygo-policy-' --format '{{.ID}} {{.Names}}'`无输出。无SMTP/CLI/浏览器/剪贴板/Keychain操作，无用户资源清理。所有临时编译产物与日志在本会话`$TMPDIR`，未写主目录。

真实Keychain、Touch ID窗口、平台权限、签名安装与系统AutoFill运行仍未实测。bridge仅编译，Swift tests使用MemoryKeys；root UI为headless。既有其它opt-in live模块可能仍有BindSnapshotRevision/直接改snapshot的旧fixture，启用其测试时按真实receipt来源迁移，不扩大生产绕过。当前桥4MiB容量/大库迁移仍未解决，不能把32MiB Go/sync解析上限外推为端到端大库可用。

## 下一进程直接工作，不再重做五链设计

1. `organization_management_ui.go`的组织管理入口与`organizationEditor`继续接**完整12类policies原生业务表单**。固定上游route/DTO/依赖/角色/策略type源码已审计，依据[组织策略执行](organization-policies.md)与原卡固定缓存；按需定向读，不重审全库。不做raw JSON页；未知data保留，危险影响确认及持久隔离、权限/失败/取消完整接入。
2. 接实际剩余policy消费：type16默认URI规则、组织生命周期与生成器/Send/PIN/账号流程等，minComplexity按固定clients/SDK zxcvbn词典/用户输入/Unicode语义，不用字符种类替代。
3. 原完整剩余继续：[覆盖矩阵](vaultwarden-api-coverage.md)中的legacy无item-key完整共享、附件加密两阶段与原生上传下载、文本/文件Send owner+接收、账号轮换/恢复/MFA/SSO/设备/应急/通知、完整大库桥/AutoFill、组织状态/bulk/copy/import/export/冲突、reprompt批量/导出、个人双改无ID数组逐行选择、附件/FIDO2完整备份与更多格式等。此列表不取消原任务其它验收项。
4. 未实现policies产品API/原生表单；live fixture policy PUT不算产品能力。没有新增账号/MFA/附件/Send界面，保持INCOMPLETE。完整实现后才由协调者独立Review；主目录dirty合并交接仍由协调者处理，本进程不得触碰。
