# 同卡续作交接：写入口策略迁移已提交，下一步离线五链联合迁移

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 本进程协调者批准：保存已经完整验证的写入口增量、记录离线五条接缝与已批准特权构造器契约后，干净提交并续启同卡。原完整范围不缩减。下轮以`git log/status`最新HEAD为准，不重新导入用户baseline、不重做成员/群组/前序个人策略调查。

## 当前基线、提交与真实完成边界

开始HEAD `188700b38c429d4a083d369c046e123eb5dfc11d`；本轮实现提交 **`6605057`**（将组织写入与个人状态批量操作接入权威策略检查）。全部历史与baseline保留。本交接另行提交。未读真实凭据、未访问生产、未改主目录或用户app/watch/剪贴板，未启动子代理。只有本卡工作树发生写入。

生产代码增量：

- `policy_execution.go`的私有`operationPolicies`新增每组织type15限制、已解析server membership与本次认证sync的encrypted ciphers；policy GET仍不发布vault/不取消隔离。
- `organization_write.go`的create/share与`organizations.go`的UpdateOrganizationCipher接入`organizationCipherPolicyGuardLocked`：type15只检查目标组织；type5不误禁共享。服务器memberID/globalUserID/role须与本地解密出的组织身份相符，confirmed+enabled；原本key链、集合可写性、scope/revision/epoch/reprompt guard继续生效。当前仍仅独立item-key共享，legacy缺口不变。
- `ciphers_api.go`的个人state及仅供route测试的partial底层、`cipher_bulk.go`的个人批量接入`personalCipherStatePolicyLocked`。每次操作认证GET，从server逐ID核验真实type、个人归属、edit/viewPassword/reprompt；调用方伪造本地文档无法改变这些判断。type15受限则拒绝；type5允许这些状态操作。missing ID报ErrConflict、重复/缺必要字段失败，均在派发前；单项reprompt须grant绑定server原文，批量仍拒绝reprompt。partial尚无独立产品入口，原生收藏/文件夹沿完整编辑保存。
- 原有`authenticatedGuardedLocked`在已取得policy context后继续派发前复核ctx/stopping/epoch/revision；刷新/checkpoint中途改变epoch即停止，显式下一次操作才重新取policy，不自动重试。组织写入在policy前准备的旧key/权限guard也因此失效。
- 新增一次GET不提供服务器事务/CAS；GET后到mutation期间远端变化仍会竞争，批量mutation发出后的部分结果仍须逐项sync核对，不盲重试。

**未实现**：离线type15读取/列表/秘密/历史/TOTP/导出/AutoFill保护、可信snapshot策略上下文、完整policy原生业务表单、组织生命周期等其它policy消费。不能把已定位接缝或批准架构称为已实现。普通RestoreSession目前原有行为仍在，下一单元须改变其离线许可边界；本轮没有增设trusted标志或测试绕过。

## 实际验证与资源

通过`GO=$(bash scripts/resolve-go.sh)`取得工具链：

- `"$GO" test ./... -count=1 -timeout=60s`通过（最终完整运行root/internal/scripts全部通过）。
- `"$GO" build ./...`通过；`"$GO" vet ./...`通过。
- `"$GO" test -race ./... -count=1 -timeout=60s`通过：root 5.942s、internal 8.507s、dev-debug 7.840s。此后仅文档调整，没有新生产或单元代码；相关live integration变更已在同一次已完成验证之前。
- `"$GO" test ./internal/vaultwarden -run 'TestOrganizationPolicy|TestOrganizationCloseDuring|TestPolicyPersonalState' -count=1 -timeout=30s`通过。
- `MYGO_VW_POLICY_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLivePolicyExecution$' -count=1 -v -timeout=120s`最终通过（test body 1.62s，含protected-state-authorization 0.17s、bulk-preflight-and-server-partial 0.07s）。独有Docker `vaultwarden/server:1.37.4`、回环、example.invalid两个角色：组织Card create/update在最新type15后拒绝，Note允许；member type5允许trash/restore/bulk archive、type15拒绝bulk；真实reprompt grant删除原项及副本；bulk缺ID预检不写，再用fixture直接请求确认server400仍会部分移动。seedPolicy PUT和直接partial协议请求仅是fixture，**不是policy管理或额外产品API入口**。
- `policy_organization_test.go`：3入口×10场景；`policy_state_test.go`：6动作×10场景，每场景两类入口分别取policy。涉及目标组织/其它组织、缺policy、成员/角色改变、disabled/accepted、type5/type15；伪造类型/归属/reprompt/edit/viewPassword、缺/重复server record。`policy_organization_lifecycle_test.go`：checkpoint失败零GET零写、成功checkpoint后旧guard停止、显式重试新GET、Close中止在途policy GET零写。
- 更新现有state/partial/bulk/org测试HTTP夹具以真实响应policy GET，未向生产Session注入授权。开发首次新增share夹具遗漏edit/viewPassword，导致10个场景在policy GET前被既有guard拒绝；补正确字段后全套通过。一条精确edit因原文不唯一被工具拒绝，随后正确替换，未留下半编辑。
- 容器每次由`TestLivePolicyExecution`创建唯一`mygo-policy-UUID`名称和`mygo.fixture`label；cleanup核验完整ID+label后仅删除本实例。最终`docker ps -a --filter 'name=mygo-policy-' --format '{{.ID}} {{.Names}}'`无输出。没有SMTP/CLI/窗口/用户剪贴板资源。
- `git diff --check`通过。实现提交后仅此交接待提交；最终报告另记最新HEAD及`git status --porcelain=v1`/`git diff --cached --name-only`空输出。
- **本轮未改Swift/桥，未执行Swift/bridge测试或实际窗口/安装/Keychain/AutoFill平台验证。** 历史52 Swift通过不冒充本轮证据。

## 下一单元的已批准特权构造器契约

协调者明确批准新增`RestoreSessionFromAuthenticatedSnapshot`（名称可据实现调整），不要求把Swift桥或主控制器移入vaultwarden包，不新增签名协议。必须诚实标明：这是**供受信app控制器使用的特权跨包构造器**。Go exported意味着同进程受信代码可调用；不能宣称语言层不可伪造，不能宣称该函数自行验证Swift凭证。信任来自既有桥完成认证+当前UI epoch/scope/revision验证的生产调用链，不是抵御任意恶意进程内Go代码。

- 仅在调用者已经确认reply.OK、认证操作类型（list/listPassword）、request.expectedRevision与state.revision、scope/server/account、当前UI epoch未锁定、完整vault/session身份一致后调用。
- 子包内部再校验vault.scope、sync.profile账号/email/wrappedKey/完整policy和组织字段；所有slice/map/raw bytes深拷贝，建立私有revision/epoch/document hash上下文；失败不可装入部分权限。
- 普通`RestoreSession`只恢复网络会话，不得假定无policy；公开可变`VaultData`、`BindSnapshotRevision`或`trusted=true`不能直接安装许可。
- 新同步发布与认证解锁都建立可信上下文；新vault/revision、锁定、关闭、隔离撤销旧上下文。纯token checkpoint只有经过认证回执证明同vault/hash及正确revision推进才可续接，不能借通用binder延续。
- 缺完整policy的旧认证缓存必须要求成功sync迁移，不能编造成空限制；必要时网络会话可恢复，但离线读取不获许可。
- 统一列表、条目、秘密、reprompt/历史/TOTP、备份导出、AutoFill与bulk边界；type5已有个人读取保持允许，type15个人并集/组织自身范围保持。Swift敏感输出依旧要求current lease。

## 离线五条接缝（已定位，尚未改动）

1. **首次/后续sync的预解密投影**：`internal/vaultwarden/client.go:SyncWithCheckpoint`认证`GET /api/sync`，核对profile identity/key后调用`decryptSync`，构造`SyncResult.Vault`，再`appendOrganizationCredentialsLocked`。`sync.go:decryptSync`负责个人最小Login投影；`organization_autofill.go:appendOrganizationCredentialsLocked`按组织key/权限/reprompt/deleted/archived筛选。需要在秘密解密/投影前解析认证policy，不能等UI显示才过滤。同步结果到本地认证publish回执之间不要把公开result.Vault当离线许可；内部同步投影与发布后的私有上下文需要清楚区分。`network.go`后台`SyncWithCheckpoint`→`callStorage(publishVault)`，确认scope/新revision及隔离标记保留后，UI callback要求`a.epoch==epoch`才采用state/session/result.Vault。
2. **认证解锁回执**：`main.go:completeStorage`接收request、captured epoch、reply；先比UI epoch，list/listPassword分支核对reply.OK/state.available/revision==request.expectedRevision/scope相等，再`observeSnapshot`、`restoreUnlockedSession`、`adoptVault`。`session_storage.go:restoreUnlockedSession`目前只用reply.Session+state.scope/password config调用普通RestoreSession；这里换受信入口，并处理缺policy的旧缓存仅可sync。`macos/Bridge/SnapshotBridge.swift:execute`的listPassword先unlockWithPassword，list先LAContext unlock，再`withCurrentLease`返回session/vault/state；status不是认证来源。
3. **UI采用vault读取之前**：`cipher_editor.go:adoptVault`目前先清旧组织/列表，依次PersonalEntries、PersonalFolders、Organizations、IsolatedOrganizations、OrganizationEntries，最后才BindSnapshotRevision。新可信上下文必须在这些读取前由验证过的调用链建立，不能让adoptVault任意公开数据成为授权工厂；通用binder只能撤销不能创造上下文。`openCipherEditorAuthorized`也调用binder后ReadPersonal/Organization，不能因此复活旧policy。直接读取函数在`vault_data.go`、`item_authorization.go`、`organizations.go`；导出入口在`backup.go`，秘密/TOTP沿对应授权读链。
4. **checkpoint同vault/hash的revision续接**：`session_storage.go:saveSessionCheckpoint`带prior.revision/scope向桥发saveSession，要求新revision、相同SnapshotID、相同scope。`adoptSessionCheckpoint`目前更新items/editor等revision并BindSnapshotRevision；这里需受控的同vault/hash续接，不能任意revision binder继承旧策略。Swift `SnapshotBridge.swift` saveSession→`SnapshotStore.swift:saveSession`，通过unlockKey/expected并在`withCurrentLease`返回State，目前不返回vault。确保持久token先于任何后续网络使用；回调在Session.mu中执行，不能从persist回调直接调用再次加同一mutex的Go方法而死锁。授权epoch刷新停止当前write的既定策略继续。
5. **隔离/显式恢复发布**：`organization_management_ui.go`的后台`isolate`发quarantineOrganization，核对reply.OK、scope、新revision、新SnapshotID及目标标记存在，保存`checkpoint/isolatedVault`；恢复分支先SyncWithCheckpoint，Organizations确认目标仍可用，再restoreOrganizationAccess返回state/vault。UI callback需相同epoch，再`adoptOrganizationIsolation`/`adoptOrganizationSnapshot`验证sessionOwnsSnapshot、新revision+SnapshotID、目标标记状态和其余隔离标记保留，然后adoptVault。Swift对应`SnapshotBridge.swift` publish/restore/quarantine均`withCurrentLease`返回vault，`macos/Shared/SnapshotStore.swift:publish/quarantineOrganization/saveSession`持久保留标记。隔离改变vault/hash且撤销组织能力，但政策仍按完整原server sync约束个人/其它项；普通sync不能恢复隔离。恢复不得拿未经发布许可的公开synced.Vault绕过新离线读guard，需专门内部验证路径或受控候选流程。

## 下轮定向fixture与验证入口

避免全仓再调查，优先这些：

- `internal/vaultwarden/session_state_test.go:resumableFixture`生成网络Session，没有可信vault，不能让它自动授予离线policy；其中RestoreSession测试应新增“网络可恢复但离线无许可”。
- `organizations_test.go:organizationFixture`目前RSA+org/collection/cipher完整，但profile缺email/wrappedKey/policies等；新读边界启用后须补完整认证fixture并经受信构造/真实sync来源。`changeOrganizationFixture`供篡改/权限测试，不应对任意修改自动重新签发许可。
- `backup_test.go:backupFixture`、`cipher_document_test.go:cipherDocumentFixture`、`item_authorization_test.go`及`organization_vectors_test.go`（直接调用appendOrganizationCredentialsLocked）需分别区分低层crypto向量与认证读能力测试，不能为通过测试而在生产加宽授权。
- 根目录`session_storage_test.go`、`personal_secret_test.go`、`personal_editor_safety_test.go`、`organization_management_ui_test.go`以及解锁/发布controller测试需覆盖真实生产回执链；未认证、错误operation/scope/revision/epoch、不完整reply、对象后改、lock/隔离、checkpoint同内容续接/异内容拒绝、sync替换均须失败边界证据。
- Swift `macos/Tests/SnapshotStoreTests.swift`已有quarantine/restoration/lease夹具，`macos/Bridge/SnapshotBridge.swift`是真实传输入口。新增policy投影和缺旧缓存迁移需Go/Swift桥相关回归；memory/headless不等于平台认证实测。
- 本轮`TestLivePolicyExecution`内syncVault helper当前只BindSnapshotRevision；离线新边界后也须显式通过受信publish等价回执测试契约，不能宣称其Go-only fixture验证了Swift桥。当前live中type15既有读取尚允许，落地后预期需同步改为受限。

## 完整其余范围保留

完成离线五链后继续完整12种policy业务表单（0/1/2/3/5/6/7/8/14/15/16/20），0/3非事务撤成员副作用确认与持久隔离、unknown data无损、其它实际消费及minComplexity固定兼容zxcvbn；不能raw JSON或假实现。events/Public API/API keys/完整管理员recovery、legacy完整共享、组织import/export/复制/批量/冲突、附件/Send、注册账号轮换/MFA/SSO/platform/devices/emergency/通知、4MiB桥大库、安全离线迁移/AutoFill、个人双改数组逐行选择及reprompt批量/导出、含附件/FIDO2无损备份复制均未完成，继续原验收。

固定协议与缓存仍按`docs/organization-policies.md`和coverage锚点：VW1.37.4 `7c188967e7a467b19b2757bc3326f9cf3ccae327`、clients `5983f56ce0cf924eea56c7d8f066f7885825a7ce`、SDK `39dbb510f5eae82f5cbfd527b0f70a01d5626ec1`。未改版本/未重新猜协议。主目录dirty最终合并由协调者处理；本卡未完整完成前不Review/merge。
