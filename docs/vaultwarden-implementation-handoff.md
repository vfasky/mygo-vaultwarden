# 同卡续作交接：恢复controller回归与type16默认URI消费

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 本轮从`392b0908673a07b8a9a33ca8c669d5fec68477f5`继续，保留全部历史与用户baseline；本文随实现提交，最新HEAD以`git log -1`为准。协调者已批准因本进程剩余上下文不足，在完成本增量验证、准确交接、干净提交后续启同卡，原完整范围不缩减。未写主目录/用户app/watch/真实凭据/生产服务，未启动子代理。

## 本轮实现与接口

- 恢复controller：`policy_management_ui.go:adoptPolicyRecoveryPreview`提取真实UI线程采用/绑定步骤，先采用认证publish回执再绑定私有review，并保留当前恢复表单。`organization_management_ui.go`生产回调使用它，失败撤会话；锁定/旧epoch/已换表单不能绑定。原两次sync链、专用receipt以及未知PUT并发窗口保持。
- 修复`adoptOrganizationSnapshot`专用清除未核验目标org的问题：必须精确匹配当前原记录完整`organizationId/policyType/mutationId`，且与恢复目标组织一致；其它pending/组织marker/session保留。
- `policy_recovery_two_stage_test.go`连接受控HTTP sync/refresh、模拟认证存储回执、真实Session及controller采用：preview→绑定→专用新sync→Validate→目标receipt。覆盖成功、策略变化、迟到preview、错误preview receipt、stale preview、普通sync、取消、错误final receipt和锁定迟到final。不是Swift落盘/实际窗口端到端测试。`policy_recovery_controller_test.go`另外覆盖完整身份/同type不同mutation/错误type/跨org、保留其他记录和marker/session、旧revision/snapshot、重放及锁定。
- type16：`operationPolicies.defaultURIMatch`从认证`policies`数组按原始顺序取首条enabled且角色适用的policy。owner/admin豁免；server disabled不是角色豁免；accepted只在policiesNew的记录不进入旧PolicyService消费。null/无效首条回退本应用默认0，不向后选第二条。JSON数字1e0/3.0按官方JS Number语义接受，字符串/小数/越界不接受。
- `sync.go:decryptCipher`与`organization_autofill.go`对URI.match缺失/null应用默认，显式match优先；0基础域名、1主机、3精确正常投影，5从不，2前缀/4正则目前不投影且不降级。所有原密文/未知字段仍保留。
- `types.go:URI.SourceIndex *int`新增可选桥字段`sourceIndex`，指向原始密文login.uris位置。Swift `SnapshotPolicy.swift`对同一认证vault按来源位置核对显式match或当前默认。无来源的旧规则、越界或规则变化不填充；丢弃规则时清理hosts/url，绝不宽松回退。旧快照仍可解密，但需成功sync迁移URI候选。该索引是认证数据内部映射，不是抵御任意同进程伪造的密码学证明。
- `pending_policy.go`和Swift同时将type16待核验期间的继承默认按Never处理；未知PUT可能收窄规则时旧宽松候选也不能继续填充。显式规则保留；专用恢复清记录后自动下一次sync重新派生继承规则。
- `Session.DefaultURIMatch`只读取当前认证完整快照许可；`cipher_editor.go`打开个人/组织创建或编辑时取得默认，`cipher_editor_fields.go`显示当前继承值。继续保存null，不把当前默认固化为显式match。政策管理说明和恢复文案同步实际边界。

## 固定来源（无需下一轮重查）

Bitwarden clients `5983f56ce0cf924eea56c7d8f066f7885825a7ce`：
- `libs/common/src/autofill/services/domain-settings.service.ts:225–246`：policiesByType→getFirstPolicy→有效枚举；本应用没有额外用户级默认设置，fallback为0。
- `libs/common/src/admin-console/services/policy/default-policy.service.ts:23–24,46–84,272–306`：源顺序、适用角色筛选、默认豁免canManagePolicies。
- 本轮补取原站固定commit源码：`libs/common/src/platform/sync/default-sync.service.ts:423–448`明确旧PolicyService消费`response.policies`，`policiesNew`是另一服务；`libs/common/src/admin-console/models/domain/organization.ts:309–310`明确owner/admin与managePolicies权限关系。1.37.4自定义managePolicies仍由既有协议校验拒绝；未放宽成任意角色权限。
- `libs/common/src/models/domain/domain-service.ts`枚举0/1/2/3/4/5。已有12类表单和恢复v2 schema细节见[组织策略专题](organization-policies.md)，不要重做。

## 本轮验证证据

Go一直使用`GO=$(bash scripts/resolve-go.sh)`；临时产物位于本轮`$TMPDIR`。

- `"$GO" test ./...`通过：root **2.295s**、internal **5.301s**，dev-debug **4.804s**。
- `"$GO" test -race ./...`通过：root **8.850s**、internal **12.271s**、dev-debug **7.828s**。随后补JSON Number语义及共享向量，针对最终相关代码执行`"$GO" test -race . ./internal/vaultwarden -run 'TestURIDefault|TestDefaultURIMatch|TestOrganizationDefaultURI|TestNativeEditorShows|TestPolicyRecoveryController' -count=1`：root **3.829s**、internal **1.603s**通过。
- `"$GO" vet ./...`、`"$GO" build -o "$TMPDIR/mygo-uri-policy-app" .`、`git diff --check`均通过。
- `swift test --package-path macos --scratch-path "$TMPDIR/swift-uri-build"`最终 **63 tests / 0 failures**，测试时间 **0.282s**。早期全量发现两个旧fixture依赖无来源候选；已明确更新旧候选迁移断言和索引撤销测试的真实sourceIndex+login来源，不放宽生产guard。MemoryKeys不代表真实Keychain/Touch ID。
- `TARGET_BUILD_DIR="$TMPDIR/bridge-output" CONTENTS_FOLDER_PATH=URIPolicyCheck DERIVED_FILE_DIR="$TMPDIR/bridge-derived" ARCHS=arm64 MACOSX_DEPLOYMENT_TARGET=14.0 CODE_SIGNING_ALLOWED=NO bash scripts/xcode-build-bridge.sh`：真实桥动态库编译通过。
- `xcrun swiftc -typecheck -swift-version 5 -module-cache-path "$TMPDIR/autofill-module-cache" macos/Shared/*.swift macos/AutoFill/*.swift`：通过。无签名安装或系统AutoFill运行。
- 共享`internal/vaultwarden/testdata/uri-default-policy-cases.json` **21向量**：全部枚举、排序、角色、disabled、accepted、非法首条和JSON数值形式；Go实际item-key加解密/explicit优先与Swift来源位置/旧规则收窄/pending16对照。`organization_uri_policy_test.go`验证RSA组织投影与同内容checkpoint保留默认，`uri_default_editor_test.go`验证个人/组织创建默认文案与null不固化、显式选择不覆盖。
- `MYGO_VW_POLICY_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLivePolicyExecution$' -count=1 -v -timeout=90s`：body **2.04s**、package **2.169s**通过。新增`uri-default-projection` **0.02s**，真实1.37.4下成员个人的六种默认和显式规则。策略fixture seed不冒充原生管理产品操作；原有12类产品GET/PUT子测 **0.36s**也通过。Go-only认证回执模拟，不能称Swift落盘/实际窗口验证。

本轮实服只创建唯一`mygo-policy-UUID`名称/label的`vaultwarden/server:1.37.4`回环容器和example.invalid账号。cleanup按完整ID+mygo.fixture label核验后仅删除本实例。最终`docker ps -a --filter 'name=mygo-policy-' --format '{{.ID}} {{.Names}}'`无输出，自有实例已清理；无SMTP/CLI/用户资源改动。未读写用户通用剪贴板；Swift套件既有命名测试剪贴板不是用户通用板。提交后状态与SHA见最终报告。

## 下一进程继续原整卡，不重做本轮

1. **组织创建/加入/恢复实际策略消费**，然后主密码minComplexity固定官方兼容zxcvbn基础（词典、版本、用户输入、Unicode、阈值、许可及独立向量）；不能字符类别冒充评分。账号改密产品仍缺时只能称评分基础，之后接真实操作；生成器/Send/PIN等逐项给消费者，不宣称12类均完整执行。本轮没有开始这些模块。
2. 尽快继续legacy无item-key完整共享、附件、Send等尚未实现的大模块，再账号/MFA/SSO/WebAuthn/设备/应急/恢复/通知、大库桥、组织批量/导出、逐项reprompt、无ID数组冲突等原全量矩阵。URI前缀/正则仍是全卡待实现，当前安全跳过不是永久缩减范围。
3. 真实窗口/Keychain/Touch ID/签名安装/系统AutoFill仍未验证。当前恢复controller测试是受控HTTP+模拟认证回执，不要外推为全桥落盘端到端；两次sync不提供CAS，也不能证明未知PUT不会迟到执行。
4. 仅完整整卡完成后由协调者启动独立Review。主目录dirty合并交接由协调者处理，工作线程不得更改主目录。保留当前全部提交与baseline。
