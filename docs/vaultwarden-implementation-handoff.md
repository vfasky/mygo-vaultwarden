# 同卡续作交接：12类策略管理与持久待核验屏障

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 从`5ec7e1d45fedf053eeb52e8cc351a93f1ec6dc25`继续，保留全部历史/baseline；本文随本轮提交，实际最新HEAD以`git log -1`为准。协调者已批准本轮在补齐当前安全回归、精确交接和干净提交后续启同卡；原完整范围不缩减。只写本卡工作树，未动主目录/真实凭据/用户app或watch/生产服务，未启动子代理。

## 已落地接口与业务入口

- `internal/vaultwarden/policy_management.go`：`OrganizationPolicies`、`OrganizationPolicy`、`SaveOrganizationPolicy`；固定Vaultwarden1.37.4的12类0/1/2/3/5/6/7/8/14/15/16/20，GET列表/单项与PUT嵌套`policy`真实DTO。管理入口限confirmed/enabled owner/admin，写前读真实成员目录核对角色。私有原值/确认绑定scope与revision；字段标量/范围校验，未知data和未编辑值/大整数保留；保存重读完整策略集及目标策略，变化拒绝。无CAS；0/3可能先撤成员后保存失败，未知结果单次消费、不重试、不伪报回滚。
- `policy_management_ui.go`与`organization_management_ui.go`：组织管理内可发现列表、12类命名控件、启停、当前配置、影响确认/取消、加载错误和锁定撤表单。主密码/生成器字段范围及URI枚举按固定clients源核验；type15上游没有data表单，保留null默认Card或现有数组。type20只有保存类型，无通知消费证据。各策略明确显示已实现/待接消费者，非raw JSON管理页。type16已有2/4可保留但新选择仅官方0/1/3/5。
- 协调者批准扩展`PendingPolicyMutation{organizationId,policyType,mutationId}`：`VaultData`有pending即schema2，无pending为schema1。Go/Swift拒绝v1夹带pending、v2丢pending、未知版本、非法/重复组织与mutationID。旧客户端只认v1，因此不能忽略新字段回流成无屏障。
- `quarantineOrganization`可带`pendingPolicy`，在PUT之前原子写记录和组织marker、旋转revision/candidate、撤旧lease；生产回调核对账号/版本/新SnapshotID/全部旧pending/本次完整记录，失败零PUT。`checkpointLocked`撤旧Go授权；Session保留pending用于新的同步预解密和操作内写guard。type15保守暂停全部个人1–8类型读取/填充/对应保存，type5仅暂停个人create/update等保存，不误禁已有读取/删除/共享。其他组织按自身权限保留。
- 普通Swift publish合并旧认证pending；saveSession/普通组织restore不清pending。完整pending进入Go快照hash；Go/Swift旧候选都过滤。`network.go`拒绝丢pending的publish回执；`adoptOrganizationSnapshot`默认保留全部pending，专用清除只接受原快照确有且新快照确已移除的那条。

## 显式恢复因果链（不要改回普通sync清除）

1. 侧栏隔离组织的专用「读取服务器当前策略以核验」发起新sync，`ReviewPendingPolicy`验证私有候选及特定pending，提取策略/成员元数据，不持有用户密码或vault秘密。
2. 普通publish保留pending/隔离。主控制器核对并采用认证回执；`BindPolicyRecoveryReview`要求已安装的完整快照许可、相同原始sync摘要、紧随源候选的epoch、scope/revision及记录。它不能自行创建离线许可。此预览路径暂时保留组织表单，避免通用adopt清掉新确认。
3. 用户查看当前策略、成员状态并明确确认；`SyncForPolicyRecovery`持Session锁核对当前预览epoch/revision/快照/记录后启动独有新sync。`ValidatePolicyRecovery`比对该候选的策略和成员，单次消费。普通/旧/并行sync、变更状态、取消和旧版本不能清屏障。
4. `restorePolicyAccess(clearingPolicy)`在认证payload只清指定完整记录。成员仍confirmed且key有效才同时恢复该组织；若成员撤销/移除，只解除经新状态核验的个人屏障，组织marker、其他pending与session保留。全部pending清除后回schema1。恢复后再同步重建候选。

原操作在Session锁中结束后才可能进入恢复；重启后必须重新预览。两次sync不是CAS/事务，也不能证明未知PUT绝不迟到执行；界面明确说明该窗口。专用bridge请求是受信主控制器入口，不是抵御任意同进程代码的权限沙箱；真实平台认证依旧依赖既有Swift存储链。

## 验证与实际边界

工具链始终`GO=$(bash scripts/resolve-go.sh)`；全部产物/下载在当前`$TMPDIR`。

- 最终主体`"$GO" test ./...`：root **1.718s**、internal **5.513s**；`"$GO" vet ./...`与`"$GO" build -o "$TMPDIR/mygo-policy-app" .`通过。
- `"$GO" test -race ./...`：root **6.475s**、internal **12.214s**，通过；dev-debug使用已通过缓存。后续补策略JSON语义比较（忽略格式/键顺序、保留大整数区别）与提示文案；`"$GO" test -race . ./internal/vaultwarden -run 'TestPolicy|TestPending|TestAllPolicy|TestOrganizationIsolation|TestOrganizationRestoration' -count=1`再次通过，root **2.101s**、internal **4.151s**；最终vet/build/diff检查通过。
- `swift test --package-path macos --scratch-path "$TMPDIR/swift-policy-build"`：**61 tests / 0 failures**，最终0.214s测试时间。MemoryKeys，不是Keychain/Touch ID实测。
- `TARGET_BUILD_DIR="$TMPDIR/bridge-output" CONTENTS_FOLDER_PATH=PolicyCheck DERIVED_FILE_DIR="$TMPDIR/bridge-derived" ARCHS=arm64 MACOSX_DEPLOYMENT_TARGET=14.0 CODE_SIGNING_ALLOWED=NO bash scripts/xcode-build-bridge.sh`：真实桥动态库编译通过，无错误输出。
- `xcrun swiftc -typecheck -swift-version 5 -module-cache-path "$TMPDIR/autofill-module-cache" macos/Shared/*.swift macos/AutoFill/*.swift`：通过。没有签名安装或系统AutoFill运行。
- `MYGO_VW_POLICY_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLivePolicyExecution$' -count=1 -v -timeout=90s`：最终body **1.97s**、package **2.079s**；新增十二类产品管理子测 **0.29s**。GET/list/PUT走产品方法，显式恢复走新的绑定/专用sync API；隔离/发布回执由受信Go-only fixture模拟，不能当作真Swift落盘或窗口证据。
- `policy_management_test.go`：12类DTO/null/未知data、大整数保留、角色、确认修改/重放、旧revision、取消、checkpoint失败零PUT、HTTP未知结果。`policy_management_failure_test.go`：0/3先副作用再失败的HTTP模拟（不是实服SMTP故障）、类型15未知/持久后取消、同步失败/关闭会话/带pending重建会话仍禁个人读取、session保留。
- `policy_recovery_test.go`：未绑定/错误pendingID/旧revision/普通sync/策略变化/重复确认拒绝；成员撤销后重新预览只能恢复个人、不恢复组织。Go/Swift共享`internal/vaultwarden/testdata/pending-policy-cases.json`核对12类型scope、多记录/重复/未知版本/降级。Swift补普通publish/token/组织restore保留、旧lease/重启候选、多pending只清一条且保留组织marker与session。
- `policy_management_ui_test.go`：headless角色入口、配置标签、pending专用恢复入口、普通回执不能丢pending及锁定撤表单。**没有真实原生窗口视觉检查、完整原生两阶段交互的自动端到端故障注入、Keychain/Touch ID/签名安装、Safari系统AutoFill、真实平台MFA或剪贴板测试。**

隔离实服每次为唯一`mygo-policy-UUID`名称/label，127.0.0.1随机端口，`vaultwarden/server:1.37.4`，example.invalid账号。cleanup核对完整容器ID与mygo.fixture label后仅删除自身实例。最终`docker ps -a --filter 'name=mygo-policy-' --format '{{.ID}} {{.Names}}'`无输出；所有本轮自有实例已清理。无SMTP/CLI/用户资源操作。git diff检查及提交后clean status见最终报告。

## 下一进程直接继续，范围不缩减

1. 本轮策略管理及屏障已接，不重做五链。先定向读`docs/organization-policies.md`的新字段表和因果链。还需完善真实原生两阶段全交互测试/错误回执注入和平台运行证据；任何发现的恢复边界问题先修，不能误把当前模块当整卡完成。
2. **type16默认URI实际消费**仍缺：`policy_execution.go`、`sync.go:decryptCipher`、`organization_autofill.go`及Swift旧候选需统一。固定clients `autofill/services/domain-settings.service.ts:225–246`用`policiesByType$`→`getFirstPolicy`，`default-policy.service.ts:272–306`决定角色豁免；`models/domain/domain-service.ts`为0域名/1主机/2前缀/3精确/4正则/5从不。最新表单只选0/1/3/5；不要误换3/4。个人/组织未显式URI规则才应用默认，现有projection只支持0/1/3，其余规则能力需诚实核对。
3. 继续组织创建/加入/恢复相关策略消费；`minComplexity`须固定clients/SDK兼容zxcvbn，核实依赖许可/固定版本/独立向量，不能用字符类别替代。生成器/Send/PIN/账号等缺依赖产品仍在原范围，界面只标待接，不伪造已执行。
4. 然后原完整legacy共享、附件、Send、账号/MFA/SSO/WebAuthn、设备/应急/恢复/通知、大库桥、组织批量/导出、逐项reprompt、无ID数组冲突等按总矩阵继续。旧opt-in fixture若不符合可信回执须修fixture，不放宽生产guard。
5. 只有完整整卡实现后协调者独立Review；主目录dirty交接由协调者处理，本工作线程不得碰主目录。保留当前HEAD全部历史与用户baseline。
