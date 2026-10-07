# 完整 Vaultwarden 实现：第十二轮邀请恢复登记交接

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 本轮协调者通过 `contact_supervisor(need_decision)` 明确批准：完成必要回归、清理、提交与精确交接后续启同卡，原完整范围不缩减；下一轮直接 groups/policies，不重做成员/邮件基线调查。本文所在提交后的 HEAD 为最新，以 git log/status 为准。

## 当前提交与范围

- 本轮实现提交：**967eb5bab96860d8278e1bab6b316b00dc8911bf**（19 files，1531 insertions/66 deletions）。本交接随后单独提交。
- 起点 `a20d02c44ac49a84cbb7f526fe5caf5484d1a58a`，前序成员 `de600f97`、集合 `49724bd` 及用户基线 `4b0a910` 全部保留，没有重新导入/回退。
- 唯一实现者，只改本 Board 工作树；主目录 `/Users/vfasky/code/mygo-vaultwarden` 未写入、暂存、提交、stash/reset/clean。没有启动子代理、用户应用/watch、外发真实邮件或接生产 vault。
- 功能及逐路由边界见[覆盖矩阵](vaultwarden-api-coverage.md)、[本轮专题](organization-invitation-recovery.md)。完整恢复管理仍缺，不把邀请auto-enrollment当成完整recovery。

## 已实现接口与原生流程

1. `internal/vaultwarden/invitation_acceptance.go`：新增 `PrepareInvitationAcceptance`、私有字段 `InvitationAcceptance`、`AcceptPreparedInvitation`。严格当前server/basepath/email/唯一参数校验，fragment用EscapedFragment避免二次解码；profile验证account/email/同org与membership，发现accepted/confirmed返回`ErrInvitationAlreadyAccepted`，不能重复POST。读取token政策，type8+autoEnrollEnabled时要求有效组织RSA SPKI。确认绑定scope/revision/authorization epoch/组织/成员/token/策略数据/组织公钥；提交前重新读取，变更拒绝。用户明确同意+完整独立可信公钥相同才用RSA-OAEP-SHA256 type3包装当前64B user key。不是org key、不是主密码。一次确认只允许一次最终请求，unknown不重放。
2. `member_invitation.go` 普通 `AcceptOrganizationInvitation` 现在调用上述流程且无隐式恢复同意；要求恢复时安全拒绝并由新原生流程完成。`member_management.go` 提取带guard的写入助手，确认后checkpoint epoch改变则请求前拒绝；已有成员操作语义保持。
3. `organization_recovery_keys.go`：新建组织生成独立RSA公私钥（2048-bit），PKCS8私钥由组织64B key type2加密、SPKI公钥明文；`OrganizationRecoveryPublicKey` 给owner提供GET公钥及显式初始化缺失钥对。先GET，公钥非空不替换；缺字段响应拒绝，不当作未初始化。POST返回公钥及密文必须逐字匹配，所有非确定结果都需核对、不自动重试。`SaveOrganization` 的create体增加固定协议`keys`，更新组织不改钥对。
4. 原生 `member_management_ui.go` / `organization_management_ui.go`：先核验策略，再显示接受或“同意账号恢复并接受邀请”；明确组织可恢复账号并访问个人密码库，须独立可信组织公钥输入。取消/锁定清确认和敏感链接，未知结果禁原表单再提交。准备期间刷新checkpoint发布新revision时丢弃旧草稿，保留输入并提示重新核验。owner组织管理增加恢复公钥读取、初始化说明/确认/取消。原三栏与Logo未改。
5. `client.go` 支持相对固定路由query，单独设置RawQuery保basepath与编码；拒绝绝对/cross-host URL、路径点段/反斜杠/编码路径替代、fragment/无效query。HTTPS/loopback、禁止重定向、有限响应、刷新先checkpoint保持；不是通用HTTP操作台。
6. `scripts/invitation-smtp/main.go` + `member_smtp_integration_test.go`：可重复的显式opt-in自有Docker/SMTP测试，只容器回环SMTP、只收example.invalid、不转发。唯一容器ID+label、唯一host回环端口，`/vault-fixture` basepath，关闭groups、启用SMTP、临时存储；先create记录ID并注册清理，再start，启动失败同样清理。

## 本轮真实覆盖与失败边界

`MYGO_VW_SMTP_TEST=1` 两种场景（普通/auto-enroll）均：自有SMTP capture invite与reinvite两封MIME邮件→真实JWT接受→accepted不释放org key→对受邀人完整SPKI可信确认→org key可用。

- 本地错误basepath/email、重复token、cancel拒绝；更改链接email匹配错误当前账号后真实服务JWT身份拒绝；伪造签名拒绝；用**刚创建自有服务器**的临时签名钥构造正确签名过期JWT，真实服务拒绝。未读任何用户服务密钥。accepted后再次准备拒绝，不重复accept。
- auto-enroll：读取真实policy、公钥，缺用户同意拒绝；服务保存登记后owner经测试HTTP读取reset-password-details，用当前org key解开组织RSA私钥，再解开resetPasswordKey，结果精确等于该受邀账号user key。没有执行密码重置/MFA恢复。
- `UseGroups=false` 实例上角色准备真实返回 `ErrMemberRoleGroupsDisabled`，保留隐藏历史关系，未声称该配置可无损改角色。
- 单元：policy/key改变零写、未同意/错误可信key零请求、外org policy拒绝、坏key、scope/revision/epoch、checkpoint失败、一次确认消耗、503未知结果、POST期间Close取消/零重试、初始化key分离/既有key不覆盖、query/basepath/cross-host。
- headless：策略准备前无接受按钮、邀请确认取消/锁定、owner恢复key原生入口/初始化确认取消/锁定。不是完整窗口、Keychain、Touch ID、系统AutoFill、签名安装验证。
- 接受与后续服务端邮件/登记副作用不可当作端到端事务；非成功状态均可能部分完成，app提示sync核对。profile已accepted而登记未完成，不会盲accept；后续既有成员登记/恢复产品尚需实现。
- GET profile/policy/key→accept之间无服务器CAS。服务器并发改policy时可能拒绝/部分执行，未伪造严格CAS。策略检查目前只auto-enroll分支，完整主密码等客户端策略仍缺。

## 最终实际验证命令与结果

Go均使用 `GO_BIN=$(bash scripts/resolve-go.sh)`。

```sh
"$GO_BIN" test ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race ./...
MYGO_VW_SMTP_TEST=1 "$GO_BIN" test ./internal/vaultwarden -run '^TestLiveSMTPInvitations$' -count=1 -v
git diff --check
```

- 最后全量：root cached、协议 **2.463s**、dev-debug cached、SMTP工具编译无独立单元；build/vet通过。
- race：root **5.411s**、协议 **6.564s**、dev-debug cached。
- SMTP最后回环：普通 **1.89s**、auto-enroll **1.72s**，整个test **3.62s/package3.742s**。
- 随后只修改UI在准备期refresh checkpoint后的旧草稿处置，针对性 `go test .` **1.510s**、`go vet .`通过、`go test -race .` **5.288s**；没有相关协议改动，不重复SMTP。
- `git diff --check`、已暂存diff检查通过；实现提交后最终工作树检查在交接提交后执行。
- 本轮**未运行Swift/bridge**：源码/桥协议未改，没有必要重复上轮已通过52 Swift测试与bridge typecheck。该历史证据在 `a20d02c:docs/vaultwarden-implementation-handoff.md`，不能冒充本轮新执行或真实平台通过。
- 开发中失败已修正：Docker未声明临时存储导致首两次readiness失败；fragment特殊字符单测发现重复解码；checkpoint测试预期改为准确保留回调错误；新增Close故障测试最初等待httptest连接context导致整段命令60s超时，改为测试控制释放server后该故障测试 **0.09s**通过，全量/race随后均通过。超时后精确进程查询无残留测试子进程。

## 自有资源清理

所有SMTP容器由测试cleanup按完整ID+唯一`mygo.fixture`标签核对后 `docker rm -fv ID`，包含readiness失败实例；没有删除镜像或其他容器。后续 `docker ps -a --filter 'name=mygo-smtp-'` 无输出。Go t.TempDir位于本轮 `$TMPDIR=/tmp/pi/01a11580-c8fe-77d9-9073-d539ef3c97f3`，SMTP邮件/token/临时binary由测试清理；JWT私钥副本读取后立即删除且只来自本测试容器。最终Bun只查本轮TMPDIR：`SMTP test temporary directories remaining: 0`。保留的同版本公开源码参考文件不含测试邮件/私钥，不涉及用户目录。

## 下一轮直接继续（原完整范围不缩减）

1. **groups CRUD/成员及集合配置**：固定服务器 `src/api/core/organizations.rs:2390–2745`；已有 `CollectionAccessDetails`、`MemberRoleDraft` 的读groups与成员/集合访问投影可复用，需原生业务表单、真实权限/取消/未知结果/先持久隔离（当前用户或org访问回收时），禁止raw JSON管理台。现有UI组织编辑器分工文件 `collection_management_ui.go`、`member_management_ui.go`、`organization_management_ui.go`。
2. **policies业务表单与真实客户端策略约束**：固定 `organizations.rs:1923–2190`；本轮只有邀请token读type8，不能把其它策略忽略当支持。主密码策略检查、2FA/SingleOrg执行等仍缺，政策修改可能影响成员权限，沿用持久隔离边界。相关source权限在org_policy.rs/model及enforcement helpers。
3. **legacy无item-key完整共享**；再接原始完整附件/Send、账户注册/profile/轮换/MFA/SSO/设备/emergency/recovery、通知、完整offline迁移/AutoFill与大库4MiB桥、全格式backup/copy/import含附件FIDO2和组织、双改无ID数组逐行冲突/reprompt bulk-export等。所有原卡范围仍有效。
4. 本轮未单独验证旧组织钥对初始化真实服务成功路径（已有mock crypto/权限），完整管理员恢复和既有成员enrollment/退出仍缺，后续恢复模块补。成员普通/恢复邮件流程已经有可重复夹具，不重复全库调查。

固定VW缓存仍 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`；固定源码与本轮精确文件参考见专题。正文列的是本轮真实覆盖，不代表整卡达到验收。协调者需在完整卡实现后才创建独立Review；主目录dirty的最终merge交接仍由协调者处理。
