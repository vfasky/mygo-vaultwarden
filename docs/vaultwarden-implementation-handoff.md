# 完整 Vaultwarden 实现：第十一轮成员增量交接

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 协调者本轮通过 `contact_supervisor(need_decision)` 批准：完成成员增量必要回归、准确清理、提交与精确交接后续启同卡；原完整范围不变。历史集合交接见 `9db25dc:docs/vaultwarden-implementation-handoff.md`；完整剩余范围与实际能力见[覆盖矩阵](vaultwarden-api-coverage.md)。不要重新导入baseline/重做旧模块。

## 提交和唯一工作树

- 起点 `9db25dc704fa59ad3691aa1a78402218e88e32a1`；全部旧成果/baseline保留。
- **de600f97bd1f892af2d52de13542759d8df35bf6**：成员原生流程、可信公钥确认、直接关系保留与角色副作用确认，16文件、1861 additions/16 deletions。
- 本交接另有后续文档提交，**以git log -1为当前HEAD**。
- 仅修改/提交 `board-2-vaultwarden-api` / `waku/board-2-vaultwarden-api`。未改主目录 `/Users/vfasky/code/mygo-vaultwarden`，未commit/stash/reset/clean主目录；未读真实凭据/接生产vault/发真实邀请邮件；未操作用户app/watch；未启动子代理。

## 本轮接口与已落代码

- `internal/vaultwarden/member_management.go`：`MemberDirectory`私有scope/revision/org/rows，`Members/Clone/Close`。`OrganizationMembers`校验owner/admin、本账号member/global-user映射、重复身份、status/type、完整目录，非admin零HTTP。`InviteOrganizationMember`一次一邮箱+角色（普通/经理/管理员/owner），初始无集合/群组分配；`ChangeOrganizationMember`负责reinvite/revoke/restore/remove，操作前重读目标、角色/status/身份变化冲突。reinvite管理员可操作所有邀请，不能revoke/restore自己；remove自己先持久隔离，再允许任何HTTP，最后owner服务端实时判定。
- `PrepareMemberConfirmation`生成不含org key的私有`MemberConfirmation`。UI要求从独立可信渠道获得完整Base64 DER/SPKI，精确相等才能确认；`ConfirmOrganizationMember`重读成员与global user公钥，替换则冲突，只用该RSA公钥OAEP-SHA256(type3)包装64B组织key，绝不共享account user key。SPKI限定RSA2048–4096/e65537/规范编码。**不是官方词组指纹，未实现词组算法**。独立可信渠道由用户核验，不能声称客户端可以证明恶意服务器的成员映射真实性。
- `member_invitation.go`：`AcceptOrganizationInvitation`解析固定1.37.4邮件fragment链接（`mail.rs:287–332`），校验当前server/host/base path/email、唯一参数/ID，不跟随外部URL，发送token给当前认证服务器，服务端JWT签名验证最终权威。`AccountSharingPublicKey`从认证本机私钥推导自己的公钥供可信通道传递。**普通接受已落API/UI及HTTP单测，但真实SMTP token接受尚未验；要求自动加入账号恢复的邀请未实现**。
- `member_roles.go`：`PrepareMemberRole`从真实 `/collections/{id}/users` 和 `/groups/{id}/users`收集直接分配，不能用member详情（full-access group时省略collections）或有效权限替代。完整分页/目录失败/缺失/重复/跨org/错把global userID当memberID均拒绝；直接rights和opaque大整数保留。`SaveMemberRole(ctx,vault,draft,consent,isolate,persist)`提交前重读全关系，无服务端CAS，GET→PUT仍有并发窗口。只有目标为本账号时强制写前隔离；他人关系冲突保稿，自己已隔离后优先清理失效表单。
- `member_management_ui.go`与`organization_management_ui.go`：组织管理→成员列表/姓名邮箱/邀请角色/单人确认；公钥核验表单；角色编辑、全组织访问副作用清单；侧栏「创建或加入组织」→敏感邀请链接接受、自己的共享公钥（可选取复制文本，不调用通用剪贴板）。后台Clone、epoch、锁定/同步/隔离清理，迟到响应不能重开。未知结果禁原表单再提交，只同步核对。README/coverage/organization-vault同步。

## 两项已明确批准的协议产品决策（必须保留）

1. **UseGroups=false时角色零写入阻断**：1.37.4 `organizations.rs:1590附近`角色PUT始终删除重建GroupUser，`:2410–2435`关闭群组返回空目录，无法证明隐藏历史关联为空。无真正role-only/partial保留路径（已定向核对注册routes/DTO）。提示管理员启用服务器群组后重新加载；不自动改服务器配置，不提供“丢弃不可见关联”绕过；保留尚未提交角色草稿。此组合是安全兼容边界，不能说所有角色管理未实现。源码+模拟数据已测，**未另启关闭群组实例实测**。
2. **晋升access_all清直接集合须明确授权**：同文件`:1545–1572`先删直接集合，owner/admin/全集合经理因access_all不再重建。UI列出全部可读集合名/只读/隐藏/manage标记，说明授予全组织访问、群组保留、今后降级不自动恢复。`MemberRoleDraft.ConfirmCollectionReset()`生成私有`MemberRoleConsent`绑定scope/revision/member/原角色/目标角色/原collections/groups/permissions/可读清单；Save默认缺consent零写，修改目标/关系使旧确认失效。取消不提交；不得后台补写/回滚。提交前角色/关系变化冲突（UI清旧确认、保稿）；自己变更前隔离优先安全。真实1.37.4晋升删除直接关系、group保留、降级不恢复已验证。

## 验证与未验证范围

Go始终使用 `GO_BIN="$(bash scripts/resolve-go.sh)"`。最终相关命令：

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race ./...
MYGO_VW_TEST_URL=http://127.0.0.1:32788 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
swift test --package-path macos
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
git diff --check
```

- 最后Go全量root cached、协议 **2.097s**、dev-debug cached；build/vet通过；race root **5.083s**、协议 **6.132s**、dev-debug **7.429s**；diff通过。
- Swift **52测试/0 failures/0.206s(wall0.210s)**，bridge typecheck通过。Swift源码本轮没改，仅回归既有持久隔离与桥；日志 `$TMPDIR/members-swift-tests.log`。
- 最后隔离1.37.4 **4.18s/package4.299s**：PBKDF2 **3.41s**、Argon2id **0.20s**、TOTP **0.57s**。产品invite/confirm/角色晋升清分配保group/降级不恢复/revoke/restore、unregistered invite/reinvite/remove、最后owner移除拒绝，原集合/权限/AutoFill回归通过。fixture中仍有直接HTTP设置group和部分角色/分配，不能声称group产品完成。真实HTTP isolate仍明确no-op，实际持久层由Swift替身测。
- 新单测：正确RSA收件人与org key、public rows拷贝不能篡改内部身份、公钥替换拒绝、预取消/旧revision、checkpoint失败零HTTP、自己角色与移除隔离失败零HTTP、Close在DELETE dispatch后结果未知且仅一次；链接server/email/重复参数/ID拒绝、自己的公钥来自本机私钥；UseGroups关闭角色阻断保稿、不完整目录零写、关系变更冲突、直接与继承区分/opaque保持、副作用清单、缺确认/旧目标/旧关系确认失效。headless覆盖管理员入口、接受确认/取消、锁定清输入和无认证草稿拒绝。
- **未验证**：SMTP投递与真实JWT邮件接受、用户实际可信渠道现场核验、真实窗口/Touch ID/Keychain/签名安装/AutoFill扩展、本轮官方CLI互操作。headless未等于全部成员表单视觉实测。邀请自动recovery enrollment尚缺，不是服务器不支持。
- 中间失败均有解释：一次新checkpoint单测错误期待ErrCheckpoint但现有checkpoint返回原storage error，修正断言后通过；一次live末尾TOTP遇实例IP **429**（自有容器日志确认），重启该实例清缓存；重启动态映射32787→32788，首次旧端口连接失败，inspect后新端口全通过。不要隐瞒这些，不是未解决产品失败。

## 自有资源已精确清理

- 名 `mygo-card2-01a11565-members`，label `mygo-test-owner=01a11565`。
- 完整ID `48152cf27d6bc0688c30905c719a64d3763a28a9e008902c4bfeec1d598f4821`；镜像 `vaultwarden/server:1.37.4` arm64 ID `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`，revision `7c188967e7a467b19b2757bc3326f9cf3ccae327`。
- 只loopback，原32787，重启后32788。bind `/tmp/pi/01a11565-4624-767e-a670-92a33ed74510/vw-members-data`→`/data`。`SIGNUPS_ALLOWED=true`、`ORG_GROUPS_ENABLED=true`；无SMTP，全部随机example.invalid虚构账号。
- 清理前inspect逐项核对ID/name/image/label/port/mount；`docker rm -fv <完整ID>`成功，精确删除上述scratch数据目录，`test ! -e`通过；精确name filter的docker ps无输出。未删除镜像/其他容器/用户资源，未启SMTP或CLI profile。

## 下一进程直接继续

先git log/status+本文+coverage成员行。优先补**成员真实隔离SMTP邀请/接受/reinvite与相关政策自动recovery enrollment、更多角色故障/权限与UI完整验证**；接着groups/policies、legacy无item-key完整共享及原整卡附件/Send/账号/MFA/通知/桥/完整离线/备份等未完成范围，仍不能停止于成员模块。大库4MiB等已知缺口仍在原卡/coverage。

固定源码 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`：邀请/接受/confirm `src/api/core/organizations.rs:962–1430`；roles `:1475–1592`、revoke/restore `:2195–2380`；groups `:2390–2745`；恢复 `:2790–3020`；成员投影 `src/db/models/organization.rs:536–660`；邮件链接 `src/mail.rs:287–332`；public user key `src/api/core/accounts.rs:557–569`。clients/SDK固定hash见coverage，勿自创官方指纹。组织恢复RSA钥对仍未生成、auto-enroll流程需要按固定官方源码核实后实现，未在本轮完成设计，不能猜用户key分发。

不自审、不Review、不合并；提交后保持干净，由协调者续启同卡。
