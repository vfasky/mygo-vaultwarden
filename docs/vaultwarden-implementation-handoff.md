# 完整 Vaultwarden 实现：第十轮集合管理交接

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 协调者本轮通过 `contact_supervisor(need_decision)` 明确批准：完成集合模块回归、提交、精确清理和INCOMPLETE交接后续启同卡，原完整范围不变。历史交接见 `b2e6ed1:docs/vaultwarden-implementation-handoff.md`；当前能力/剩余整卡范围见 [覆盖矩阵](vaultwarden-api-coverage.md)，不要重复导入基线或重做旧模块。

## 提交与唯一工作树

- 起点 `b2e6ed121557bf3583dddad3b0fe39293fc8dfa1`，保留全部前序成果。
- **49724bd**：集合原生CRUD、成员/群组集合访问配置、持久隔离复用、多角色真实协议和安全回归，14文件，1349 additions/10 deletions。
- 本交接另有后续文档提交；**以 `git log -1` 为最新HEAD**。
- 仅写入 `board-2-vaultwarden-api` / `waku/board-2-vaultwarden-api`。未改主目录 `/Users/vfasky/code/mygo-vaultwarden`，未commit/stash/reset/clean主目录，未读真实凭据/快照，未访问生产vault或发送真实邀请，未操作用户app/watch，未启动子代理。

## 本轮已接产品与文件地图

- `internal/vaultwarden/collections.go`：`CollectionDetails(ctx,vault,orgID,collectionID,persist)`返回绑定scope/revision的 `*CollectionDraft`；空collectionID准备新草稿。`SaveCollection(ctx,vault,draft,isolate,persist)`；`DeleteCollection`同样要求危险写前isolate。详情使用完整 `/collections/{id}/details`，不拿sync投影冒充完整访问配置。名称type2/org key；保留users/groups/externalId与opaque，包括大整数及未修改访问条目未知字段。
- `internal/vaultwarden/collection_access.go`：`CollectionAccessDetails(ctx,vault,source,persist)`返回独立草稿，从 `/users/mini-details` 获取姓名/邮箱及membershipID/globalUserID映射，从启用时 `/groups` 获取群组名字与组织归属。`CollectionDraft.Access`是业务选择项；私有原目录验证身份，不能伪造任意成员/账号ID。未列出的旧条目继续保留。`Clone/Close/AccessChanged`用于后台副本、清理和确认。
- `organizations.go`增加 `UseGroups` 和 `CanCreateCollections()`。**profile没有accessAll字段**；经理type4必须具备官方 createNewCollections/editAnyCollection/deleteAnyCollection 三项permissions才可创建。owner/admin创建；集合级经理只能管理已有manage集合；普通成员不能管理。三项规则来自固定上游manager-as-custom转换，不从角色数字大小推断。
- `collection_management_ui.go`、既有 `organization_management_ui.go`：组织导航→管理当前组织→集合列表/新建/名称编辑/删除确认；配置成员与群组访问→姓名邮箱/群组名称、分配/移除、只读/隐藏密码/管理控件→保存确认。没有raw JSON编辑器。未知结果禁当前表单重复提交；锁定/同步/隔离清表单，后台独立Clone和epoch防迟到恢复。
- 测试：`collections_test.go`、`collection_access_test.go`、`collections_integration_test.go`、`collection_management_ui_test.go`；扩充 `organization_members_integration_test.go`，把成员只读/隐藏、取消直接分配改为调用产品集合接口。成员邀请/确认/角色变更等fixture仍不是产品实现。
- README、coverage、organization-vault已同步。Swift存储实现本轮未修改，复用既有持久组织隔离/显式恢复能力。

## 必须保持的边界

1. 访问数组的ID是membershipID，不能用global userId。目录校验当前member/account双向映射、重复用户/成员、群组组织归属；配置变更只来自认证目录。UseGroups关闭时不请求群组目录，不抹掉原有不可编辑群组分配。
2. 仅更名不隔离。修改**已有集合访问**或删除集合在任何HTTP之前先 `checkpointLocked(isolate)`→Swift `quarantineOrganization`；隔离失败零HTTP（包含保存前GET）。保守隔离整个目标组织，保留个人和其他组织。无产品no-op回调。
3. 普通sync不能撤隔离。成功/错误/取消/结果未知都保留隔离；用户从侧栏「重新核验：组织名」明确确认，新sync验证confirmed/enabled、member/account、RSA钥链后由专用restore发布恢复，**不会重新提交原集合操作**。正常成功访问调整后也走这条恢复路径。不是永久锁死，也不是悄悄自动恢复。
4. 保存前新GET逐字段核对原详情，有差异返回ErrConflict。**服务端没有集合CAS，GET与PUT之间仍有竞争窗口**；不声称严格CAS/事务。数组重排保守视作冲突。服务器更新访问会先删除再重建，任意非200/意外成功响应按未知结果，不重试。保持未编辑数组/条目/unknown是请求级保证，不能保证上游存储未知扩展。
5. 集合删除仅解除关联，不删除组织cipher。管理权不能与只读/隐藏限制同时新配置。离线仍只能依据最后一次认证快照；没有远端实时撤销通知。

## 验证与实际边界

Go均经 `GO_BIN="$(bash scripts/resolve-go.sh)"` 解析。最终命令：

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race ./...
MYGO_VW_TEST_URL=http://127.0.0.1:32786 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
swift test --package-path macos
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
git diff --check
```

- 最后Go全量root **1.257s**、协议 **1.643s**、dev-debug cached；build/vet/diff退出0。最终race root **5.284s**、协议 **4.963s**、dev-debug cached。
- Swift **52测试、0 failures，0.166s/wall0.170s**；bridge typecheck退出0。本轮Swift未改，因集合新写路径复用持久隔离而重跑。日志 `$TMPDIR/collections-swift-tests.log` 是临时日志。
- 最后隔离1.37.4：PBKDF2 **3.36s**、Argon2id **0.20s**、TOTP **0.54s**，总 **4.10s** / package **4.221s**。实际owner和全组织经理CRUD、集合级经理details/mini目录/更名、禁止创建、普通成员禁止管理；产品访问配置直接成员readOnly/hidePasswords覆盖group、取消直接分配后group回退，连同多集合有效权限和AutoFill投影回归全部通过。
- 单元：opaque大整数/未知条目保持、旧详情冲突、目录账号/成员混淆、clone隔离、manage不一致拒绝、revision/预取消、refresh checkpoint失败零请求、持久隔离失败零HTTP、删除dispatch后取消/Close结果未知且不重试。headless：角色入口、姓名/邮箱业务控件、权限联动、危险确认、锁定清理；既有持久隔离/旧lease/候选/显式恢复测试继续通过。
- **真实HTTP fixture的isolate是明确no-op**，仅验证协议；持久存储另由Swift MemoryKeys测试。未运行真实Go→Swift→Keychain→系统扩展全链路、真实窗口/Touch ID/安装、官方CLI本轮组织互操作、SMTP邮件接受、公钥用户现场核验。不能把headless和替身说成这些已验证。
- 中途仅一次编译失败（新增UI权限标签helper漏定义），补齐后全部通过；没有未解决失败。

## 自有资源清理完成

- 容器 `mygo-card2-01a1154b-collections`，label `mygo-test-owner=01a1154b`；完整ID `a42374abafb9030c9f4a4d6b995ac9e454f67cfc3d2c57eb74ede47f764c2e21`。
- 镜像 `vaultwarden/server:1.37.4` arm64，ID `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`；inspect revision `7c188967e7a467b19b2757bc3326f9cf3ccae327`。
- 仅loopback `127.0.0.1:32786`；bind `/tmp/pi/01a1154b-10a3-72f2-b1a6-2690b4796eff/vw-collections-data`→`/data`。随机example.invalid账号，无SMTP。
- 清理前重新inspect核对完整ID/name/image/label/mount/port；`docker rm -fv <完整ID>`成功，仅删上述scratch数据目录；`test ! -e`通过，精确name filter的docker ps无输出。未删其他容器/镜像/用户资源。

## 下一进程直接继续，不重复调查旧模块

首先看git log/status、本文与coverage相关行即可。下一步按协调者要求：**成员invite/accept/可信公钥确认/reinvite/角色/revoke/restore/remove原生闭环，然后groups/policies、legacy无item-key共享及整卡余项**。成员/群组生命周期仍未实现，集合bulk-access/批量删除也缺；其他完整范围继续见coverage/原卡，未缩减。

固定上游源码仍在 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`（1.37.4 commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`，完整tag/归档hash见coverage）。定向入口：

- `src/api/core/organizations.rs:962/989`邀请；`:1239`接受token；`:1352`确认包装key；`:1433`mini-details；`:1475/1483`角色/集合/groups；`:2195/2288/2300`revoke/restore；`:2451/2507/2540`group DTO/create/update。
- `src/db/models/organization.rs:438–535`profile（manager permissions；没有accessAll）；`:536–710`完整成员与mini详情（memberID/globalUserID）。
- `src/auth.rs:886–1006`ManagerHeaders/Loose；集合明细 `organizations.rs:744–795` 返回真正直接users，列表access-details会额外混入manage-all成员，不可用列表替代原始详情进行完整PUT。
- 确认成员时必须重新验证组织member与global user public-key映射，UI明确可信校验确认。可核对完整DER/SPKI公钥；若实现词组指纹，先读固定官方 clients `web-v2026.5.0` commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 的实际实现，**未在本轮定位/实现指纹算法，不得自创哈希冒充官方词组**。集成fixture的静默RSA发key不可照搬到产品。
- 新增管理请求继续session guard/checkpoint；当前账户可能失权的写入复用强制isolate与明确恢复，不能只等成功回调撤权。最后owner、角色边界、多个成员部分成功必须真实处理。独立item-key共享保持已有opaque支持，legacy重加密不得把user key共享给组织。

本轮不自审、不Review、不合并；提交后保持干净，续启同卡。
