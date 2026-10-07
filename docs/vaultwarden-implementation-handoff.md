# 完整 Vaultwarden 实现：第九轮组织生命周期交接

**INCOMPLETE — 整卡未完成，禁止启动 Review 或合并。** 本轮经 `contact_supervisor(need_decision)` 获准：完成组织生命周期/持久隔离恢复、必要验证、分模块提交、精确清理后交接续启同卡。整卡范围不缩减。前轮全文在 `0045ad8:docs/vaultwarden-implementation-handoff.md`，不回退、不重新导入。

## 提交和隔离

- 本轮起点 `0045ad840245d415c4e2aafa8312d27a4fe2fc02`，保留d3ad954/5a398db及全部前序成果。
- **e260064**：组织生命周期原生管理、write-ahead持久组织隔离、明确联网核验恢复，Go/Swift/headless/真实协议回归。22文件，1301 additions/50 deletions。
- **46ad508**：隔离/恢复回执必须推进revision，恢复一个组织不得顺带移除其他组织隔离；新增headless回归。
- 文档提交接在其后，最新HEAD用 `git log -1` 核对；不能把正文中的历史提交当最终HEAD。
- 唯一写入工作树 `board-2-vaultwarden-api`，分支 `waku/board-2-vaultwarden-api`。未操作主目录 `/Users/vfasky/code/mygo-vaultwarden`，未commit/stash/reset/clean主目录，未读真实凭据/快照、未访问生产vault、未操作用户app/watch、未启动其他子代理。

## 当前新增产品能力

1. `internal/vaultwarden/organization_management.go`：`SaveOrganization`创建/修改、`OrganizationProfile`读取、`LeaveOrganization`退出、`DeleteOrganization`删除。固定源码 `organizations.rs:101/183/224/237/270/276`。
   - 创建每次随机64B组织key，当前经过验证的账户PKCS8/SPKI公钥RSA-OAEP SHA256包装，默认集合名type2；组织名和账单邮箱明文。验证名称/邮箱/长度。可选组织RSA恢复keys未生成；本接口不等于组织恢复功能完成。
   - owner可GET/PUT资料；普通已确认成员可退出；owner删除要求真实当前主密码，使用已认证KDF构造masterPasswordHash，服务器最终验证。最后owner退出由服务器实时拒绝。邮件OTP替代验证未实现。
   - scope/身份/revision/current session、请求取消和refresh checkpoint先落盘。管理操作没有item reprompt授权，不因合法refresh撤销item-grant epoch而错误拒绝请求；测试覆盖checkpoint失败零请求和成功checkpoint可继续。任何写入非预期响应/非事务失败均不盲重试。
2. `organization_management_ui.go`：侧栏创建组织、组织导航→管理当前组织、owner名称/账单邮箱编辑、退出确认、owner主密码删除确认、加载失败重载、取消并锁定、未知结果核对提示。当前组织名来自服务器，表单绑定快照revision，锁定/同步清理；和现有项目/文件夹/批量/备份编辑互斥。
3. 按协调者明确要求，危险请求采用组织级持久隔离，而不是每次全账号logout。API必须提供isolate回调，先安全存储后才能HTTP。隔离失败/旧revision/错误scope/预取消不会发送危险请求；磁盘失败没有已发请求需要补偿，因此不使用全logout兜底。存储回执异常会阻断请求并使界面重新解锁核对，不能伪报成功。发送后的取消/Close/未知结果均保留隔离。
4. Swift `SnapshotStore.quarantineOrganization`：同文件锁、scope、expectedRevision和password unlock授权下原子重封完整payload；保留个人/其他组织和session，过滤目标组织Login投影，新snapshot ID和revision撤销旧lease及候选。不会把目标组织key放入元数据。正常publish继续随机新AES key；隔离重封沿用当前AES key但使用新GCM nonce、新header和密码wrapper，避免为本地隔离创建跨Keychain多阶段事务。
5. 新可选 `VaultData.quarantinedOrganizations` 在AES-GCM认证payload内；旧Go/Swift快照缺字段按空处理，不升version。按scope+org ID隔离。原始server-encrypted `sync` 字节完整保持，不重编码或删除profile新旧列表/集合/cipher字段，因此opaque大整数和未知扩展不丢失。Go `Documents/organizationVaultLocked`统一排除目标文档/keys/集合；Swift统一过滤对应credentials并验证payload不含隔离候选。旧密文仍存在于认证payload内，隔离不等同磁盘安全擦除。
6. 普通publish认证旧payload并合并隔离标记，旧服务器响应不能复活；saveSession保留完整vault及标记。publish默认继续不向一般lease返回vault；bridge主应用显式includeVault并回传规范化vault，Go同步采用该vault，已有隔离却没有正确回执则拒绝。扩展认证读取只拿过滤credentials，完整vault/session仍只属主应用。主密码wrapper损坏时不得覆盖旧payload擦除隔离；需显式撤销本地快照。Swift更换包装key支持显式priorUnlockKey，客户端KDF/key轮换产品仍未实现。
7. 显式恢复：`IsolatedOrganizations`只给名称，侧栏「重新核验：名称」→用户确认→新`SyncWithCheckpoint`→Go验证confirmed/enabled、全局用户ID与member ID、RSA密钥链→专用`restoreOrganizationAccess`发布。Swift再次验证当前成员/用户与旧隔离标记，只取消指定org的隔离；其他隔离保留。普通sync绝不取消。accepted、错误账号/member、网络失败、已退出/删除仍无授权均不恢复；恢复不重发原危险写。全账号显式logout清整个快照，之后登录从服务器重建。

这解决的是组织生命周期；**集合CRUD/访问配置、成员可信邀请确认与角色管理、groups/policies、legacy共享均未在本轮实现**。权限/只读/reprompt/RSA/独立item-key共享等第八轮成果继续保持。

## 验证证据与局限

所有Go通过 `GO_BIN="$(bash scripts/resolve-go.sh)"` 解析。

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race ./...
swift test --package-path macos
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
MYGO_VW_TEST_URL=http://127.0.0.1:32785 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
git diff --check
```

- 最后Go全量root **1.145s**、协议/dev-debug cached；此前实际协议 **1.255s**。build/vet/diff退出0。最后race root **4.777s**、协议/dev-debug cached；此前实际协议race **4.242s**，全部通过。
- Swift **52 XCTest、0 failures**，最终测试 **0.134s/wall0.137s**；bridge typecheck退出0。随后仅Go同步回执安全检查和文档更改，没有无理由重复Swift。
- 最后隔离1.37.4：PBKDF2 **3.30s**、Argon2id **0.28s**、TOTP **0.61s**；总 **4.20s**，package **4.319s**，全通过。真实产品创建组织/默认集合解密、GET/PUT组织资料、最后owner退出拒绝、member restore fixture后产品正常退出、owner密码删除。原组织cipher/RSA/member多集合/直接用户优先group等回归继续通过。
- **真实协议fixture的isolate回调是明确标注的no-op**，只用于独立HTTP互操作；Swift持久隔离另用MemoryKeys测试。不能声称已运行真实安装环境下Go→Swift→Keychain→系统扩展完整端到端。没有SMTP/生产邮件、官方CLI组织互操作、真实窗口视觉/Touch ID/真实Keychain/系统AutoFill安装验证，CLI输出仍明确not requested。
- Go单测：随机org key/RSA/默认集合加密、owner和member权限、正确方法/DTO、主密码hash、无隔离回调/磁盘失败零请求、checkpoint失败零请求与成功可继续、最后owner拒绝不重试、预取消零请求、发送后cancel/Close结果未知、隔离后无文档/keys/集合/重复退出请求。
- Swift新增：隔离后同/独立store重新打开、模拟扩展读取过滤、个人和其他组织保留、session checkpoint轮换保留、普通sync旧授权不能恢复、scope/revision/错误key拒绝、旧lease失效、锁定后离线解锁继续隔离、显式恢复验证accepted/wrong-user/member-account混淆拒绝与正确恢复。既有候选身份/index测试继续通过。没有进程kill/断电的真实故障注入；原子文件写和重开测试是该边界的证据，不能夸大。
- Headless：创建/保存入口、成员仅退出确认取消、编辑器互斥、锁定清表单、持久隔离回执保留个人/session、旧epoch迟到回调不能复活、恢复入口必须显式操作、旧revision/错误恢复回执拒绝、恢复一个组织不得移除其他组织隔离。
- 本轮中间失败均修复：Swift publication默认不能返回vault给普通lease；密码包装轮换需旧key授权、损坏wrapper测试先logout；Go持久化回调原始错误应保留而非假定ErrCheckpoint；发现管理guard误把合法refresh的item epoch变化当失效，改为current session+revision，并增加成功checkpoint测试。最终以上命令全通过。

## 自有资源已清理

- 容器名 `mygo-card2-01a11529-management`，label `mygo-test-owner=01a11529`。
- 完整ID `270d356bd1b51606770d61dd3e00ab5aa1ad10a057fddc35b12a71613b57cffa`。
- 镜像 `vaultwarden/server:1.37.4`，ID `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`，arm64；exec输出Vaultwarden1.37.4/Web-Vault2026.7.0。协议按提供的1.37.4固定commit源码核验，未以Web-Vault版本替代协议版本。
- 仅loopback `127.0.0.1:32785`；bind `/tmp/pi/01a11529-bc1e-70d8-87c3-77ed8787ae1a/vw-organization-management-data`→`/data`。ORG_GROUPS_ENABLED与测试ratelimit开启。账号均随机example.invalid，无SMTP。
- 清理前完整ID重新inspect确认image/label/mount，之后 `docker rm -fv <完整ID>` 成功；只删除上述scratch数据目录，`test ! -e "$TMPDIR/vw-organization-management-data"`通过，精确name filter的docker ps无输出。没有清理其他容器、镜像或用户资源。

## 下一轮继续同一卡，不重做基线

优先 **集合CRUD及users/groups访问配置；成员invite/accept/可信公钥确认/reinvite/角色/revoke/restore/移除；groups/policies产品与真实有效授权；legacy无item-key跨key共享**。本轮生命周期、隔离和恢复已建立，不重复fixture基础。创建的组织缺可选RSA恢复key对/OTP替代验证仍需后续账号恢复模块补齐。

- 新Go接口 `SaveOrganization/OrganizationProfile/LeaveOrganization/DeleteOrganization/IsolatedOrganizations`；危险接口额外`isolate func(SessionCheckpoint) error`是强制write-ahead边界，不得去掉/给产品传no-op。
- 新原生 `organizationEditor` 与 `adoptOrganizationSnapshot`，与session checkpoint同revision协作但允许经过验证的隔离/恢复新snapshot ID；不要复用只允许同snapshot ID的`adoptSessionCheckpoint`处理组织隔离receipt。
- Swift新增bridge操作 `quarantineOrganization` 和 `restoreOrganizationAccess`。新管理端点若会撤销访问，复用持久隔离设计；不得只等成功UI回调或只清内存。主应用sync必须消费Swift规范化vault。
- 固定源码缓存继续 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`；tag对象54a40806c990da2def7acd5a3152edc530c59b79，commit7c188967e7a467b19b2757bc3326f9cf3ccae327，归档SHA256d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7。
- `organizations.rs:466` FullCollectionData `{name,groups,users,externalId}`，users ID是membership，不是global user。`:962/989`邀请，`:1239`accept token，`:1352`confirm包装目标user公钥；`:1475/1483`角色/集合/groups；`:2195/2288/2300`revoke/restore；`:2451/2507/2540`group DTO/create/update；精确读取注册routes和headers授权，不猜语义。
- 成员确认不能照搬fixture静默发key，需验证目标global user public key与member映射，并明确可信指纹/用户确认。已有org权限对特殊管理角色新增/共享目的集合仍保守，后续按服务端有效授权补齐，不能永久拒绝真实有权用户。
- legacy共享需要全部字段重加密、附件key包装、FIDO2和unknown完整性；不能共享user key。独立item-key opaque共享已有，保留。未知不可安全转换请求前拒绝并明确缺口。

其余原卡未完范围全部保留：完整逐注册路由矩阵；组织状态/批量/复制/import-export/冲突安全；完整策略/目录Public API/events/recovery；附件二阶段/MAC/外部URL；Send；注册/profile/keys/主密码/邮箱/KDF/user-key轮换非事务恢复/账号删除清库/stamp/MFA providers/SSO/WebAuthn/devices/auth requests/domains/emergency；SignalR MessagePack；大库桥/query/multipart/binary/Retry-After；个人双改数组逐行冲突UI和reprompt批量/导出。均是客户端待实现，不冒充上游限制。

本轮不自审、不Review、不合并。继续同一卡完整目标。
