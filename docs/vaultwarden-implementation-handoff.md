# 完整 Vaultwarden 实现：第七轮阶段交接

**INCOMPLETE — 整卡未完成，禁止据此启动 Review 或合并。** 本轮已通过 `contact_supervisor(need_decision)` 得到明确批准：完成最后安全回归、文档、提交和自有资源清理后精确交接，续启同一卡。下轮直接推进组织密钥/权限产品闭环，不重复导入或重做个人基线。原整卡验收范围不缩减。

## 提交与工作区

- 唯一写入目录：分配的 `board-2-vaultwarden-api`；分支 `waku/board-2-vaultwarden-api`。主目录 `/Users/vfasky/code/mygo-vaultwarden` 未写入、暂存、提交、stash/reset/clean；用户app/watch、凭据、其他容器均未操作；未访问生产服务、未启动子代理。
- 起点 **5c2da9369d7a527c515ea7cb23ed8f7a619ea5cc**，保留 `ad6aef0/cbe30c5/ddb2ca5` 及全部前序成果。前六轮证据：`git show 5c2da93:docs/vaultwarden-implementation-handoff.md`。
- **8c064fc**：个人冲突比较/显式字段选择重新应用及原生入口、真实HTTP400旧版错误识别、协议/headless/隔离回环验证、覆盖矩阵与 `docs/cipher-conflicts.md`。
- **fe18500**：reprompt最新授权/旧grant拒绝/再次冲突、双改数组远端新增保留回归；迟到再次授权回调释放已脱离的私有草稿；README准确更新。
- 最后文档提交HEAD以 `git log -1` 为准。代码已分模块提交；最终退出前确认工作树及index干净。

## 本轮实际产品与协议行为

详见 [冲突处理](cipher-conflicts.md)、[覆盖矩阵](vaultwarden-api-coverage.md) 与 [敏感操作](sensitive-operations.md)。

| 能力 | 本轮结果 | 剩余边界 |
|---|---|---|
| 冲突与结果未知 | 编辑器保留旧原始密文/本地草稿；冲突阻断重复保存；未知结果原有禁重试继续保持；完成新sync后才能进入比较 | 未知结果的新建项目（尚无ID）仍需人工核实，不提供自动重建或重试 |
| 比较与选择 | 「同步最新版本」→「比较本地与远端改动」；固定中文字段名显示本地/远端是否改动、双方当前值是否相同；默认远端、逐字段勾选本地、采用远端或重新应用到草稿；另行明确保存 | 比较页不展示秘密值，也不提供敏感差异展开；没有声称视觉验证 |
| 最新文档为底 | `ComparePersonalCipher` / `ApplyPersonalCipherComparison`仅本地操作；保留远端unknown字段、权限、密钥、归档与最新server revision；比较对象session/revision/document hash绑定 | 服务端不是严格CAS；比较到保存仍有协议竞态 |
| 取消和授权 | 返回比较保留原稿；reprompt必须新文档新grant；旧grant不可重基；旧稿30秒期限仍有效；锁定/新同步/已删除/迁移组织/权限、key、type、reprompt变化阻断 | 组织reprompt流程未实现；旧稿过期按既有承诺清除，不能无限延长明文草稿 |
| 历史删除 | 只删除原先观察且本地删除的完整条目；最旧端匹配重复；远端新增/扩展改变条目保留；同时改密码仍记录当前远端密码 | UI目前仍为清除全部的确认，非逐条选择；历史明文显示统一短认证仍缺 |
| URI/custom双改 | 若远端未改可应用本地列表；双方同值可采用；双方都改且不同，阻断本地全数组应用，保留远端并提示在新表单编辑 | **逐行双版本对应尚缺**。不能按index盲配；列表无稳定ID，不得把本地旧数组覆盖远端新增/unknown；不是上游不支持 |

### 固定源码冲突纠正

Vaultwarden1.37.4缓存 `src/api/core/ciphers.rs:455–466`：`cipher.updated_at.signed_duration_since(dt).num_seconds() > 1`。差值截断为整数秒，**不足两秒可能接受旧稿**。原文档“约一秒容差”不够精确，已修正本轮覆盖矩阵/UI/专文。

服务端通过 `err!("The client copy of this cipher is out of date. Resync the client and try again.")`返回HTTP400；`src/error.rs:223–249`序列化顶层 `message` 和 `errorModel`。`cipherUpdateStatusError`只在单cipher更新HTTP400且顶层message**精确等于这条固定字符串**时返回脱敏 `ErrConflict`，其他400仍 `ErrValidation`，403仍权限错误。未知成功/5xx继续结果未知处理，不输出/记录原始错误体。单元明确测试普通400、含out of date但非固定消息、畸形JSON、403带同消息均不能误认冲突。

## 实际验证

Go统一由 `GO_BIN="$(bash scripts/resolve-go.sh)"` 解析。实际执行：

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race ./...
swift test --package-path macos
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
MYGO_VW_TEST_URL=http://127.0.0.1:32782 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
git diff --check
```

- 最后代码回归：root **0.985s**、协议 **0.845s**、dev-debug cached；race root **3.386s**、协议 **3.307s**、dev-debug cached。build/vet/diff check退出0。之后只有注释与文档改动，不重复无关验证。
- Swift实际 **50 XCTest、0 failures**，测试0.127s / wall0.131s；bridge typecheck退出0。本轮没有Swift源码变化，随后Go安全回归未重复Swift。
- 新单元：八类型无损重基/unknown保持，最新server revision、采用远端、历史新增及保存时当前远端密码加入历史、删除/组织迁移/edit/viewPassword/key变化/missing、revision/close/二次项目变化、旧grant/expiry、双改URI/custom远端新增/opaque保留、HTTP400精确识别。
- 新headless：原生比较入口/中文字段状态、敏感值不输出、显式本地/远端采用不发请求、结果未知须先新sync、返回/锁/新sync/删除/权限、reprompt最新文档重新授权、旧grant拒绝、新草稿后再ErrConflict仍保稿并禁重复保存。
- 最终真实回环：PBKDF2 **2.73s**、Argon2id **0.21s**、TOTP **0.55s**，总3.49s / package **3.603s**，全通过。新增实测创建个人Login→远端改备注→旧稿PUT拒绝→全sync→比较→采用本地标题→新PUT保持远端备注→删除自有项目。既有八类型、备份、folder/bulk、reprompt等回环继续通过。
- 真实回环失败记录：首次等待1.2秒旧稿仍被接受；按源码改2.2秒后得到普通validation分类，暴露旧分类遗漏，修正为上述精确固定message识别。该次TOTP也出现network错误，未从日志确证原因，不能断言限流。重启**自有**容器后Docker随机端口由32781变32782；一次测试误用旧32781导致注册network失败，inspect确认新映射后最终全通过。未将失败说成成功，也未访问任何外部vault。
- 未运行官方CLI，本轮输出明确 `official CLI interoperability not requested`。未做真实原生窗口/安装、通用剪贴板、Keychain/Touch ID/AutoFill平台交互、SMTP、SSO/WebAuthn验证；headless/命名pasteboard/协议回环不替代这些。

## 自有资源清理（已完成）

- 容器名 `mygo-card2-01a114f0-comparison`，完整ID **bbe608f1af355d8b356f941ba84b8727c1d95f7d2be17cfd16ade1f3506a8c10**，label `mygo-test-owner=01a114f0`。
- 镜像 **sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216**，inspect版本1.37.4/commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`。仅loopback自动空闲端口32781，重启后32782。
- bind数据目录 `/tmp/pi/01a114f0-5cec-73ad-b5be-81b16d193f1e/vw-comparison-data`→`/data`；账号均fixture随机example.invalid。清理前按ID inspect再次核对label/image/mount，随后 `docker rm -fv <完整ID>`成功，仅删除本轮scratch数据，`test ! -e`成功；精确名字过滤 `docker ps -a`无输出。未清理别人的容器、volume、镜像、应用或文件。

## 下一进程直接推进组织产品闭环

不再重做个人基线。此轮只做组织入口源码定位，**尚未新增RSA/组织代码**。准确适配点：

- `internal/vaultwarden/client.go:263` `Session`持有用户key，`Close`取消操作/clear key/撤销epoch；`SyncWithCheckpoint`做scope/profile/key校验后完整存原始sync。新增组织密钥不能持久化到未认证列表，生命周期须复用这里。
- `VaultData.Sync`已在Swift AES-GCM快照内原样保存全部profile/collections/policies等；`vault_data.go`个人列表显式跳过organizationId；`item_authorization.go:personalDocumentLocked`显式拒绝组织。不要直接取消拒绝而没有组织key/权限。
- `cipher_document.go` `cipherItemKey(document,ownerKey)`已经支持由owner key解包item key，`DecryptCipherDocument`/内部 `encryptCipherDocument`可复用字段无损转换，需以组织key为owner且独立组织授权。个人API `ciphers_api.go`显式拒绝组织；不要简单换organizationId当共享。
- 原生 `cipher_editor.go:adoptVault/openCipherEditorAuthorized/mutateCipher`目前仅个人；`network.go`全sync后的adopt/revision/checkpoint生命周期是组织UI接入点。需要连接组织/collections分类、列表/读取/编辑/共享，随后管理界面，不能只堆crypto helper当产品完成。

固定服务器源码根 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`，tag对象 `54a40806c990da2def7acd5a3152edc530c59b79`、commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`、归档SHA256 `d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7`。已读取的准确入口：

1. `src/db/models/user.rs:264–330`：`account_keys_json()`含 `accountKeys.publicKeyEncryptionKeyPair.{wrappedPrivateKey,publicKey}`；profile兼容 `privateKey`，`organizations`仅confirmed，`organizationsNew`包括accepted。不要给accepted组织解密权限。
2. `src/api/core/ciphers.rs:198–219` sync输出 `profile,folders,collections,policies,policiesNew,ciphers,domains,sends,userDecryption.userKeyId`。两套新旧字段同时存在需一致性/版本校验，不能把profile原始对象丢掉。
3. `src/db/models/organization.rs:438–534` `Membership::to_json`：`id`是组织ID；`organizationUserId`是membership ID，`userId`是全局用户ID，`key/status/type/enabled`按成员。Manager转换为custom type4；profile `permissions`的createNewCollections/editAnyCollection/deleteAnyCollection三项模拟accessAll。不要假设profile直接有accessAll或把membership ID当用户ID。`has_full_access`在784附近，管理DTO在536起。
4. `src/db/models/cipher.rs:587–656` `get_access_restrictions`：本人/组织full access/群组full access优先，否则多collection权限readOnly/hidePasswords分别AND、manage OR；sync逐collection直接用户权限优先于群组，不可简单把任意群组许可OR进来。返回cipher的edit/viewPassword在385附近；组织成员confirmed才能有效。
5. `src/db/models/collection.rs:69–152`：集合名是组织key加密；`to_json_details`提供readOnly/hidePasswords/manage，full access、manager角色及直接/群组权限影响结果。后续需同时尊重server cipher有效权限和collection/role/policy，不能从角色号大小推断所有操作。
6. 用户RSA公钥Base64 DER/SPKI；私钥PKCS8以user key包装；组织key用RSA-OAEP type3 SHA256/type4 SHA1。固定参考Bitwarden clients `web-v2026.5.0` commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce`与SDK RSA `39dbb510f5eae82f5cbfd527b0f70a01d5626ec1`（前轮审计提供，当前轮未重读RSA源码）。需固定向量/畸形key/权限/revoke/account-member混淆/真实隔离组织互操作。

后续仍完整保留：组织创建/编辑/退出/删除、成员invite/accept/confirm/revoke/restore、collections/groups/policies/events/目录Public API/recovery/API keys；附件二阶段加密binary/multipart/外部URL禁Bearer/补偿；文本文件Send seed/HKDF/fragment/send_access接收；注册/profile/keys/邮箱/主密码/KDF/全user key轮换非事务恢复/删除清库/security stamp/MFA各provider/SSO/WebAuthn/devices/auth requests/domains/emergency；SignalR MessagePack通知/断线sync；大库桥；query/binary/Retry-After；完整逐注册路由矩阵、组织及完整import/export。reprompt批量/导出逐项授权、历史显示统一授权、个人双改数组逐行UI仍缺。所有这些是未实现客户端范围，不可伪装上游限制。

继续同一卡，不自审、不完成、不合并。
