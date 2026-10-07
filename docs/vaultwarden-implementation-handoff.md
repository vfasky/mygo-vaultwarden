# 完整 Vaultwarden 实现：第三轮阶段交接

**INCOMPLETE — 整卡未完成，未达到最终验收。** 协调者通过 `contact_supervisor(need_decision)` 明确批准：本轮完成最终验证、清理自有资源、提交精确交接后退出，再续启同一卡；**不启动 Review、不合并、不缩减完整原始需求**。下一轮继续本工作树，不重导入基线。

## 当前工作树与提交

- 唯一写入目录：`/Users/vfasky/Library/Application Support/Waku/worktrees/board/56a21c6a-f119-465b-ae4e-7e77f68151bd/board-2-vaultwarden-api`。
- 分支 `waku/board-2-vaultwarden-api`。
- 本轮起点 **697b99b**，保留 `4b0a910` 用户成果基线、`331b1c4` 首轮协议基础、`362ad24` 首轮交接、`7ae7560` 八类型/完整离线库及 `697b99b` 第二轮交接。
- 本轮模块提交 **15a0567**：加密文件夹管理及可核对部分结果的个人批量操作（18文件）。
- 本轮模块提交 **7f0a408**：布尔/关联字段、URI匹配、密码历史、无损表单及安全回归（10文件）。
- 本文在以上两提交后单独提交，最终HEAD以 `git log -1` 为准。最终报告给出该HEAD及干净状态。
- 没有写入、提交、暂存、stash/reset/clean主目录 `/Users/vfasky/code/mygo-vaultwarden`，没有读凭据或访问生产vault，没有操作用户app/watch或其他容器，没有启动子代理。主目录dirty合并问题仍由协调者处理。

## 本轮新增产品能力

### 加密文件夹闭环

- `internal/vaultwarden/folders.go`：`SaveFolder` POST `/api/folders` 或 PUT `/api/folders/{id}`；`DeleteFolder` DELETE同路径。名称以user key做type-2随机IV加密。校验ID/名称长度/UTF-8、scope、closed session；保存成功响应校验ID和解密名称，不可信成功响应标为结果未知。复用checkpoint先落盘与禁写重试。
- `PersonalFolders`从认证完整sync读取并解密folders，校验账号和重复ID；文件夹名不放认证前status或AutoFill列表。
- 原生侧栏：文件夹列表、无文件夹、新建、管理；管理页更名/删除，删除确认说明只解除归属、项目不删除。项目编辑器选择文件夹，在当前文件夹新增默认选中。
- `VaultEntry/ displayCredential`增加folderID供认证后本地筛选。文件夹删除后成功同步导航至「无文件夹」；更名后的导航标题/移动后的列表来自新快照。旧项目草稿保持原snapshot revision，不能因文件夹更新获得新写权限。
- Folder draft绑定本地session revision；仅令牌checkpoint可推进，完整同步后旧草稿阻断；结果未知保留表单禁重试；锁定/登出清除文件夹/表单，迟到回调清理私有草稿。
- 上游没有folder revision CAS；本地revision门控不能防止别的设备同时更名，矩阵已明确。

### 个人批量与清回收站

- `internal/vaultwarden/cipher_bulk.go`：`ChangePersonalCiphers`支持PUT `/api/ciphers/move`、`/delete`（软删）、`/restore`、`/archive`、`/unarchive`及DELETE `/api/ciphers`（永久删除）。选中ID必须在当前个人快照、可编辑，拒绝组织ID、重复/非法ID；永久删除只允许deleted。
- 原生顶栏「批量管理」打开独立选择/操作/确认页，支持移动目标文件夹。回收站「清空回收站」只选当前完整个人快照中deleted条目，再明确确认永久删除；**不调用purge**。
- 上游批量并非事务，delete/restore/archive可能改部分后返回错误；move会移动可访问项后因missing ID返回400。本实现所有批量非200/204响应都视为可能部分执行，绝不重复请求。
- 操作结束后全量同步，沿用scope/revision CAS发布。逐项显示「当前状态已符合目标」或「当前状态未符合目标」，同步失败保留「尚未核对」。这是观察状态，不声称HTTP失败代表全部失败或整个批次原子成功。已提交批次永久禁再提交；若要处理未符合项需关闭后重新选择。
- 清回收站与批量选择绑定确认时的snapshot revision，未来同步中新进入回收站的项目不会自动加入旧批次。
- 批量页只处理当前筛选列表；清空回收站遍历全部个人deleted元数据。成员/组织批量尚未实现，不能把本能力算作组织管理。

### 编辑细节

- 文本/隐藏/布尔/关联四类自定义字段可新增和编辑。布尔以加密字符串`true/false`保存；关联目标使用固定客户端枚举，仅Login/Card/Identity有可选关联。未知关联ID原样保留，可显式改为已知关联；未变更字段保留null与未知扩展。未知字段类型继续保留/可显式删除，不映射成文本。
- URI可选择默认、基本域名(0)、主机(1)、起始部分(2)、完全匹配(3)、正则表达式(4)、从不填充(5)。保持未知策略及扩展，修改URI继续维护加密checksum。**AutoFill仅既有0/1/3实现，2/4不支持，UI明确提示；5不进入填充。** 没有把策略保存等同于全平台填充匹配已实现。
- 「显示密码历史明文」明确点击后显示历史密码/日期，可隐藏；默认不显示。仍缺历史删除、当前秘密安全复制和TOTP码生成。
- `cipherEditor.applyInputs()`从UI独立提取无损合并；不修改原source map；不把未编辑的custom null变成空字符串。完整PUT仍同item key保留未知/FIDO2；仍不支持copy/share/轮换跨key重加密。
- 所有这些编辑入口沿用`ReadPersonalCipher`个人/edit/viewPassword/reprompt门控；组织、viewPassword=false和reprompt项目无法打开新控件，新增测试覆盖。尚未实现reprompt再次验证，不通过显示历史绕过。

## 文件地图与继续入口

- 文件夹：`internal/vaultwarden/folders.go`、`folder_editor.go`，测试`folders_test.go`、`folder_editor_test.go`。
- 批量：`internal/vaultwarden/cipher_bulk.go`、`bulk_editor.go`，测试`cipher_bulk_test.go`、`bulk_editor_test.go`。
- 安全与真实回环：`internal/vaultwarden/folders_bulk_safety_test.go`、`folders_bulk_integration_test.go`、`integration_test.go`、`personal_editor_safety_test.go`。
- 编辑细节：`cipher_editor_fields.go`（固定枚举及控件）、`cipher_editor_inputs.go`（合并）、`cipher_editor_fields_test.go`；原有`cipher_editor.go`接入。
- 共同生命周期：`main.go` app持有folder/bulk state；`network.go`锁定清除、同步发布后`reconcileBulk`；`session_storage.go`checkpoint可推进同快照草稿；`ui.go`入口；`vault_data.go`/`storage.go`认证元数据folderID。
- 本轮无需Swift格式迁移：完整sync已有folders，仍保存在原AES-GCM payload；只改Go认证显示投影。Swift44测试和bridge typecheck通过，不是新增Swift功能。
- 当前覆盖矩阵 `docs/vaultwarden-api-coverage.md`、README和旧只读文档已更新。第二轮详细历史可通过 `git show 697b99b:docs/vaultwarden-implementation-handoff.md`读取，无需重新做已完成工作。

## 协议依据与源码获取

- Vaultwarden1.37.4缓存 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`，本轮直接读 `src/api/core/folders.rs`、`ciphers.rs`。
- tag对象`54a40806c990da2def7acd5a3152edc530c59b79`，commit`7c188967e7a467b19b2757bc3326f9cf3ccae327`，归档SHA256`d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7`。
- Bitwarden clients固定commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce`：`libs/common/src/vault/enums/{linked-id-type.enum,field-type.enum}.ts`、`libs/common/src/models/domain/domain-service.ts`、`libs/common/src/vault/models/domain/login-uri.ts`。
- 首次raw路径`linked-id-type.ts`连接失败；按内置`github-mirror-fallback/SKILL.md`尝试gh-proxy.org返回404，停止该无效路径。GitHub目录API确定实际`.enum.ts`路径后raw超时，最终通过**原站公开GitHub contents API、固定ref、Base64解码**读取准确内容，未用镜像作为源码成功依据、未读取认证配置。scratch保存这些源码和tree供临时参考，生命周期结束可能消失。

## 本轮验证：实际命令和结果

Go统一 `GO_BIN="$(bash scripts/resolve-go.sh)"`；未安装或运行应用。

最终代码回归：

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race ./...
git diff --check
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
swift test --package-path macos
```

- 最终Go test root **0.998s**、协议与dev-debug cached；build/vet退出0。
- 最终全仓race root **4.592s**、协议 **4.019s**、dev-debug cached；全部通过。
- Swift **44 XCTest/0 failures**：SnapshotStore36、VaultCredential2、VaultURI6；0.138s。bridge typecheck退出0。Swift没有本轮更改，测试在本轮文件夹/批量完成后执行；后续只改Go编辑器及文档，未无意义重复Swift。
- 新增httptest：文件夹路径/加密/响应身份/错误未知状态、bulk所有真实路由、400部分状态语义、永久删除active拒绝、组织/权限/重复ID拒绝、checkpoint阻断folder/bulk、Close取消bulk不重试。
- Headless：文件夹管理确认/取消、过滤、默认选择、空回收站只选deleted、批量逐项部分状态且不重试、草稿checkpoint/过期revision、迟到响应/锁定清理、文件夹更名/移动/删除后分类与旧草稿权限；布尔/关联控件与unknown/null无损、URI match保源、历史显式显示/隐藏、组织/reprompt/viewPassword门控。
- 开发中新增publication测试第一次失败，因为测试只改变snapshot/session revision但未模拟成功publication更新itemsRevision；按真实发布路径修正fixture后三次状态一致，最终通过。没有借此放宽产品revision门控。
- 以上是单元/headless证据，**没有真实窗口视觉、签名安装、Keychain/Touch ID、AutoFill交互、官方客户端解密/导入导出互操作验证**。

### 隔离真实1.37.4服务

镜像`vaultwarden/server:1.37.4` ID `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`。

唯一名称`mygo-card2-01a11486-vw`、label`mygo-test-owner=01a11486`、loopback随机端口，scratch目录`/tmp/pi/01a11486-9d2c-728e-9c6d-2eb6f46a0876/vw-data`挂`/data`。`SIGNUPS_ALLOWED=true`、`SIGNUPS_VERIFY=false`、`DOMAIN=http://localhost`、`LOGIN_RATELIMIT_MAX_BURST=100`。账号随机`example.invalid`；没有生产请求，未测试SMTP。

| 容器ID | 用途 | 清理 |
|---|---|---|
| `955930282c71a00fcdddfc6b27022f4b7fc636744ddc0c90f329a99ecf5b2d7a` | 初次把scratch挂`/scratch`，未设置数据位置；没有跑测试，立即重建 | 核对label后`docker rm -fv`，含匿名volume已移除 |
| `72b52647b9f56e7bf301042be8067ddeb661872ce1654c3c5411f748d19c6913` | 正确scratch `/data`，`127.0.0.1:32774`，完成两轮真实回环 | 最后核对ID/label/mount后按完整ID `docker rm -fv`；自己的vw-data已删除并`test ! -e`确认 |

最终真实命令：

```sh
MYGO_VW_TEST_URL=http://127.0.0.1:32774 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
```

最终 **PASS**：PBKDF2 **0.36s**、Argon2id **0.24s**、TOTP **0.57s**，总 **1.17s** / 包 **1.286s**。PBKDF2账号执行所有八类既有写回环；本轮新增文件夹新增/更名/离线读取/删除后项目仍存在且无文件夹、全部六种批量动作、实际400部分移动核对；八类布尔字段往返、Login关联字段和值为null往返，原custom/passwordHistory/URI checksum断言保留。

清理后 `docker ps -a --filter name=mygo-card2-01a11486-vw --format '{{.ID}} {{.Names}}'`无输出。没有清理其他容器/进程。这证明Go协议对固定服务器可用，不证明真实原生保存按钮到签名Swift bridge/Keychain/AutoFill链路已验证。

## 仍未完成：下一轮按此继续

1. **个人复制**：必须新item key、完整已知字段/历史/URI/custom保持；不能把`NewPersonalCipher`当前的创建约束误用为无损copy。对无法完整重加密的附件/FIDO2/未知数据明确拒绝，后续补完整能力；不悄悄删字段。当前尚无copy API/UI。
2. **个人import/export**：真实原生文件选择/保存、本地Bitwarden格式转换、明确敏感导出确认和完整字段保留、官方互操作；当前均未实现，不能使用raw JSON页面或伪造/export端点。组织导入导出后续保留。
3. **reprompt与秘密**：主密码再次验证/短时scope+revision授权、当前密码安全显示/复制与剪贴板过期/锁定清除、TOTP生成/复制；历史删除、冲突比较/显式重基仍缺。现有历史明文查看只针对已有允许打开的个人项目，不能算这些需求完成。
4. **组织RSA/权限/collections/共享与管理**：解包PKCS8私钥和RSA-OAEP3/4组织key；完整role/group/manage/readOnly/hidePasswords/accessAll授权，userId与memberId区分；再组织CRUD、邀请接受确认撤销/恢复、成员/群组/策略/events/Public API目录导入/API keys/恢复。当前完整sync保留这些密文，但未解密或操作。
5. **附件/Send**：独立有界binary/multipart/query传输，外部URL无Bearer、MAC/大小/URL验证、失败补偿、安全临时文件和取消；Send seed16/HKDF/link fragment/password/send_access流程及产品入口均未实现。
6. **账号全流程/通知**：注册/验证/profile/keys/主密码/邮箱/KDF/用户key轮换故障恢复/删除/清库/security stamp、MFA全部provider管理、SSO/WebAuthn平台交互、设备/auth requests/domains/emergency/恢复、SignalR MessagePack及断线同步仍缺。
7. **桥大库**仍4MiB C ABI限制，超限报错保旧；不能作为永久范围排除。query/multipart/binary、Retry-After、逐注册method/path/别名矩阵尚未补完；上游审计已完成，不能重新声称没审计或将客户端缺失标为上游限制。
8. **验证**：真实视觉/安装/Keychain/AutoFill/官方解密及导入导出、SMTP/WebAuthn/SSO和新增全部模块的故障/权限/crypto测试仍需完成。继续Go build/test/vet/race与Swift回归，每模块接原生入口和离线状态。任何新容器只建自己唯一实例、准确清理。

继续同一卡，不自审，不完成，不合并；上述完整原任务全部保留。
