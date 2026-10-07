# 完整 Vaultwarden 实现：第二轮阶段交接

**INCOMPLETE — 整卡未完成，未达到验收。** 协调者经 `contact_supervisor(need_decision)` 明确同意本轮完成必要安全回归、提交精确交接后退出，再续启同一卡。**不得启动 Review，不合并，不缩减完整原始需求。** 本轮不是把正常模块完成宣称整卡完成；还有 folders/bulk/copy/import-export/组织/附件/Send/账号等大量明确缺项。

## 工作树和提交

- 唯一写入目录：`/Users/vfasky/Library/Application Support/Waku/worktrees/board/56a21c6a-f119-465b-ae4e-7e77f68151bd/board-2-vaultwarden-api`。
- 分支：`waku/board-2-vaultwarden-api`。
- 保留原提交：`4b0a910` 用户前序成果基线、`331b1c4` 首轮协议基础、`362ad24` 首轮交接。本轮没有重新导入基线。
- 本轮代码提交：**`7ae7560` — 接入八类型个人密码库编辑与完整加密离线文档**（24个文件，1402行新增/62行删除）。本交接/覆盖矩阵/README随后独立提交；最终HEAD以 `git log -1` 和进程最终报告为准。
- 主目录 `/Users/vfasky/code/mygo-vaultwarden` 未读取凭据、未写入、未暂存/提交/清理/重置。其dirty合并阻塞仍交协调者处理；不可自行更改用户主目录。未操作用户app/watch，未启动子代理。

## 本轮完成的产品与接口

1. `cipher_document.go` 支持全部8类型已知字符串加解密：Login、SecureNote、Card、Identity、SSHKey、BankAccount、DriversLicense、Passport。后3类字段来自固定客户端源码逐项名单。`NewPersonalCipher` 使用新随机64-byte item key，用用户key包装；`CreatePersonalCipher` POST `/api/ciphers`。SSH必须包含privateKey/publicKey/keyFingerprint，否则明确验证失败。
2. 原有同key无损编辑扩展到密码/多个URI/自定义字段。改密码自动加入旧密码history并更新passwordRevisionDate；改URI生成SHA256/Base64的uriChecksum后加密；notes/名称/收藏/标准类型字段可修改。未知opaque/FIDO2、原revisionDate/archivedDate及大整数保留。解码editable map使用json.Number，生成密文不修改表单对象。创建拒绝未知section/custom/URI扩展及历史输入，不允许把复制/跨key重加密伪装成新增。
3. 新 `vault_data.go`：`VaultData{version:1,scope,sync:[]byte}` 保留完整server-encrypted sync原始JSON（Go JSON传输时base64）；验证profile账号、ciphers数组、唯一安全ID和大小。`Documents`、`ReadPersonalCipher`、`PersonalEntries`提供当前认证session下的文档/显示投影，组织暂不解密，reprompt/不可viewPassword拒绝解密。
4. Go `SyncResult.Vault` → `storageRequest.Vault` → Swift `SnapshotPayload.vault` → AES-GCM；`saveSession`保留完整vault，旧payload无vault时兼容解锁，下次成功同步迁移。只有主应用认证`list/listPassword`返回vault；status/index/AutoFill默认lease不返回。完整vault与64KiB session分开。**C ABI仍为4MiB总上限，超限保旧并报错；大库传输尚未完成。**
5. AutoFill独立Login投影增加`archivedDate`、`viewPassword=false`排除，原deleted/reprompt/组织排除保持；零条仍明确替换。完整文档不因投影排除而丢弃。Swift迁移、checkpoint保存完整库、跨scope、锁定撤销等新增测试。
6. `cipher_editor.go`及UI：八分类/收藏/归档/回收站；选择分类→顶栏新增（所有项目默认Login）；详情「查看与编辑」。标准字段表单、密码/TOTP秘密遮掩、SSH多行、notes多行、多网址、文本/隐藏自定义字段、收藏。已有布尔/关联自定义字段保留或显式删除，不能编辑其类型/关联。编辑页归档/取消归档、软删除确认、回收站恢复/永久删除确认。写成功后同步并按会话CAS发布，不乐观拼接快照。
7. `cipherEditor.revision`绑定本地快照revision；只换token的同snapshot checkpoint可以推进草稿revision，完整同步替换不能。旧草稿保存被阻断且内容保留；**没有自动合并/重基UI**。未知写结果保留草稿并禁再次保存，允许同步核对；已确认保存后同步成功才关闭草稿。
8. `stopNetwork`推进epoch并取消/关闭session，清除内存vault/editor/list。撤销后迟到写回调不采纳checkpoint、不重启同步，并释放其私有草稿。写后取消、意外2xx、5xx、成功响应损坏/身份不符统一MutationUncertainError。所有非GET写请求无自动重试，刷新checkpoint失败阻断后续请求。

## 文件地图

代码提交新增：`cipher_editor.go`、`cipher_editor_test.go`、`internal/vaultwarden/cipher_create.go`、`vault_data.go`、`personal_vault_test.go`。

主要修改：`cipher_document.go` / `ciphers_api.go` / `authenticated.go`、`client.go` / `sync.go` / `types.go`及对应测试；`main.go` / `network.go` / `session_storage.go` / `storage.go` / `ui.go`；Swift `SnapshotTypes.swift` / `SnapshotStore.swift` / `SnapshotBridge.swift` / `SnapshotStoreTests.swift`。完整24文件列表可用 `git show --stat 7ae7560`。README、旧只读说明、安全快照说明和覆盖矩阵同步更新，不能再说产品完全只读，也不能说完整API完成。

## 协议依据

- Vaultwarden1.37.4固定源码缓存：`/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`。
- tag对象 `54a40806c990da2def7acd5a3152edc530c59b79`；commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`；归档SHA256 `d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7`。
- 完整审计由上一协调进程提供，不能再写“审计尚未完成”；但**本仓库逐注册method/path/别名矩阵仍未全部落地**。原始`routes.txt`在缓存父目录；含未注册声明，需要核对routes!及main挂载，不可机械当成全部启用API。
- 本轮额外读取 clients commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 下 `libs/common/src/vault/models/domain/{bank-account,drivers-license,passport,login-uri,login}.ts`，原始GitHub固定URL成功，无镜像回退。副本在本进程scratch，生命周期结束可能消失；重新读取固定commit即可。
- 真实服务发现 db/models/cipher.rs:298附近把缺少三项SSH字段的type5响应置为null，因此新增前加了校验。服务器revision旧版本检查不是严格CAS、可能400；原值携带，不用本地snapshot revision代替。
- DELETE单条永久删除、PUT `/delete`软删、POST同路径为永久删除别名仍严格区分。完整PUT保留archivedDate。encryptedFor当前用户；尚无完整encryptedByKeyId/用户key轮换生命周期。

## 已执行验证和真实结果

所有Go命令使用 `GO_BIN="$(bash scripts/resolve-go.sh)"`，未安装/运行app。

最终本地回归：

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" vet ./...
"$GO_BIN" build ./...
"$GO_BIN" test -race ./...
git diff --check
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
swift test --package-path macos
```

- Go test最终：root **0.647s**、internal/vaultwarden **0.562s**、scripts/dev-debug cached；build/vet退出0。
- 最终全仓race：root **3.080s**、协议 **2.794s**、dev-debug **7.318s**，全部通过。
- Swift **44 XCTest / 0 failures**（SnapshotStore36、VaultCredential2、VaultURI6）；bridge额外typecheck通过。Swift测试用MemoryKeys，不是真实Keychain/Touch ID证据。
- Headless新增覆盖八类型新增入口、认证文档打开、真实表单生成、删除确认取消、锁定清除、外部revision阻断、checkpoint草稿授权、迟到回调、冲突/未知结果保留。**没有运行真实窗口或视觉验收**；没有签名安装或真实AutoFill交互。
- Go新增覆盖八类独立key/字段加密、passwordHistory+URI checksum和不修改草稿、opaque扩展/大整数、自定义字段无损编辑、新key拒绝unknown扩展、成功响应损坏/意外2xx/5xx未知结果、完整文档scope/reprompt/closed session、归档/权限排除。既有HTTP/checkpoint/锁定测试继续通过。
- 开发过程中headless发现TextInput不能直接Key（已改外层容器Key）、表单滚动测试需要滚动到确认控件；全部修复后最终通过。不要把先前失败当最终结果，也不要隐去真实发现。

### 隔离真实Vaultwarden回环

镜像ID：`vaultwarden/server:1.37.4` = `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`。

唯一容器名 `mygo-card2-01a11468-vw`，label `mygo-test-owner=01a11468`，`-p 127.0.0.1::80`。数据目录 `/tmp/pi/01a11468-5213-72e9-8b73-e4a546b4b11e/vw-data`。设置 `SIGNUPS_ALLOWED=true`、`SIGNUPS_VERIFY=false`、`DOMAIN=http://localhost`；为重复隔离用例设置 `LOGIN_RATELIMIT_MAX_BURST=100`。没有测试SMTP，也没有发送邮件；注册为无SMTP测试token流程。

本进程依次创建并准确移除：

| 容器ID | 端口 / 用途 | 最终状态 |
|---|---|---|
| `9b6a154c7851fb1803576675e3b29e989be50872942148c0626505e2cf93d6f9` | 初次未挂scratch，未跑测试即移除并重建 | `docker rm -fv`已移除（含其匿名volume） |
| `22095d7cf872a9d938a3ecd9f358d8ec811ae64e1e78f99b67902e3bf7f16863` | 32770；发现SSH必填约束，重复登录达到默认限流 | 已移除 |
| `cca7c1b32713a9f7315a49074900bd8c15f370f4a1f9d2db1c9066d07e933888` | 32771；提高测试burst后完整首轮通过 | 已移除 |
| `06a81434e715f4ac7d32688f78b22eeee69b85335254f85dbbc597a0d5f1eec3` | 32772；加入真实自定义字段、旧密码history/URI checksum断言后重跑 | 已移除 |

最后一轮命令：

```sh
MYGO_VW_TEST_URL=http://127.0.0.1:32772 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
```

**PASS**：PBKDF2 **0.37s**、Argon2id **0.23s**、TOTP **0.57s**；总test **1.17s**，包 **1.597s**。PBKDF2账号额外逐一执行8类型create/update/archive/unarchive/trash/restore/permanent delete；验证custom字段、history、checksum保留，以及归档Login不进入AutoFill。所有账号随机`example.invalid`。每次最终清理前核对容器label和ID；`docker ps -a --filter name=mygo-card2-01a11468-vw`最终无输出；自身scratch数据目录已删除并`test ! -e`确认。没有操作其他容器或用户app/watch。

这证明Go类型化协议与该服务端回环，不证明真实原生保存按钮→签名bridge→Keychain的完整安装链路。未用官方客户端解密此轮写入、未做官方导入导出互操作；测试也不覆盖SMTP/WebAuthn/SSO/组织等未实现能力。

## 剩余缺项与下一进程具体入口

1. 优先补全个人闭环：`src/api/core/folders.rs`的folders CRUD、UI文件夹选择/过滤；ciphers bulk move/delete/restore/archive、逐项结果；清回收站只删除deleted项目，不能调用purge；copy需新key且对unknown/附件/FIDO2有明确完整重加密或拒绝。个人import/export做本地格式转换与敏感导出确认。不能只新增脱离UI的协议接口。
2. 补齐个人编辑细节：布尔/linked custom fields完整编辑器、reprompt再次验证/设置、密码history展示、密码与TOTP安全展示复制、URI match策略、冲突比较/显式重基。现有冲突草稿保留且旧revision拒绝写入，但用户需核对后重新打开编辑。当前表单非完整编辑器，不能宣称满足所有个人CRUD验收。
3. 组织RSA链和权限模型：解包PKCS8用户私钥与RSA-OAEP3/4组织key；读取已保存完整sync中的组织/collections/policies；按role/group/manage/readOnly/hidePasswords/accessAll执行授权；memberId与userId分开。再接组织、成员、群组、策略、共享、events/目录Public API/恢复等真实产品入口。
4. 附件与Send：独立有界二进制/外部预签名传输，严禁Bearer外泄；加密文件格式、MAC/大小、两阶段失败补偿、安全临时文件及锁定取消；Send seed/HKDF/link fragment/send_access接收流程。当前没有实现这些模块，不是上游不支持。
5. 账号注册/验证/profile/keys/主密码邮箱KDF/轮换删除/清库/security stamp、设备/auth requests/domains/emergency、MFA所有provider与管理、SSO/WebAuthn真实平台交互。用户key轮换非整体事务，必须恢复计划和故障注入。
6. 通知SignalR MessagePack与断线同步；全面逐注册路由矩阵（含main挂载、identity、admin、占位/部署资源边界）。上游审计结论见卡片要求，不再猜测/export/trash/Send旧access等端点。
7. 大库传输仍受4MiB桥限制；应实现有界安全传输，不混入session，更不能把附件塞JSON。完整sync当前作为opaque server-encrypted数据存储，组织等新模块需建立正式typed视图但保持未知字段原始字节。
8. 后续新增每个模块继续httptest/故障/crypto/真实隔离回环、Go build/test/vet/race和Swift回归；真实视觉/签名安装/Keychain/AutoFill/MFA平台交互需要独立验证，不能由单元通过代替。

继续同一工作树。已有baseline和全部阶段提交无需重导入。真正完成整卡后再由协调者启动独立Review；本轮只允许INCOMPLETE交接。
