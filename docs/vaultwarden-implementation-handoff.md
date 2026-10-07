# 完整 Vaultwarden 实现：第四轮阶段交接

**INCOMPLETE — 整卡未完成，未达到最终验收。** 协调者已通过 `contact_supervisor(need_decision)` 明确批准本轮完成复制故障回归、验证、自有资源清理和精确交接后退出，继续同一卡；**不启动 Review、不合并、不缩减完整原需求**。正常后续模块可持续推进，不应把单个模块结束自动视为阶段结束。

## 工作树与提交

- 唯一写入目录：`/Users/vfasky/Library/Application Support/Waku/worktrees/board/56a21c6a-f119-465b-ae4e-7e77f68151bd/board-2-vaultwarden-api`；分支 `waku/board-2-vaultwarden-api`。
- 本轮起点 **dfe42c7**；全部保留前序 `4b0a910` baseline、`331b1c4`、`7ae7560` 八类型/完整离线库、`15a0567` 文件夹/批量、`7f0a408` 编辑细节及各轮交接。**不要回退或重导入基线。**
- 本轮模块提交 **0dab306**：八类型标准个人项目安全复制与原生确认/取消边界（9文件）。本文随后单独提交，最终HEAD见 `git log -1` 与最终报告。
- 没有改动、提交、暂存、stash/reset/clean主目录 `/Users/vfasky/code/mygo-vaultwarden`，没有读取凭据、访问生产vault、操作用户app/watch/其他容器或启动子代理。主目录dirty合并问题仍交协调者处理。

## 本轮功能与边界

- `internal/vaultwarden/cipher_copy.go`：`Session.CopyPersonalCipher(ctx, scope, source, fields, persist)`。先审查原始文档完整schema，防止通过从草稿删除未知字段绕过检查；再利用既有编辑转换生成包含当前表单修改、URI checksum和自动旧密码历史的密文；最后完整解密已知字段、生成独立随机64字节item key、以user key包装该key并重新加密所有已知秘密，再POST `/api/ciphers`。
- 八类型标准字符串、name/notes、四类custom、passwordHistory、URI和checksum均重加密。保留folder/favorite与历史；新建时去掉源ID/creation/revision/lastKnownRevisionDate、归档/回收日期及服务器权限metadata。副本是活动项目，原项目及原始JSON不变。
- 源个人/edit/viewPassword/无reprompt权限门控，scope校验；UI绑定打开源时的本地revision，storage status检查后才写。刷新checkpoint先持久化；Close取消；任何未知结果沿用既有不重试路径。返回源ID的伪成功响应判为结果未知。
- 含附件、非空FIDO2、未知顶层/section/URI/custom/history扩展、非空encryptedByKeyId、非当前type的非空section、组织项目等无法完整转换的源，**在请求前拒绝**。这些是客户端仍缺能力，不能算上游不支持。完整copy含附件/FIDO2/未来扩展仍保留为整卡未完成项。
- 原生编辑页「复制为新项目」→明确说明复制当前表单、原项目不变、副本恢复活动状态及未支持数据拒绝→确认。取消保留草稿；未知结果保留草稿并禁再次创建；成功全量同步发布，锁定/迟到回调沿用清理。
- 没有新增Swift格式或桥接口；新副本通过既有全量sync→加密vault payload→最小AutoFill投影链路。没有直接乐观插入本地凭据。

### 真实服务器发现的协议细节

首次真实回环复制Login被严格allowlist拒绝。固定版源码 `src/db/models/cipher.rs:263` 后的兼容逻辑会返回 **`login.uri` = 第一个`login.uris[].uri`的加密别名**，为空则null。它不是未知明文metadata。

- `cipher_document.go` 的字段转换现在同时处理legacy `login.uri`。编辑canonical uris时同步更新已有alias，避免旧地址滞留；copy将alias与列表分别以新key重加密。
- 新增wrapped item key夹具，修改当前网址/密码后复制，断言alias和canonical地址一致、旧密码进入历史、源JSON未改、新key不等于源key或user key、旧key不能解密新alias。
- 修复后真实1.37.4八类复制全部通过；没有放宽未知字段检查绕开错误。

## 本轮变更与测试文件

- 新增 `internal/vaultwarden/cipher_copy.go`、`internal/vaultwarden/cipher_copy_test.go`、`cipher_copy_test.go`。
- 修改 `internal/vaultwarden/cipher_create.go` 抽取内部已加锁的create提交/响应验证，创建与复制共用既有请求安全路径。
- 修改 `internal/vaultwarden/cipher_document.go` legacy URI加密与alias同步。
- 修改 `cipher_editor.go` 复制确认及mutation dispatch。
- 修改 `internal/vaultwarden/integration_test.go` 八类真实复制、解密/历史/checksum断言与副本清理。
- README与 `docs/vaultwarden-api-coverage.md` 准确声明已完成的标准复制与未完成边界。
- 前三轮详情不重复：`git show dfe42c7:docs/vaultwarden-implementation-handoff.md`，第二轮 `git show 697b99b:docs/vaultwarden-implementation-handoff.md`。

## 验证证据

Go统一 `GO_BIN="$(bash scripts/resolve-go.sh)"`。最终实际执行：

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
"$GO_BIN" test -race ./...
MYGO_VW_TEST_URL=http://127.0.0.1:32775 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
git diff --check
```

- 全部通过。最终Go test协议 **0.535s**，root/dev-debug cached（本轮此前root **0.648s** 已通过）；build/vet退出0。
- 最终race协议 **2.589s**，root/dev-debug cached（本轮此前root **3.022s**、dev-debug **7.356s**）；全部通过。
- 新增八类完整字段复制/独立key/原JSON不变/历史与checksum、wrapped source key/legacy alias、未知扩展/FIDO2/附件/权限/reprompt拒绝、原源unknown即使草稿删除仍不发请求、scope混淆、checkpoint失败零请求、HTTP500未知结果单次请求、Close取消不重复创建、响应返回源ID拒绝。
- 新增headless复制确认/取消/草稿保存、陈旧revision阻断、未知结果禁再次提交、锁定迟到回调清秘密。
- 首次真实回环 **失败**（pbkdf2下Login复制拒绝），依据固定源码修复legacy URI后重跑通过；最终PBKDF2 **0.38s**、Argon2id **0.27s**、TOTP **0.57s**，总 **1.22s** / 包 **1.340s**。PBKDF2执行全部八类型复制，并保留原CRUD/文件夹/批量等回归。
- Swift本轮没有改动，依赖/go.mod也未改。按协调者允许未无理由重复Swift；继承第三轮同Swift代码的 **44 XCTest/0 failures** 与 `swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift` 退出0证据。**不声称本轮重新执行Swift。**
- 未进行真实原生窗口视觉、安装、Keychain/Touch ID、AutoFill交互、官方客户端解密/import/export互操作或SMTP/WebAuthn/SSO验证。

### 本轮隔离真实1.37.4资源与清理

- 镜像 `vaultwarden/server:1.37.4` ID `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`。
- 唯一容器 `mygo-card2-01a1149e-vw`，ID `5ffe520b6800786b8be4b36eb3c6f32e969533b1c3936ee8c658c734d717f99a`，label `mygo-test-owner=01a1149e`，loopback `127.0.0.1:32775`。
- scratch `/tmp/pi/01a1149e-0acf-7269-84df-5e032315920c/vw-copy-data`挂载`/data`，SIGNUPS_ALLOWED=true、SIGNUPS_VERIFY=false、DOMAIN=http://localhost、LOGIN_RATELIMIT_MAX_BURST=100。测试随机example.invalid账号，没有生产请求或SMTP。
- 最后用`docker inspect`核对ID、label和挂载后，按上述完整ID执行`docker rm -fv`成功；只删除自己的vw-copy-data，`test ! -e`通过；`docker ps -a --filter name=mygo-card2-01a1149e-vw`无输出。没有遗留本轮容器/数据或清理其他资源。

## 下一轮直接继续的入口

优先 **个人Bitwarden import/export真实闭环**，再reprompt/秘密、组织RSA，不重做已完成模块：

1. 原生文件选择/保存可直接复用当前依赖 `github.com/egoist/mygo@v0.2.15/dialog.go`：`mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.window, Filters: []mygo.FileFilter{{Name: ..., Extensions: []string{"json"}}}})` 返回paths（取消nil），`Dialog.Save(SaveDialogOptions{...})` 返回path（取消空字符串）。这两个API可任意goroutine调用、阻塞到关闭对话框。**这里只读确认了API，尚未集成产品或测试。**
2. dialog结果回到UI时必须核对epoch/scope/revision，锁定取消后不能继续解密/写入/发请求。原生保存对话框只选路径，并不实现安全写入。导出仍需明确敏感确认、安全0600临时文件/原子落盘、失败/锁定清理、符号链接/覆盖处理；这些尚未实现，不能把Save API当安全存储。
3. Bitwarden官方格式转换需固定客户端源码为据，完整映射八类型/fields/history/URI/folders。不要将`CipherFields`直接JSON输出当官方格式；`NewPersonalCipher`仍拒绝history/未知字段，不可直接用它声称完整导入。导入需新key、folder映射、明确创建预览/确认、部分失败逐项追踪与未知结果不重试；导出全量加密快照解密只能在认证lease内，未知字段不能静默丢弃。
4. 可复用本轮copy的已知字段/schema与随机item key思路，但它是对已保存个人源的复制，带权限与revision要求，**不能把它直接复用为任意导入协议壳**。copy含附件/FIDO2/未知扩展仍需后续支持。

## 整卡仍未完成（全部保留）

- 个人/组织import-export、官方互操作；完整copy含附件/FIDO2/未知扩展。
- reprompt主密码再次验证/短时scope+revision授权、密码安全展示/复制与剪贴板过期/锁定清理、TOTP生成/复制、历史删除、冲突比较与显式重基。
- 组织PKCS8/RSA-OAEP3/4密钥链、role/group/manage/readOnly/hidePasswords/accessAll权限、collections/共享、组织CRUD/退出、邀请接受确认撤销恢复/成员与群组、策略/events/Public API目录导入/API keys/账号恢复。
- 附件独立有界binary/multipart/query、0x02/IV/HMAC/CBC、外部URL禁Bearer、大小/MAC/URL、两阶段补偿/安全临时文件；Send seed16/HKDF/password/fragment/send_access、文件/文本CRUD与接收UI。
- 账号注册/验证/profile/keys/主密码/邮箱/KDF/用户key轮换恢复/删除/清库/security stamp，MFA其他provider管理、SSO/WebAuthn平台交互，设备/auth requests/domains/emergency/recovery，SignalR MessagePack通知与断线同步。
- 桥仍4MiB限制，超限保旧但不是永久范围排除；query/multipart/binary统一传输/Retry-After、逐注册method/path/别名完整矩阵仍缺。
- 上述模块的权限/故障/crypto/真实互操作，以及真实视觉/安装/Keychain/AutoFill/SMTP/WebAuthn/SSO验证。

固定协议缓存仍可读：Vaultwarden1.37.4 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`，commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`，tag对象 `54a40806c990da2def7acd5a3152edc530c59b79`，归档SHA256 `d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7`。固定客户端commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce`。本轮只读固定本地源码，没有重新下载或更换版本。

继续同一卡，不自审、不完成、不合并；下一轮从最新HEAD开始。
