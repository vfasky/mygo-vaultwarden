# Send 独立客户端模块交接

本卡基于 `14bbaf0ec2f176c598560883cc895f4dcd24405d`。仅新增 `internal/vaultwarden/send*.go`、根 `send_*.go` 和本文件；没有修改 Session struct、认证/存储核心、附件 lane、main/ui/network 或总文档。独立协议、Session 操作、原生组件与隔离测试已实现。**真实主窗口入口由集成卡注册；未验证真实窗口、系统剪贴板或系统文件选择器的交互。**

## 固定协议与加密

- Vaultwarden 1.37.4，commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`，源码 `src/api/core/sends.rs`、`src/auth/send.rs`、`src/db/models/send.rs`。客户端审计基线 `5983f56ce0cf924eea56c7d8f066f7885825a7ce`；本模块不支持后续 item-send 等扩展。
- seed 随机16字节；HKDF-SHA256 salt=`bitwarden-send`、info=`send` 派生64字节 AES/HMAC key。seed 仅以 user key 的 type2 EncString 包装到 owner DTO；接收 seed 只在 URL fragment `/#/send/{accessId}/{base64urlSeed}`。固定服务器 accessId 是 UUID 原始16字节的无填充 Base64URL。复制链接也是秘密操作。
- Send 名称、私人备注、文本、文件名用 Send key 加密；隐藏文本布尔值/访问限制/日期/禁用/隐藏邮箱是标准协议 metadata。私人备注仅 owner 可见。访问口令是 PBKDF2-SHA256(password UTF-8, seed, 100000, 32)，再标准 Base64。更新时 nil 保留口令，移除走专用 PUT。
- 官方 SDK 向量来源：[send.rs](https://raw.githubusercontent.com/bitwarden/sdk-internal/39dbb510f5eae82f5cbfd527b0f70a01d5626ec1/crates/bitwarden-send/src/send.rs)，`test_get_send_key`、`test_decrypt`：测试固定用户包装 seed→64B key，以及独立 seed→名称/文本。密码另用 Python hashlib 独立固定向量；文件 binary 复用既有官方 SDK 附件向量/有界流 helper。
- owner：GET `/api/sends`、GET/PUT/DELETE `/api/sends/{uuid}`、POST `/api/sends`、PUT `/api/sends/{uuid}/remove-password`。新文件：POST `/api/sends/file/v2`，验证 fileUploadType=0、sendResponse 身份/完整加密数据/密文大小与精确相对 URL，再 POST `/api/sends/{uuid}/file/{fileId}` multipart `data`。**multipart filename 必须是加密文件名**；不能沿用附件的固定 `attachment.bin`。
- receiver：POST `/identity/connect/token`，grant_type=`send_access`、client_id=`desktop`、send_id=`accessId`、可选 password_hash_b64；验证 scope=`api.send.access`、Bearer、有效期/有界 token；随后 POST `/api/sends/access`，文件 POST `/api/sends/access/file/{fileId}`。没有旧 `/access/{id}`。文本访问和文件获取下载能力会消耗访问次数，不自动重试。
- 文件上限512 MiB，64 KiB 分块；使用现有 binary `0x02 || IV16 || HMAC32 || CBC` 与 private spool。接收先完整验证 MAC/大小/填充，再解密；signed URL 请求无 owner/receiver bearer、cookie、设备头或 Referer，禁所有重定向。上传只构造当前 server 路径，拒绝外部/错ID/未知type回执。
- 删除时间须未来且≤31天，过期时间可空、不能晚于删除；非空最大次数为1…2^31−1。日期上传规范化到毫秒（防服务端序列化精度导致误判）。不提供邮件验证输入，原生界面准确提示固定服务器不支持。旧邮件验证型/未知 owner authType 拒绝解密为可编辑草稿。

## Session API 与恢复规则

- `Session.NewSend(vault, kind)`：kind 0文本/1文件；必须当前 `AcceptAuthenticatedSnapshot` 接受的完整 vault。返回 `*SendDraft`。
- `Session.Sends(vault)`：从受信快照的 sends 派生离线 owner 草稿；调用者改写 `VaultData.Sync`、scope、revision、pending 等不会获得读取许可。离线访问次数注明可能过时。
- `Session.ListSends(ctx, scope, persist)`：认证 owner 列表，执行现有 refresh/checkpoint；当前读取成功才返回解密草稿。草稿拥有 plaintext/seed，必须逐个 `Close`。
- `SaveSend(ctx, draft, source, plaintextSize, persist)`：文本 source=nil；新文件要求精确长度 reader；已有文件内容及文件名不可修改。使用 `OpenSendSource(path)` 安全打开普通文件，关闭句柄归调用者。成功返回新的 `SendDraft`；失败绝不把文件 metadata 当完成。
- `DeleteSend`、`RemoveSendPassword`：重新认证读取当前 owner 条目，与草稿私有 wire 比较，再单次派发。删除不被 DisableSend 阻止；移除口令只执行 DisableSend，不误执行无需回写的隐藏邮箱限制。
- 每个写动作先受控 refresh 并持久 checkpoint，读取完整权威 `/api/sync` 用现有严格 parser 验证 scope/profile/wrapped key/成员/双政策数组，再执行 type6 DisableSend 与 type7 SendOptions。owner/admin 按源豁免，confirmed 普通/经理执行，禁用组织不绕过政策。本机 pending6/7 阻断修改；删除仍允许。全局服务端 sends_allowed 最终由服务器拒绝。
- 私有草稿绑定 Session 指针、scope、authorizationEpoch、authorizationRevision。慢 refresh/checkpoint、锁定、切换账号或快照替换不能续接旧稿；文件 spooling 后和第二阶段前重新检查，第二阶段重新读取政策。`ShareLink()` 也检查当前 Session lease，不能从锁定后的旧草稿复制 seed。`CanEdit()` 仅报告 lease，不能授权或续期。
- 一旦调用写派发，草稿被消费，所有写错误都不会自动重试。网络/5xx/异常成功/错误成功回执/写后取消为 `MutationUncertainError`。新文件 metadata 已成功但 upload 未完成时返回 `SendUploadError{ID,Cause}`；UI 明示部分结果，并提供刷新/同步后明确删除入口。无自动补偿 DELETE、无自动重传。
- 保存前本地校验/政策拒绝等尚未派发的错误，原生面板保留仍有效的草稿；lease 已失效或请求已派发的草稿不能复用。写后必须全量 sync/publish，再重开条目。owner GET→PUT/DELETE 与政策 GET→写无服务器事务/CAS，接收访问次数也会造成草稿冲突，需要重开。

## 接收与文件发布

- `Client.OpenSend(ctx, link, password)`：只接受显式配置 server（含 base path）的完整分享链接。粘贴其他主机的链接不会发请求；fragment seed 不进入 URL path/query/body。返回独立 `*SendReceiver`。无需 owner Session；parent ctx 生命周期应覆盖接收面板，不要在 Open 返回后立即 cancel。
- `receiver.Fields()`：解密受控 view，包含可用时的 creatorIdentifier；接收者不会看到 owner notes。面板对 hidden 文本先显示明确“显示分享文本”操作。
- `receiver.SaveFile(ctx, absolutePath)`：先验证并 pin 目标目录，再获取下载能力、下载、MAC验证、解密。父目录逐级 openat(O_NOFOLLOW)，拒绝 symlink；0600临时文件 fsync，发布前再检查取消/receiver 状态，linkat 原子 no-replace。已有目标（含竞态新出现的文件）不覆盖。所有失败/取消路径移除临时文件。
- `receiver.Close()` 立即取消其在途传输，随后清空 key/token/wire。失败的文件 access 消费 receiver 的下载动作，用户只能明确重新打开分享请求新能力。普通文件删除不是磁盘安全擦除；Go/OS 不能保证历史字符串副本完全清零。

## 主窗口注册步骤（集成卡可直接实施）

1. 给 app 增加 `sendPanel *SendPanel`；在侧栏现有 Send 导航选中时创建并渲染 `sendPanel.View(c)`。owner 入口要求 `sessionOwnsSnapshot()`、非 pending，取得 `*vaultwarden.Session`、当前认证 `a.vault`、`*a.liveScope`。client 用相同规范 server 新建或使用 app 已持有客户端；不改变服务器配置来接收粘贴的陌生链接。
2. 构造 `SendHost`：
   - `Dispatch`: 通过当前 window.Update 执行传入 callback。worker 不直接写 app/UI 状态；闭窗后仍应执行清理 callback（不可静默丢弃 late result）。
   - `Check`: 使用独立、线程安全的 lease 数据（捕获 scope、UI epoch、expected revision、unlocked/closed 位），读取 `callStorage(status)` 并核对 scope/revision/unlocked。不能在 worker 无锁读取 app mutable fields；锁定/切换应原子撤销 lease。
   - `Checkpoint`: 使用现有 `saveSessionCheckpoint(prior, cp, callStorage)`，完整验证 `cp.AcceptAuthenticatedReceipt`；同步更新线程安全 expected revision/待接纳 receipt。**不要在此回调调用 Session.AcceptAuthenticatedSnapshot/BindSnapshotRevision 或同步等待 UI 做这些操作**，因为 Session 操作持有 mu。
   - 在 `Dispatch` 的 UI wrapper 中，先按现有 `adoptSessionCheckpoint` 接纳本次已验证回执；接纳失败则 `stopNetwork`/关闭面板。checkpoint 推进 epoch 使旧 Send 草稿失效，建议关闭并重建面板，然后允许 callback 清理晚到结果。这里不能把旧 draft epoch 改成新值。
   - `Copy`: 使用 app 现有受控敏感剪贴板操作；分享 URL 含 seed，应使用现有超时清理/锁定撤销规则，不能日志输出字符串。
   - `Changed`: 触发现有 `syncVault(false)`；sync 前关闭原面板、发布受信快照后重建。这个回调仅在确认成功时触发；未知/部分结果由用户“刷新 Send”或主窗口同步核对。
3. 调用 `ConfigureSendDialogs(a.window, &host)` 安装真正的 MyGo native Open/Save sheet；源文件经 `vaultwarden.OpenSendSource` 验证，目标通过 receiver 安全发布。native sheet 不支持程序化取消，但关闭面板会取消生命周期；sheet 返回后检测取消，不打开源文件、不发上传/下载。已有目标不会覆盖，即使系统 Save sheet 给出覆盖确认。
4. `NewSendPanel(session, client, vault, scope, host)`，根据入口调用 `Offline()` 或 `Refresh()`。它拥有自己的草稿、rows、receiver、in-flight generation，不向全局注册表注册，也不通过 raw JSON 展示。
5. 在 `lockInterface`、`stopNetwork`、账号切换、全量 sync 开始、快照/epoch replacement、退出 Send 导航、主窗口关闭之前执行 `sendPanel.Close(); sendPanel=nil`。先 cancel，再清除 UI；in-flight worker 拥有移交的 draft/receiver，晚到结果由 generation 检查关闭，不复活敏感信息。先撤销线程安全 host lease 再关闭面板。
6. 如果提供锁定状态的匿名接收入口，可构造 session=nil/vault=nil 的面板；其 Check 必须绑定匿名窗口自身 generation/cancellation，不能假装拥有 owner session。New/Offline/Refresh 自动不运行 owner API；接收使用独立 client。该入口是否放主窗口由集成卡决定，不影响本模块的 receiver 功能。

## 验证证据

- `go test ./... -run '^TestSend' -count=1`：Send 官方 HKDF/文本向量、独立 PBKDF2向量、owner CRUD/政策、snapshot tamper/lock、pending、refresh先checkpoint/失败零写/旧稿失效、取消/未知写零重试、第二阶段政策拒绝/回执身份/大小/类型/URL保护、multipart 加密 filename、receiver 路径/口令/seed、跨origin signed URL 无凭据/cookie、MAC/超长/重定向/错ID/取消、源文件与发布 symlink/no-replace/0600/清理，以及原生 headless 组件表单/锁定/晚到回调/未知结果、接收隐藏文本、owner/receiver 口令字段隔离、取消文件选择保留尚未派发草稿。
- `go test -race ./... -run '^TestSend|^TestAttachment' -count=1` 通过（含复用附件 binary/transport 的定向回归）。
- `MYGO_VW_SEND_TEST=1 go test -race ./internal/vaultwarden -run '^TestSendLive1374$' -v -count=1` 通过：独有 `vaultwarden/server:1.37.4` loopback 容器，随机端口、随机 `mygo-send-{uuid}` 名称及 `mygo.fixture` label；fixture example.invalid 账号；文本 owner创建/编辑/禁用/密码添加与移除/三次访问上限/真实过期拒绝，接收错误口令与正确解密；文件元数据/direct multipart/接收grant/下载/解密/0600发布；owner列表与两项删除。Cleanup 检查 container ID 对应 label 后 `docker rm -fv ID`。未使用生产账号、没有外发真实分享。
- `go test ./...`、`go vet ./...`、`git diff --check` 通过。新增文件不依赖全局 go.mod 变更。
- 真实主窗口接线、native sheet 视觉、真实 Keychain/系统剪贴板行为不在本卡实测范围；最终集成卡须验证。HTTPS 下载通过本地 TLS fixture，真实 Docker 回环仅 loopback HTTP；未验证外部托管生产存储。
