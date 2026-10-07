# 完整 Vaultwarden 实现：阶段交接

**INCOMPLETE — 阶段成果，整卡未完成，未达到验收。** 协调者已同意在本进程提交后继续同一 Board 卡片、复用同一工作树；不得启动 Review 或把模块测试通过当作整卡完成。完整原始需求保持不变，详见 Board 卡片 #2。此文档是下一实现进程的起点。

## 工作树、提交与基线

- 唯一写入工作树：`/Users/vfasky/Library/Application Support/Waku/worktrees/board/56a21c6a-f119-465b-ae4e-7e77f68151bd/board-2-vaultwarden-api`。
- 卡片分支：`waku/board-2-vaultwarden-api`。
- 主目录 `/Users/vfasky/code/mygo-vaultwarden` 只能读，不能提交、暂存、清理、stash 或写文件。主目录 dirty 的最终合并由协调者处理。
- 原始 main：`2aa0d3b9f10f2a9ae41344393fbaf69ff676364d`。
- 基线提交：`4b0a910`（只读导入全部 tracked diff，包括删除；复制允许的 20 个未跟踪源码/资源；排除 shot.png、shot-s.png；没有读取 .local 凭据）。包含原生登录/TOTP/解锁、session 持久化、Swift 快照、UI 与 dev-debug 前序成果。
- 当前功能模块提交：`331b1c4`，建立安全门控/type-2 加密/有限无损 cipher 编辑和状态操作；本交接文档会在其后单独提交。最终 HEAD 以最终报告及 `git log -1` 为准。
- 导入时与阶段末均 `cmp` 核对源 tracked binary diff 未变化。阶段末逐个比较 `git show 4b0a910:<path>` 与源目录 20 个允许文件，全部字节一致；未动源目录。

## 已实现接口与约定

1. `internal/vaultwarden/authenticated.go`：`statusError`（11 行）；`beginOperationLocked`（32 行）；`persistPendingLocked`（51 行）；`refreshAndCheckpointLocked`（65 行）；内部 `authenticatedLocked`（82 行）。调用方持有 Session.mu；operation 独立锁让 Close 在等待 mu 前取消网络。
2. `client.go:277` Close 与 `client.go:325` SyncWithCheckpoint 已接入。pending checkpoint 无 callback 返回 ErrCheckpoint；已绑定账户且有 PasswordUnlock 的持久 session 没有 callback 时禁止 token 轮换。初次登录未绑定账户的既有 Sync 流程继续工作。
3. `types.go:30` MutationUncertainError 包装非 GET/HEAD 请求的传输错误。调用方必须提示核对并同步；绝不能自动重复写入。401 只对 GET 执行一次 refresh + GET，写请求不重试。400/422、401、403、404、409/412、429、5xx 分别分类，原始错误正文不交给 UI。
4. `crypto.go` EncryptString：64-byte key，随机 16-byte IV，AES256-CBC PKCS#7 + HMAC-SHA256，type-2 字符串。明文 ≤ 1 MiB。DecryptString 继续拒绝未知格式。
5. `cipher_document.go:16` CipherDocument 保存原始 encrypted JSON；**只能存入认证后的加密 snapshot payload，不能塞进 displayCredential**。CipherFields 是有限已知明文字段视图，字段 map 中仍可能携带未支持的 encrypted 扩展；不可直接作为 JSON 编辑器暴露给用户。
6. `cipher_document.go:182/201` DecryptCipherDocument / EncryptCipherDocument：五类已知字符串解密，独立 item key 解包，保持 opaque/passkey 字段和超大 JSON 数值；重写保持同一 item key、ID/type/organization/revision。要求源 edit/viewPassword、无 reprompt、有效 RFC3339 revision；写入 encryptedFor + lastKnownRevisionDate。**当前拒绝密码、URI、自定义字段、历史、archive/deleted 的修改**；不可声称完成完整编辑，也不可把这个方法用于 copy/share/key rotation。
7. `ciphers_api.go`：ChangeCipherState、SetCipherPersonalMetadata、UpdatePersonalCipher 均 requireScopeLocked（server+account），经过 cancellation/checkpoint，拒绝含 path/query/百分号等字符的 ID。状态成功后只返回操作结果，不乐观改快照，调用方必须用当前 revision lease 同步。
8. 状态接口区分 PUT delete（软删除）与 DELETE cipher（永久删除）。personal partial 仅 `{folderId, favorite}`，避免覆盖秘密内容。**这些 API 目前没有 UI 调用，也未完成应用级 reprompt/确认。**

## 固定上游源码与版本证据

- 原始资源：`https://raw.githubusercontent.com/dani-garcia/vaultwarden/1.37.4/src/api/core/ciphers.rs`。
- 内置搜索确认该标签的 CipherData 与 routes；Bun 原始 fetch 30 秒超时后完整读取技能 `/Applications/WorkTony.app/Contents/Resources/providers/pi/skills/github-mirror-fallback/SKILL.md`，从 `https://gh-proxy.org/` 前缀下载同一公开资源成功。
- 本进程只读参考缓存：`/tmp/pi/01a11459-bb53-75b3-a6b2-a18629359dcb/ciphers-1.37.4.rs`。
- SHA-256：`c6787b94bd8f0b13b328ad55d972c91556831b48ea379692d85092412e7ca9ae`。镜像内容验证包含 `pub fn routes()`，正文为 Rust 源码。尚没有标签 commit 签名/摘要验证，不能声称完成完整供应链验证。
- scratch 生命周期可能在进程退出后结束；如缓存不在，向协调者拿并行审计缓存，或按技能重新取得固定资源，不可换 main。
- 具体已读：routes 34–104，sync 121，CipherData 240–298，create 338–384，update 682–715，partial 743–754，share 988–1021，attachment 1167 起，删除 1499–1590，restore 1601，move 1639，purge 1712，archive 1778。
- 重要发现：1.37.4 除题述 type1–5 外，还接受 type6 BankAccount、7 DriversLicense、8 Passport，不能列为上游不支持。当前代码明确拒绝未实现类型。服务端 stale revision 检查可能返回普通 400，不保证 409。
- 完整各模块注册路由审计卡正在并行，由协调者转交；本进程没有启动任何子代理。

## 已执行验证及结果

工具链统一用 `GO_BIN="$(bash scripts/resolve-go.sh)"`。

- `"$GO_BIN" fmt ./internal/vaultwarden`：完成。
- `"$GO_BIN" test ./...`：三个包通过；最终一轮 root cached、internal/vaultwarden 0.438s、scripts/dev-debug cached。
- `"$GO_BIN" vet ./...`：退出 0，无输出。
- `"$GO_BIN" build ./...`：退出 0，无输出，没有运行/安装 app。
- `"$GO_BIN" test -race ./internal/vaultwarden`：通过，2.447s。
- `swift test --package-path macos`：42 XCTest，0 failures；SnapshotStore 34、VaultCredential 2、VaultURI 6；后续无 Swift 修改。
- `git diff --check`：通过。
- 新测试：authenticated_test.go（checkpoint 绕过、状态脱敏分类、Close 中断、写401无重试、未知写结果）；encrypt_test.go（空/Unicode/块/大输入/随机IV/三个组件篡改/错key）；cipher_document_test.go（五类、passkey/opaque 保留、大整数、拒绝危险修改、恶意 ID）；ciphers_api_test.go（状态方法、scope、partial最小体、revision+encryptedFor）。
- 未做真实 Vaultwarden 安装回环、真实账号、视觉预览、签名/安装、真实 Keychain/AutoFill 验证。未访问/写入生产库，未触碰用户 app/watch。

## 下一批具体步骤

1. 阅读 agent.md、覆盖矩阵和 Board 原任务；向协调者取得并行 1.37.4 全路由审计，不再从标签猜端点。先核对新模型与上游 SDK 字段加密规范，完善字段 typed 编辑边界。
2. 完成 cipher 创建/复制与独立随机 item key、password history、URI checksum、自定义字段/history 无损编辑，支持完整 sync 数据（raw CipherDocument + folders + collections + policies + domains + sends + org profile/privateKey）。未知字段跨 key 操作要拒绝或完整重加密，不能丢失 passkey。
3. 组织 RSA 私钥（类型3/4及现代格式按正式协议）、组织 key 解包、collection 权限；完善五类及额外基线类型状态，明确不支持格式而非当空。
4. 先设计并落地加密 snapshot 版本迁移与 Go/Swift bridge 完整模型，再接原生编辑/详情/分类/密码TOTP/确认。新明文只能在认证 lease 下取用；display 列表不可含完整秘密。AutoFill 只投影合规 Login，deleted/reprompt/不可访问/归档规则须明确并测试。
5. folders、批量、回收站 purge、attachments 加密上传/受限下载、个人/组织 import/export（明确确认）。请求层增加 query/multipart/binary、大小/超时/取消；继续避免通用 raw HTTP UI。
6. 组织管理、成员/邀请/角色、groups/policies/events/目录；Send 文本/文件全链路；账号安全、MFA providers、设备/auth request/emergency/domains/必要浏览器认证。按范围逐项实现 UI，不用空壳掩盖。
7. 通知/断线同步、锁定清空所有新 form/download/auth；恶意响应、并发 revision 与失败测试；完整 Go+Swift 回归，条件允许跑隔离临时 Vaultwarden，更新 README/旧只读文档真实产品状态。
8. 同步维护覆盖矩阵，每项写实现/测试/入口/权限/边界，最终完整实现后再交独立 Review。

## 已知风险与必须修复的边界

- 目前状态操作由服务器执行权限检查，尚缺 UI reprompt/危险确认与 collection/policy 集成，不能直接当可用产品发布。
- 加密更新是有限字段更新，未做新增/复制/组织，密码/URI/历史/字段修改明确报 ErrUnsupportedEdit；后续实现这些后才能去掉限制。
- 请求成功但响应损坏的写入结果需统一用“同步核对”语义处理（目前更新解码错误可直接返回 ErrProtocol/ErrEncryption）；不能诱导重试。
- HTTP 429 没有 Retry-After 调度；仅提示稍后重试，不自动重复写入。
- CipherDocument 尚无持久 scope/revision 绑定包装；Session API 已检查调用 scope，但未来 UI/离线编辑必须让文档来源绑定快照 scope+revision，不能接受外部任意 encrypted document 当作当前账号编辑来源。
- Go string 无法可靠原地抹除；当前继承项目做法，真正新增明文生命周期与UI清理尚待实施。新 API 不应绕过 app epoch。
- 完整路由矩阵尚待审计，额外类型与 COSE/其他加密格式不能猜测。

请继续同一卡片，不把本阶段提交合并为“完成”。
