# 并行集成：附件客户端

本分支基于 `14bbaf0ec2f176c598560883cc895f4dcd24405d`。协调者根据用户最新决定，将完整 macOS 客户端拆为并行任务；本卡候选仅覆盖**连接现有 Vaultwarden 服务的附件 Session + 原生列表/上传/下载/删除闭环**。不实现服务端路由、数据库或权限服务，不承接 Send、legacy 跨组织 binary 迁移或账号模块。全客户端是否完成由最终集成卡验收；本候选需独立 Review，提交不等于合并。

## 可复用客户端接口

`internal/vaultwarden/attachments.go`、`attachment_access.go`：

- `Session.Attachments(ctx, vault, cipherID, grant, persist) ([]AttachmentInfo,error)`：受认证快照、组织隔离与新 `/sync` 权限共同控制；仅返回 ID、安全文件名建议和密文大小，不返回 key/签名 URL。
- `Session.UploadAttachment(ctx, vault, cipherID, filename, *os.File, grant, persist) (AttachmentUploadResult,error)`：**接管并关闭**已安全打开的普通文件。输入 0–512 MiB；随机附件 key，cipher key 加密文件名/包装 key；有界磁盘加密，重新读取权限后创建 v2 metadata，严格校验 attachmentID、direct type0 API 相对 URL、cipher 身份/版本/原有字段与新增附件 key/name/size；再次 `/sync` 核对后仅一次 multipart 上传，最终 `/sync` 核对。`MetadataCreated/Uploaded/Reconciled` 表示分阶段确认程度；任何错误都保留可确认的 attachmentID，不自动重试或 DELETE。完整普通 Sync/checkpoint 仍由原生 controller 完成，本方法的私有权限 sync 不发布新的本地 vault。
- `Session.DownloadAttachment(ctx, vault, cipherID, attachmentID, grant, persist, consume) (*AttachmentPublication,error)`：认证 GET 下载 metadata 与快照 ID/key/name/size 对照，独立无凭据 signed 下载、完整 MAC 验证后把临时普通文件交给 `consume(*os.File,size)` **暂存但不发布**。无 attachment key 的 legacy 文件用 user/org key，有 key 的用 cipher key 解包。暂存后再次取服务端权限与精确记录核对，返回单次进程内发布能力。失败时调用者清理自己的暂存文件。
- `Session.PublishAttachment(ctx, proof, grant, publish func() error)`：短回调仅做原子不覆盖发布，不复制文件、不调用 Session。proof 绑定 Session、快照、revision、epoch、reprompt，30 秒有效且消费一次；lock/logout/换号/授权撤销/快照失信/取消后不可发布。
- `Session.DeleteAttachment(...) error`：受控单次 DELETE，成功回执后原生 controller 必须正常同步；未知结果不重试。UI有独立永久删除确认。

`authenticated.go` 的唯一共用变化：抽出包内 `prepareAuthenticatedDispatchLocked(ctx, mutation, persist, guard)`，使 JSON 与 streaming 请求共用 refresh→checkpoint→policy→guard→取消检查；原有 GET 在 401 刷新后也再次执行 guard，不能延长旧授权。签名文件下载仍绝不继承 account Bearer/cookie/device/referer。

## 原生入口和文件通道

- `cipher_editor.go` 和 `organization_ui.go` 各接一个 `attachmentView`；其他编辑行为不重写。新文件 `attachment_editor.go` 提供列表加载、系统 Open/Save、上传、另存下载、删除确认、进行中状态、取消、失败与完成结果。只读组织仅有列表/下载。reprompt 仍由原项目授权流程处理。
- 原生操作传路径到 Go，自有安全文件句柄向 Session 输送文件，**不把文件塞进 JSON/4 MiB 桥**；Swift 存储 schema/ABI 未改。输入/输出每一层父目录都通过现有 `openBackupParent` 的 no-follow descriptor 遍历；输入只接受普通文件，防止符号链接/FIFO及打开后路径替换改变读取对象。上传同时检测处理前后长度/mtime变化；这不是对任意并发原地改写者提供文件系统快照。
- `attachment_file_unix.go` 用64 KiB流复制到所选目录0600随机暂存文件，fsync后保留未发布状态；复用 `stagedBackup.Commit` 的 `linkat` 原子不覆盖发布。晚回调/错误/取消只清理自己的临时文件，不删除用户已保存的目标。文件名仅作显示，去掉路径部分/控制字符；当前 Save panel 由用户填写目标名，未设置建议默认文件名。
- 文件提交前 UI 再核验 Swift storage status 的 account/server/revision lease，并在 UI 线程调用 `PublishAttachment`。上传/删除前比较独立控制项副本和受认证已保存内容，拒绝未保存草稿，防止同步关闭表单导致静默丢失；检查不修改原稿。刷新 checkpoint 导致旧授权失效时保留认证边界，不绕过。
- 进度为可见“验证权限并传输”状态，配取消及完成/失败反馈，**没有百分比/速率进度**。单次操作 controller 5分钟，底层 HTTP 同样有界。没有附件离线文件缓存，列表/传输目前需要联网。

## 生命周期及锁顺序

Session方法持 `mu`，`beginOperationLocked` 注册 `cancelOperation`。`Close` 先短持 `operationMu` 设置 stopping并取消，释放后才等 `mu`；文件输入 `context.AfterFunc` 关闭自有输入句柄，HTTP绑定ctx，所有spool由defer关闭删除。`PublishAttachment` 在 `mu` 下验证proof，再持 `operationMu`执行短原子发布，和Close的撤销有确定先后次序，不能在回调再次调用Session而死锁。UI不在后台直接发布目标，所有结果回到UI线程后核对epoch/editor/snapshot；late callback仅清理stage。

## 本轮实际验证

工具链均由 `bash scripts/resolve-go.sh` 解析；临时产物只在本会话 `$TMPDIR`。测试过程未改主目录、恢复ref、用户已有应用/watch或生产账号。

- `go test ./...`、`go vet ./...`、`go build -o "$TMPDIR/mygo-attachment-client" .`、`go test -race ./...` 通过。新增Session测试包括个人/组织空/9MiB文件上传、metadata拒绝/恶意URL/type/id/cipher/key/size/版本、分阶段失权/策略/失败/取消；不自动重试或补偿删除。
- download测试包括 legacy-key、只读、隐藏密码、reprompt、metadata错配、坏MAC/截断/签名失效、传输/暂存后撤权、lock/epoch/快照失信/取消/超时/重复proof；未校验内容不进入consume。已有基础 signed跨host无凭据/redirect/8MiB binary测试继续通过。
- preflight测试涵盖scope、公有VaultData篡改、回收站、quarantine、pending-type15、无checkpoint callback、checkpoint失败/取消、401 refresh后的guard重验、Close取消且零写入；未冒称模拟夹具替代真实平台权限链。
- root headless MyGo测试验证入口/删除确认/只读按钮/进行中与取消/lock/草稿保护；文件测试覆盖超过4MiB流、0600、no-follow、父目录symlink、打开后输入替换、目标抢先存在、不覆盖/不误删、取消清理。
- `MYGO_VW_ATTACHMENT_TEST=1 go test ./internal/vaultwarden -run '^TestLiveAttachments$' -count=1 -v -timeout=150s`：现成 **Vaultwarden1.37.4** 唯一Docker实例的个人和组织0字节/8MiB+3完整create/upload/list/download/校验/delete/sync通过；真实成员只读下载/拒删、隐藏密码新旧快照拒绝、撤权后旧快照拒绝通过。fixture只注册example.invalid账号，邀请现有隔离账号，无真实邮件；按完整container ID+唯一label核对后清理，最终对应docker列表为空。
- 真实 `scripts/xcode-build-bridge.sh` arm64 macOS14 无签名桥构建通过，输出位于 `$TMPDIR/attachment-bridge-*`。未改Swift代码，不重复无关Swift单元/AutoFill测试。

## 明确边界与后续集成

1. **未实测**macOS窗口/Open/Save panel交互、真实Keychain/Touch ID、真实Swift持久lease与lock竞争、签名安装或系统AutoFill；headless/编译/Go-only认证回执不代表这些平台测试通过。
2. 仅固定Vaultwarden1.37.4 direct `fileUploadType=0`；外部预签名上传/Azure拒绝且保留未知结果供核对。支持认证binary type2；旧无MAC type0/新COSE拒绝。512MiB是实际输入上限，但本轮最大实际传输为9MiB级测试，未跑512MiB端点实传。spool占磁盘，不承诺安全擦除。
3. 两阶段操作不是事务。metadata已建但后续拒绝/失权/取消时不自动删除；用户同步看到附件后可明确删除。服务端成功但客户端未收到回执时只能同步核对，不能宣称回滚。删除确认后正常sync失败同样需要核对。
4. legacy**读取**无key分支已验证；legacy跨key共享、附件复制/备份/离线cache由后续专门任务处理。本模块没有把账户key授予组织。
5. 文档与实现作为并行集成接口，以本页为本轮状态。全局handoff旧INCOMPLETE描述属于上轮历史；协调者在最终集成时统一coverage/README，不把其他子任务缺口误记为本附件分支完成。
