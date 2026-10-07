# Vaultwarden API 覆盖矩阵

**INCOMPLETE：整卡未完成，未达到验收。** 本轮增加个人原生文件导入导出与官方 CLI 互操作；不是完整 Vaultwarden API 产品。协调者已批准阶段提交后继续同一卡，禁止据此启动 Review 或合并。

固定服务器 **Vaultwarden 1.37.4**：tag 对象 `54a40806c990da2def7acd5a3152edc530c59b79`，commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`，归档 SHA256 `d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7`。字段加密参考 Bitwarden clients `web-v2026.5.0` commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 的 `libs/common/src/vault/models/domain/{bank-account,drivers-license,passport,login-uri}.ts`。本轮从固定 commit 的 raw URL 成功读取这四份文件，未换用 main。

## 已连接的个人功能

以下 `/api` 前缀来自 main.rs 的挂载。别名列明服务器支持，不代表客户端逐个执行过。单条状态操作必须先在当前认证快照中打开可编辑的个人项目，写入前检查本地 revision，成功后全量同步并用原会话的 CAS 发布。

| 能力 | 方法 / 路径及别名 | Go 实现 / 测试 | 原生入口、权限与实际边界 |
|---|---|---|---|
| 全量同步 | GET `/api/sync`；query `excludeDomains` 尚未开放 | `SyncWithCheckpoint`、`VaultData`；sync/session 测试及真实回环 | 顶栏「同步」。保留服务器原始加密响应及未知区段；个人八类型列表与最小 Login 填充分离；组织数据只保存不解密 |
| 新增 | POST `/api/ciphers`；`/create`、`/admin` 未实现 | `CreatePersonalCipher`、`NewPersonalCipher`；八类型独立随机 item key 测试和真实回环 | 在八种分类选择「新增」；默认所有项目新增 Login。type-2 字段加密，item key 由用户 key 包装；未知 section/custom/URI 扩展拒绝跨新 key 写入；SSH 三项不能为空 |
| 更新 | PUT `/api/ciphers/{id}`；POST 同路径 / admin 别名未调用 | `UpdatePersonalCipher`、`EncryptCipherDocument`；八类型、未知扩展、大整数、自定义字段、历史和 URI checksum 测试 | 「查看与编辑」→「保存」。保留同 item key/FIDO2/未知扩展；必须个人、edit/viewPassword、无 reprompt、源 revision 合法。支持名称/备注/类型标准字符串、多 URI、TOTP 秘钥、文本/隐藏/布尔/关联自定义字段；关联目标按类型限定，未知关联ID/扩展与null值保留。reprompt再次验证仍缺 |
| 收藏 / 文件夹 metadata | PUT `/api/ciphers/{id}/partial`，POST 别名 | `SetCipherPersonalMetadata`，最小请求体 httptest | 收藏已接入完整编辑保存；partial 接口尚未直接接 UI，文件夹列表/管理及编辑器文件夹选择已接入 |
| 软删除 | PUT `/api/ciphers/{id}/delete` | `ChangeCipherState(CipherTrash)`；方法断言、真实回环 | 编辑页「移入回收站」→确认；不使用 POST 同路径 |
| 恢复 | PUT `/api/ciphers/{id}/restore` | `CipherRestore`；真实回环 | 回收站打开项目→恢复 |
| 永久删除 | DELETE `/api/ciphers/{id}`；POST `/api/ciphers/{id}/delete` 为永久删除别名 | `CipherDeletePermanently`；仅 DELETE 已测试 | 回收站打开项目→永久删除→不可恢复提示→确认；顶栏清空回收站只选deleted再确认批量删除 |
| 归档 / 取消 | PUT `/api/ciphers/{id}/archive`、`/unarchive` | `CipherArchive/CipherUnarchive`；真实回环，归档排除 AutoFill | 编辑页归档按钮；侧栏归档分类；完整 PUT 保留原 `archivedDate` |
| 分类 | 本地过滤认证后的完整库元数据 | `PersonalEntries`、`filteredItems`；headless 测试 | 八类型、收藏、归档、回收站；未知格式/reprompt显示受保护占位标题，不能解密编辑；不是虚假的空分类 |
| 密码历史 / URI 完整性 | 更新体的 passwordHistory、passwordRevisionDate、uriChecksum | 自动保留旧密码，URI SHA256 Base64 再 type-2 加密；单元与真实回环 | 改密码/网址时维护；历史显式显示/隐藏已接入，历史删除未完成。URI默认及0–5策略可编辑，未知策略保留；起始/正则匹配当前仅保存，不进入AutoFill |
| 完整离线数据 | 本地 `VaultData{version:1,scope,sync:base64}` | Go Documents 校验、Swift `SnapshotPayload.vault`、bridge、迁移与 checkpoint 测试 | 完整原始 sync 仅放 AES-GCM payload；认证主应用解锁才返回；状态/AutoFill lease不返回。旧 payload 无 vault 时可解锁，下次成功同步迁移 |

实际 Cipher 类型是 1 Login、2 SecureNote、3 Card、4 Identity、5 SSHKey、6 BankAccount、7 DriversLicense、8 Passport。逐字段加密名单来自固定客户端源码，未递归加密所有字符串。`encryptedFor` 是当前稳定账号 UUID。源 `lastKnownRevisionDate` 原样提交；服务端只有约一秒容差的旧版本检测，可能返回 400，并非严格 CAS。当前不轮换用户 key；源中的 `encryptedByKeyId` 若存在原样保留，尚无完整 keyId 生命周期/轮换流程。

## 安全边界及验证

| 边界 | 实际实现及证据 | 仍需完成 |
|---|---|---|
| 请求约束 | TLS/loopback、禁重定向、请求超时、32 MiB响应限制、ID过滤、脱敏错误；既有测试 | query/multipart/binary独立传输、Retry-After未完成 |
| 刷新持久化 | pending checkpoint失败阻断请求；Swift同scope/revision保存session并保留完整vault；相关Go/Swift测试 | 所有未来模块必须复用门控 |
| 写入未知结果 | 传输错误、意外成功状态、5xx、成功响应不可解码/身份错误、写后取消均按未知结果；不自动重试；UI禁重复保存并保留草稿 | 尚无逐字段冲突比较/显式重基；同步改变本地revision后旧草稿禁止提交，需用户核对后重新编辑 |
| 锁定与撤销 | `stopNetwork`推进epoch并取消会话，清除vault/editor/list；迟到回调不能复活并释放私有草稿；headless及race | Go/Swift运行时无法证明清零所有字符串历史副本；真实系统安装/视觉未验证 |
| 填充投影 | 只含个人Login；deleted、archived、reprompt、viewPassword=false和组织均排除；零条显式替换；真实归档回环及Swift撤销测试 | 组织授权后填充、等价域名、更多URI规则仍缺 |
| 未知字段 | 同key更新保留opaque passkey/扩展/大整数；加密输入不修改编辑草稿；未知格式失败 | 标准个人copy已实现新key完整转换；附件/FIDO2/未知扩展copy仍拒绝，share/用户key轮换未实现，不能用有限编辑冒充这些能力 |
| 桥和快照大小 | vault不混入64 KiB session；沿用4 MiB C ABI上限，超限报错、保旧快照 | 完整大库有界传输尚未扩展；附件禁止通过JSON/此桥传输 |
| 认证前元数据 | header仅控制元数据；完整库不在displayCredential/status/session日志；Swift认证lease才返回vault；原生开表单后才解密秘密 | 密码/TOTP安全显示复制、reprompt再次验证尚缺；当前密码输入遮掩且没有复制秘密入口 |

## 其余模块与新增覆盖（全部保留，不缩减范围）

| 模块 | 1.37.4 审计事实与边界 | 当前实现 / UI / 验证 |
|---|---|---|
| folders CRUD | POST `/api/folders`、PUT `/api/folders/{id}`、DELETE `/api/folders/{id}`；POST 更新及 `/delete` 为服务器别名，客户端未调用；GET 列表/单条由完整 sync 本地读取替代 | `SaveFolder/DeleteFolder/PersonalFolders`；type-2 名称加密、scope、错误未知结果、离线读取测试与真实 1.37.4 回环；侧栏新建/管理/筛选；编辑器文件夹选择；删除明确提示只解除项目归属；草稿绑定本地revision、锁定清除。服务器没有文件夹CAS |
| 个人批量管理 | PUT `/api/ciphers/move`（POST 别名）、`/delete`（软删）、`/restore`、`/archive`、`/unarchive`；DELETE `/api/ciphers`（POST `/delete` 为永久删除别名） | `ChangePersonalCiphers`；验证选中ID属个人快照，永久删除仅允许deleted；httptest方法断言、真实批量及400部分移动回环；顶栏批量管理→选择项目/操作→确认；回收站清空只选择deleted，绝不purge。任意批量错误后同步逐项展示当前目标状态，不重试、不宣称原子成功；锁定清除 |
| copy / import-export | 个人无 `/export` 或 `/trash`；purge是清全库 | `CopyPersonalCipher`经POST `/api/ciphers`新建，八类型标准字段、历史、custom、URI/checksum及legacy `login.uri`以新随机item key完整重加密；编辑页「复制为新项目」→说明当前草稿/清除归档回收状态→确认。源不改，绑定scope/revision/checkpoint；结果未知不重复创建，成功全量同步。httptest/headless/真实1.37.4八类回环通过。附件/FIDO2/未知扩展及非空encryptedByKeyId在请求前拒绝，完整复制仍未完成；个人明文文件导入导出已接入，详见下表；组织import-export、附件/FIDO2/未知扩展完整备份仍未实现。 |
| 个人文件导入 / 导出 | 无独立export端点；导入用 POST `/api/folders`、POST `/api/ciphers`，回收站项再 PUT `/api/ciphers/{id}/delete`；不调用purge或盲重试 | `backup.go/backup_import.go`、`backup_editor.go`、`backup_file_unix.go`；顶栏「导入导出」→格式与范围→敏感确认/预览→原生Open/Save。兼容JSON覆盖固定官方1–7类；MyGo格式1–8类，标准秘密、四类custom、多URI、全部history、全部个人folders含空文件夹；未知schema/附件/FIDO2/reprompt导出拒绝。导入先完整预检/新key加密后逐项创建、新folder ID映射、部分失败停止、已知ID同步核对。文件最大32MiB/10,000项目，0600临时文件、逐目录拒绝符号链接、原子不覆盖发布；epoch/scope/revision/取消门控。八类单元/真实1.37.4往返，官方CLI2026.5.0七类导入解密+官方导出再回导通过；未实际验证原生Dialog视觉。 |
| 组织 / collections / members / groups / policies / events / recovery | RSA SPKI/PKCS8、OAEP type3/4；权限涉及角色、群组、readOnly/hidePasswords/manage/accessAll；memberId不等于userId | 完整加密组织profile/collections等已随sync保留；RSA解包、组织CRUD、共享、策略/权限与所有管理UI未实现 |
| 附件 | `attachment/v2`元数据后multipart `data`；二进制 `0x02||IV16||HMAC32||CBC`；root `/attachments/...`或预签名URL | 未实现；需外部URL禁Bearer、大小/MAC、两阶段补偿和安全临时文件 |
| Send | seed16、HKDF-SHA256 salt `bitwarden-send`/info `send`；访问走grant `send_access` 后 `/api/sends/access`、`/access/file/{fileId}`；无旧 `/access/{id}` | 未实现。文件/文本所有者及接收UI均缺；emails验证型Send上游不支持 |
| 账号 / keys / KDF / registration | 新注册在 `/identity/accounts/register/send-verification-email` 与 `/finish`；rotate-user-account-keys为非整体事务完整DTO | 仅测试fixture注册，不是产品注册；profile/邮箱/主密码/KDF/轮换/删除/清库/security stamp未实现 |
| MFA / SSO / WebAuthn | provider0 TOTP、1 Email、2 Duo、3 YubiKey、7 WebAuthn；5 remember；8恢复码会删除MFA。`/api/webauthn`空列表不是MFA WebAuthn | 登录password/TOTP/refresh已有且真实回环；其他provider管理、浏览器交互、SSO/PKCE/解密尚缺 |
| devices / auth requests / domains / emergency | 有正式上游端点，不能视作不支持 | 未实现产品功能 |
| notifications | `/notifications/hub` SignalR MessagePack；匿名事件拼写 `AuthRequestResponseRecieved`；断线需全同步 | 未实现 |
| events / Public API | collect挂root `/events/collect`；Public API仅POST `/api/public/organization/import` | 未实现 |
| admin / 部署资源 | `/admin`是独立HTML运维cookie；图标/静态文件/存活检查是资源；tasks/passkey登录/billing/plans部分占位，Secrets Manager不支持 | 需逐项方法/别名/权限/UI或准确上游边界完整矩阵；本表未完成该逐注册路由验收项 |

完整路由审计已由协调者提供。固定源码缓存：`/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`；原始路由抽取 `routes.txt` 在同一父目录（含未注册声明，不能直接把每行当启用API）。后续须逐模块核对 `routes!` 和 main挂载后补足每条注册路由，而不是把客户端尚缺功能标成上游限制。

本轮测试、隔离容器证据、续做步骤见 [精确交接](vaultwarden-implementation-handoff.md)。
