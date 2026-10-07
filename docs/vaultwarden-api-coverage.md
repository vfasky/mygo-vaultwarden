# Vaultwarden API 覆盖矩阵

**阶段成果，整卡未完成，未达到验收。** 当前原生产品仍以登录、解锁和只读同步为主；新写入接口尚未接入原生界面或完整快照模型。此矩阵禁止用于宣称“完整 Vaultwarden API 已完成”。

兼容目标固定为 **Vaultwarden 1.37.4**。已直接核对该标签的 [`src/api/core/ciphers.rs`](https://github.com/dani-garcia/vaultwarden/blob/1.37.4/src/api/core/ciphers.rs)，首次 raw 直连超时后依照内置 github-mirror-fallback 技能取得同一资源。其余模块逐路由审计尚待并行审计结果。标签源码缓存位置、后续步骤见 [实现交接](vaultwarden-implementation-handoff.md)。不能将 HTTP 方法相近的路由视为同义词，特别是删除。

## 当前已核对的协议和实现

路径前缀 `/api` 由客户端添加。以下为能力入口，不声称已测试每一个上游别名。

| 功能 | 1.37.4 方法与路径 | 上游源码 | 本地实现 / 测试 | 权限、界面和真实状态 |
|---|---|---|---|---|
| 全量同步 | GET `/api/sync`，可选 query `excludeDomains` | ciphers.rs:121 | client.go `SyncWithCheckpoint`；既有 sync/client/session 测试 | 仅既有个人 Login 投影进入 UI；query 尚未支持；组织、其他类型及完整 metadata 尚未集成 |
| 项目更新 | PUT `/api/ciphers/{id}`；POST 同路径别名；另有 admin 别名 | ciphers.rs:682–715 | ciphers_api.go `UpdatePersonalCipher`；`TestUpdateCipherEncryptedAndRevisionBound` | 仅个人五类的有限字段编辑；要求源文档 edit/viewPassword、无 reprompt、有效 revision；未接入 UI；仅测试 PUT |
| 收藏 / 文件夹 | PUT `/api/ciphers/{id}/partial`，POST 别名 | ciphers.rs:743–754 | `SetCipherPersonalMetadata`；`TestCipherPartialDoesNotOverwriteEncryptedFields` | 用户自己的 metadata，服务端校验可访问性；客户端仅测试 PUT；未接 UI |
| 软删除 | PUT `/api/ciphers/{id}/delete`，另有 admin / bulk 变体 | ciphers.rs:1511 | `ChangeCipherState(CipherTrash)`；`TestCipherStateRouteMethodsAndScope` | 服务端校验；尚需 UI 确认、reprompt 与本地权限集成 |
| 永久删除 | DELETE `/api/ciphers/{id}`；POST `/api/ciphers/{id}/delete` 为永久删除别名 | ciphers.rs:1499、1523 | `ChangeCipherState(CipherDeletePermanently)`；同上 | 只实现 DELETE；危险操作 UI 确认未接入 |
| 恢复 | PUT `/api/ciphers/{id}/restore`，另有 admin / bulk | ciphers.rs:1601 | `ChangeCipherState(CipherRestore)`；同上 | 未接 UI / 全量同步模型 |
| 归档 / 取消 | PUT `/api/ciphers/{id}/archive`、`/unarchive`；另有 bulk | ciphers.rs:1778、1793 | `ChangeCipherState(CipherArchive/CipherUnarchive)`；同上 | 未接 UI / 快照 / AutoFill 排除规则 |
| 五类加密文档 | CipherData type 1 Login / 2 SecureNote / 3 Card / 4 Identity / 5 SSHKey | ciphers.rs:240–298、type match 549 起 | cipher_document.go；`TestCipherDocumentFiveTypesPreserveExtensions`、`TestCipherDocumentRejectsUnsafeChanges` | 支持标准字段 type-2 解密与有限重写，未知 JSON 扩展原样保留；不是完整 CRUD |
| 新增 / 复制 / 分享 | POST `/api/ciphers`、`/create`、`/admin`；PUT/POST `/{id}/share` | ciphers.rs:338–384、988–1021 | 未实现 | 必须生成/包装新 key，重加密未知扩展前明确检查；禁止复用有限编辑接口冒充复制 |
| 批量 / collections / import / purge | 详见上游 routes 注册列表 | ciphers.rs:34–104 | 未实现 | 待逐项核对请求、响应、权限和 UI |
| 附件 | GET 获取；POST attachment/v2 JSON 元数据 + multipart 数据；legacy/admin/share/delete 变体 | ciphers.rs:1167–1488 | 未实现 | 需加密二进制、下载 URL 边界、临时文件与取消清理 |

`CipherData` 在该版本还接受 type **6 BankAccount、7 DriversLicense、8 Passport**。本次五类模型明确拒绝这些类型，不能称上游不支持；字段/加密协议与 UI 尚待核对。服务端本身以 `lastKnownRevisionDate` 检查旧数据，但当前上游用常规错误路径报告陈旧 revision，不能假定必为 HTTP 409；客户端已经区分真实 409/412，400 仍为脱敏验证错误。

## 安全基础状态

| 项目 | 当前证据 | 剩余工作 |
|---|---|---|
| HTTPS / loopback、无重定向、响应上限、超时 | 既有 Client 边界与测试保留 | query / multipart / binary 的统一有界接口未完成 |
| token 刷新先持久化 | authenticated.go；pending 无 callback 拒绝；已绑定持久 session 在无 callback 时禁止刷新；session_state 及 authenticated 测试 | 确保所有新增 API 复用同一门控；初次未绑定登录同步仍允许原有内存流程 |
| 错误脱敏与分类 | 400/422 validation、401 expired、403 permission、404、409/412 conflict、429、5xx network；响应正文不回传 | 账号/MFA/公共 API 需各自安全业务错误建模 |
| 未知写入结果 | 所有非 GET/HEAD 传输错误返回 MutationUncertainError；无自动重试；401 写入只发一次 | UI 必须同步核对并禁止自动重发；成功状态后响应损坏也需统一处理 |
| 锁定/取消 | Session.Close 先取消当前请求再等 mutex；取消响应体读取返回 ErrCancelled；race 通过 | 新表单/下载/授权随 app epoch 与快照 lease 清理尚未实现 |
| type-2 加密 | 随机 IV、AES256-CBC/HMAC、明文上限、篡改与错 key 测试 | 组织 RSA / 新格式 / 文件格式 / Send KDF 未完成 |
| 未知字段 | 文档保留原始未知字段；JSON Number 避免大整数舍入；同 key 更新；passkey opaque 保留测试 | 密码/URI/历史/自定义字段编辑当前明确拒绝，后续需要无损完整编辑；其他加密格式明确失败 |

## 完整范围待办（不得删减）

| 模块类别 | 需要完成的能力 | 当前状态 |
|---|---|---|
| 客户端密码库 API | 全类型新增/编辑/复制；密码历史、URI checksum、自定义字段、TOTP；bulk move/delete/restore；folders；trash purge；archive；import/export | 部分协议基础，产品未完成 |
| 组织和管理员 API | RSA 私钥/组织 key；组织、collections、共享、成员/邀请/确认/角色；groups/policies/events/目录；权限映射 | 未实现；需并行协议审计 |
| Send | 文本/文件 create/read/edit/delete，访问、密码、过期、次数；正式 E2EE 和文件流程 | 未实现 |
| 账号与安全 API | profile/register/verify/keys/email/password/KDF/delete/purge；devices/sessions/auth requests；domains；emergency；MFA 与浏览器/平台认证 | 登录/TOTP/refresh 是基线成果，其余未实现 |
| 公共/身份 API | 身份登录 provider、必要公共流程与错误语义 | 仅基线 password/TOTP/prelogin/refresh；其他待审计实现 |
| 通知与同步 | 通知状态、断线全量同步、背景任务账号/锁定隔离 | 仅基线手动同步/epoch 边界 |
| 原生 UI | 完整分类、folder/org/collection/favorite/archive/trash；编辑/详情/复制密码和 TOTP；附件/Send/账号/组织；确认/取消 | 保留基线三栏/登录/解锁布局；新入口未实现 |
| Go–Swift 离线 | 完整 encrypted vault 文档与 metadata、迁移、lease/revision/撤销；仅合规 Login AutoFill 投影 | 仍为基线 Login 快照，新模型尚未桥接 |
| 服务器 HTML 管理 / 运维 | `/admin` 等服务器管理流程与客户端范围区分 | 路由及理由待审计；不擅自冒充客户端 API |
| 上游不支持的服务 | 按 1.37.4 实际注册与实现明确标记 | 尚未取得完整审计，不猜测名单 |
| 验证 | fixture/httptest、恶意输入、权限、冲突、取消、Swift、临时 loopback 真服务、原生视觉 | 本阶段本地测试通过；真服务、安装和视觉验证未做 |
