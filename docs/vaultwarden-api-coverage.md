# Vaultwarden API 覆盖矩阵

**INCOMPLETE：整卡未完成，未达到验收。** 本轮新增集合CRUD、成员/群组集合访问配置，复用组织创建/资料修改/退出/删除及持久隔离恢复；已有组织密钥/权限、读写共享与安全Login投影继续保留，见 [组织密码库](organization-vault.md)；个人冲突比较与显式重新应用见 [冲突处理](cipher-conflicts.md)；既有 reprompt 短授权、密码/TOTP短时显示和受控复制见 [敏感操作](sensitive-operations.md)。禁止据此启动 Review 或合并。

固定服务器 **Vaultwarden 1.37.4**：tag 对象 `54a40806c990da2def7acd5a3152edc530c59b79`，commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`，归档 SHA256 `d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7`。字段加密参考 Bitwarden clients `web-v2026.5.0` commit `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 的 `libs/common/src/vault/models/domain/{bank-account,drivers-license,passport,login-uri}.ts`。本轮从固定 commit 的 raw URL 成功读取这四份文件，未换用 main。

## 已连接的个人功能

以下 `/api` 前缀来自 main.rs 的挂载。别名列明服务器支持，不代表客户端逐个执行过。单条状态操作必须先在当前认证快照中打开可编辑的个人项目，写入前检查本地 revision，成功后全量同步并用原会话的 CAS 发布。

| 能力 | 方法 / 路径及别名 | Go 实现 / 测试 | 原生入口、权限与实际边界 |
|---|---|---|---|
| 全量同步 | GET `/api/sync`；query `excludeDomains` 尚未开放 | `SyncWithCheckpoint`、`VaultData`；sync/session 测试及真实回环 | 顶栏「同步」。保留服务器原始加密响应及未知区段；个人八类型与已有组织条目/集合列表，最小 Login 填充分离；组织密钥与权限校验后才解密，未确认/禁用成员不给密钥 |
| 新增 | POST `/api/ciphers`；`/create`、`/admin` 未实现 | `CreatePersonalCipher`、`NewPersonalCipher`；八类型独立随机 item key 测试和真实回环 | 在八种分类选择「新增」；默认所有项目新增 Login。type-2 字段加密，item key 由用户 key 包装；未知 section/custom/URI 扩展拒绝跨新 key 写入；SSH 三项不能为空 |
| 更新 | PUT `/api/ciphers/{id}`；POST 同路径 / admin 别名未调用 | `UpdatePersonalCipher`、`EncryptCipherDocument`；八类型、未知扩展、大整数、自定义字段、历史和 URI checksum 测试 | 「查看与编辑」→「保存」。保留同 item key/FIDO2/未知扩展；必须个人、edit/viewPassword、reprompt=0或有效项目短授权、源 revision 合法。支持名称/备注/类型标准字符串、多 URI、TOTP 秘钥、文本/隐藏/布尔/关联自定义字段；关联目标按类型限定，未知关联ID/扩展与null值保留。reprompt主密码验证后30秒项目能力已接入，刷新checkpoint/锁定/变更revision撤销 |
| 收藏 / 文件夹 metadata | PUT `/api/ciphers/{id}/partial`，POST 别名 | `setCipherPersonalMetadataUnchecked`（内部transport，仅路由测试），最小请求体 httptest | 收藏已接入完整编辑保存；partial 接口尚未直接接 UI，文件夹列表/管理及编辑器文件夹选择已接入 |
| 软删除 | PUT `/api/ciphers/{id}/delete` | `ChangePersonalCipherStateAuthorized(CipherTrash)`；方法断言、真实回环 | 编辑页「移入回收站」→确认；不使用 POST 同路径 |
| 恢复 | PUT `/api/ciphers/{id}/restore` | `CipherRestore`；真实回环 | 回收站打开项目→恢复 |
| 永久删除 | DELETE `/api/ciphers/{id}`；POST `/api/ciphers/{id}/delete` 为永久删除别名 | `CipherDeletePermanently`；仅 DELETE 已测试 | 回收站打开项目→永久删除→不可恢复提示→确认；顶栏清空回收站只选deleted再确认批量删除 |
| 归档 / 取消 | PUT `/api/ciphers/{id}/archive`、`/unarchive` | `CipherArchive/CipherUnarchive`；真实回环，归档排除 AutoFill | 编辑页归档按钮；侧栏归档分类；完整 PUT 保留原 `archivedDate` |
| 分类 | 本地过滤认证后的完整库元数据 | `PersonalEntries`、`filteredItems`；headless 测试 | 八类型、收藏、归档、回收站；未知格式显示受保护占位；reprompt占位可进入主密码再次验证表单；不是虚假的空分类 |
| 密码历史 / URI 完整性 | 更新体的 passwordHistory、passwordRevisionDate、uriChecksum | 自动保留旧密码，URI SHA256 Base64 再 type-2 加密；单元与真实回环 | 改密码/网址时维护；历史显式显示/隐藏与确认清除已接入（保存时提交；同时改密码仍记录刚替换的旧密码）。URI默认及0–5策略可编辑，未知策略保留；起始/正则匹配当前仅保存，不进入AutoFill |
| 完整离线数据 | 本地 `VaultData{version:1,scope,sync:base64}` | Go Documents 校验、Swift `SnapshotPayload.vault`、bridge、迁移与 checkpoint 测试 | 完整原始 sync 仅放 AES-GCM payload；认证主应用解锁才返回；状态/AutoFill lease不返回。旧 payload 无 vault 时可解锁，下次成功同步迁移 |

实际 Cipher 类型是 1 Login、2 SecureNote、3 Card、4 Identity、5 SSHKey、6 BankAccount、7 DriversLicense、8 Passport。逐字段加密名单来自固定客户端源码，未递归加密所有字符串。`encryptedFor` 是当前稳定账号 UUID。源 `lastKnownRevisionDate` 原样提交；服务端检查整秒差值 `num_seconds() > 1`（不足两秒可能接受旧稿），HTTP400精确固定消息已映射为ErrConflict，并非严格 CAS。当前不轮换用户 key；源中的 `encryptedByKeyId` 若存在原样保留，尚无完整 keyId 生命周期/轮换流程。

## 安全边界及验证

| 边界 | 实际实现及证据 | 仍需完成 |
|---|---|---|
| 请求约束 | TLS/loopback、禁重定向、请求超时、32 MiB响应限制、ID过滤、脱敏错误；既有测试 | query/multipart/binary独立传输、Retry-After未完成 |
| 刷新持久化 | pending checkpoint失败阻断请求；Swift同scope/revision保存session并保留完整vault；相关Go/Swift测试 | 所有未来模块必须复用门控 |
| 写入未知结果 | 传输错误、意外成功状态、5xx、成功响应不可解码/身份错误、写后取消均按未知结果；不自动重试；UI禁重复保存并保留草稿 | 同步后逐字段比较本地/远端改动并显式选择重新应用或采用远端已接UI，原始最新文档保留unknown；历史只删除已观察条目；reprompt新grant、锁定和版本隔离测试及真实回环通过。双改URI/custom无稳定行ID，逐行对应选择仍缺，目前明确保留远端后手动编辑；详见 [冲突处理](cipher-conflicts.md) |
| 锁定与撤销 | `stopNetwork`推进epoch并取消会话，清除vault/editor/list；迟到回调不能复活并释放私有草稿；headless及race | Go/Swift运行时无法证明清零所有字符串历史副本；真实系统安装/视觉未验证 |
| 填充投影 | 个人及获授权组织Login；deleted、archived、reprompt、viewPassword=false排除；组织成员confirmed+enabled、有效cipher权限门控；零条显式替换；组织真实成员/集合撤销回环及Swift撤销测试 | 等价域名、更多URI规则仍缺；离线无法发现服务器新撤销，成功sync才替换；真实签名AutoFill未验证 |
| 未知字段 | 同key更新保留opaque passkey/扩展/大整数；加密输入不修改编辑草稿；未知格式失败 | 标准个人copy已实现新key完整转换；个人copy的附件/FIDO2/未知扩展仍拒绝；组织share已支持独立item key重包装、同key保持附件包装/FIDO2/unknown，legacy无item key共享及用户key轮换未实现 |
| 桥和快照大小 | vault不混入64 KiB session；沿用4 MiB C ABI上限，超限报错、保旧快照 | 完整大库有界传输尚未扩展；附件禁止通过JSON/此桥传输 |
| 认证前元数据 | header仅控制元数据；完整库不在displayCredential/status/session日志；Swift认证lease才返回vault；原生开表单后才解密秘密 | 个人与组织Login密码/TOTP短时显示复制、reprompt读取/更新已接入；个人单项状态/有限完整copy已实现；reprompt批量/导出与完整组织策略管理仍缺 |

## 其余模块与新增覆盖（全部保留，不缩减范围）

| 模块 | 1.37.4 审计事实与边界 | 当前实现 / UI / 验证 |
|---|---|---|
| folders CRUD | POST `/api/folders`、PUT `/api/folders/{id}`、DELETE `/api/folders/{id}`；POST 更新及 `/delete` 为服务器别名，客户端未调用；GET 列表/单条由完整 sync 本地读取替代 | `SaveFolder/DeleteFolder/PersonalFolders`；type-2 名称加密、scope、错误未知结果、离线读取测试与真实 1.37.4 回环；侧栏新建/管理/筛选；编辑器文件夹选择；删除明确提示只解除项目归属；草稿绑定本地revision、锁定清除。服务器没有文件夹CAS |
| 个人批量管理 | PUT `/api/ciphers/move`（POST 别名）、`/delete`（软删）、`/restore`、`/archive`、`/unarchive`；DELETE `/api/ciphers`（POST `/delete` 为永久删除别名） | `ChangePersonalCiphers`；验证选中ID属个人快照，reprompt或viewPassword=false在整批请求前拒绝（需单项验证后操作），永久删除仅允许deleted；httptest方法断言、真实批量及400部分移动回环；顶栏批量管理→选择项目/操作→确认；回收站清空只选择deleted，绝不purge。任意批量错误后同步逐项展示当前目标状态，不重试、不宣称原子成功；锁定清除 |
| copy / import-export | 个人无 `/export` 或 `/trash`；purge是清全库 | `CopyPersonalCipher`经POST `/api/ciphers`新建，八类型标准字段、历史、custom、URI/checksum及legacy `login.uri`以新随机item key完整重加密；编辑页「复制为新项目」→说明当前草稿/清除归档回收状态→确认。源不改，绑定scope/revision/checkpoint；结果未知不重复创建，成功全量同步。httptest/headless/真实1.37.4八类回环通过。附件/FIDO2/未知扩展及非空encryptedByKeyId在请求前拒绝，完整复制仍未完成；个人明文文件导入导出已接入，详见下表；组织import-export、附件/FIDO2/未知扩展完整备份仍未实现。 |
| 个人文件导入 / 导出 | 无独立export端点；导入用 POST `/api/folders`、POST `/api/ciphers`，回收站项再 PUT `/api/ciphers/{id}/delete`；不调用purge或盲重试 | `backup.go/backup_import.go`、`backup_editor.go`、`backup_file_unix.go`；顶栏「导入导出」→格式与范围→敏感确认/预览→原生Open/Save。兼容JSON覆盖固定官方1–7类；MyGo格式1–8类，标准秘密、四类custom、多URI、全部history、全部个人folders含空文件夹；未知schema/附件/FIDO2/reprompt导出拒绝。导入先完整预检/新key加密后逐项创建、新folder ID映射、部分失败停止、已知ID同步核对。文件最大32MiB/10,000项目，0600临时文件、逐目录拒绝符号链接、原子不覆盖发布；epoch/scope/revision/取消门控。八类单元/真实1.37.4往返，官方CLI2026.5.0七类导入解密+官方导出再回导通过；未实际验证原生Dialog视觉。 |
| 组织 / collections / members / groups / policies / events / recovery | RSA SPKI/PKCS8、OAEP type3/4；权限涉及角色、群组、readOnly/hidePasswords/manage/accessAll；memberId不等于userId | RSA PKCS8/SPKI/type3+4解包、明确orgID/memberID/globalUserID、confirmed+enabled门控；已有组织/集合原生导航、只读查看/受权编辑、新建、独立item key共享、reprompt与最小AutoFill投影已接入，详见下表。组织创建/资料/退出/删除已接API与原生侧栏，危险请求前持久隔离；集合CRUD及成员/群组集合访问配置已接API与原生组织管理。成员生命周期、groups自身/policies/events/recovery管理及UI仍未实现，fixture请求不算这些产品完成 |
| 附件 | `attachment/v2`元数据后multipart `data`；二进制 `0x02||IV16||HMAC32||CBC`；root `/attachments/...`或预签名URL | 未实现；需外部URL禁Bearer、大小/MAC、两阶段补偿和安全临时文件 |
| Send | seed16、HKDF-SHA256 salt `bitwarden-send`/info `send`；访问走grant `send_access` 后 `/api/sends/access`、`/access/file/{fileId}`；无旧 `/access/{id}` | 未实现。文件/文本所有者及接收UI均缺；emails验证型Send上游不支持 |
| 账号 / keys / KDF / registration | 新注册在 `/identity/accounts/register/send-verification-email` 与 `/finish`；rotate-user-account-keys为非整体事务完整DTO | 仅测试fixture注册，不是产品注册；profile/邮箱/主密码/KDF/轮换/删除/清库/security stamp未实现 |
| MFA / SSO / WebAuthn | provider0 TOTP、1 Email、2 Duo、3 YubiKey、7 WebAuthn；5 remember；8恢复码会删除MFA。`/api/webauthn`空列表不是MFA WebAuthn | 登录password/TOTP/refresh已有且真实回环；其他provider管理、浏览器交互、SSO/PKCE/解密尚缺 |
| devices / auth requests / domains / emergency | 有正式上游端点，不能视作不支持 | 未实现产品功能 |
| notifications | `/notifications/hub` SignalR MessagePack；匿名事件拼写 `AuthRequestResponseRecieved`；断线需全同步 | 未实现 |
| events / Public API | collect挂root `/events/collect`；Public API仅POST `/api/public/organization/import` | 未实现 |
| admin / 部署资源 | `/admin`是独立HTML运维cookie；图标/静态文件/存活检查是资源；tasks/passkey登录/billing/plans部分占位，Secrets Manager不支持 | 需逐项方法/别名/权限/UI或准确上游边界完整矩阵；本表未完成该逐注册路由验收项 |

## 本轮组织路径

| 能力 | 方法 / 路径 / 别名 | 实现、权限、UI、验证 |
|---|---|---|
| 密钥/组织/集合/项目读取 | GET `/api/sync`，本地VaultData | `Organizations/OrganizationEntries/ReadOrganizationCipher`；PKCS8/type3+4、confirmed+enabled、全局账号与成员ID区分；组织名称明文、集合名org key；侧栏组织/集合，个人库独立过滤。OpenSSL固定向量、畸形/兼容字段、身份错配、headless和真实owner/member回环 |
| 组织项目创建 | POST `/api/ciphers/create`；`/api/ciphers/admin`别名未调用 | `CreateOrganizationCipher`；目标集合readOnly=false且hidePasswords=false；独立item key；集合→新增→八类型选择。真实组织Login、headless类型选择；组织其余七类未单独做真实回环 |
| 组织项目编辑 | PUT `/api/ciphers/{id}`；POST/admin别名未调用 | `UpdateOrganizationCipher`；snapshot原文比对、有效edit/viewPassword、reprompt短grant、scope/revision/checkpoint；原生保存后sync。unknown保持、checkpoint失败、取消/Close在途写入、真实owner/member/password history/reprompt |
| 个人项目共享 | PUT `/api/ciphers/{id}/share`；POST同路径未调用；批量 `/ciphers/share` 未实现 | `SharePersonalCipher`；原生目标选择→确认；独立item key重包装、同key附件key/FIDO2/opaque保留；无item-key legacy拒绝。非200视结果未知，因为上游非整体事务。httptest大整数/扩展/跨组织、真实标准Login共享 |
| 组织授权秘密与填充 | 本地API/已有Swift桥 | `AuthorizeOrganizationItem/WithOrganizationSecret/appendOrganizationCredentialsLocked`；原生密码/TOTP短时显示复制；授权Login最小投影，隐藏/删除/归档/reprompt排除。成功sync撤回组织草稿/grant/候选；离线无法发现远端新撤销。真实成员只读/隐藏、直接用户优先group、多集合AND、撤集合/revoke投影及Swift撤销回归 |
| 组织创建与资料 | POST `/api/organizations`；GET/PUT `/api/organizations/{orgId}` | `SaveOrganization/OrganizationProfile`；侧栏创建组织、组织导航→管理当前组织。随机64B org key，由当前有效账号RSA包装；默认集合名type2加密，组织名/账单邮箱明文。owner-only资料；服务端组织创建策略仍强制执行；400等非事务错误不重试。httptest/headless/隔离1.37.4真实创建与修改通过；组织RSA恢复key对尚未生成，`keys`可选省略 |
| 退出与删除组织 | POST `/api/organizations/{orgId}/leave`；DELETE `/api/organizations/{orgId}` | `LeaveOrganization/DeleteOrganization`；退出确认/owner主密码删除确认；固定KDF生成masterPasswordHash，服务器最终验证/最后owner检查。调用者必须先持久隔离，失败不发请求。真实最后owner拒绝、普通成员退出、owner删除通过。无邮件OTP替代验证产品流程 |
| 本机组织隔离/恢复 | Swift `quarantineOrganization` / `restoreOrganizationAccess`；恢复前GET `/api/sync` | `VaultData.quarantinedOrganizations`在认证payload内，scope+org隔离；不改原始加密sync字节，Go排除组织keys/集合/文档，Swift剔除对应Login投影。危险请求前原子写入并推进revision与candidate ID；旧lease失效；个人/其他组织/session保留。普通sync/checkpoint不能移除标记。侧栏重新核验→显式确认→新同步验证confirmed/enabled/用户与member身份/RSA钥链后单独恢复；恢复不重试原写。Swift独立store重开/AutoFill读取模式/旧lease、Go取消/Close/磁盘失败门控/headless通过；没有真实系统扩展安装验证 |
| 集合CRUD | POST `/api/organizations/{orgId}/collections`；GET `/api/organizations/{orgId}/collections/{collectionId}/details`；PUT/DELETE 同集合路径 | `CollectionDetails/SaveCollection/DeleteCollection`；组织管理→集合新增/更名/删除确认。名称用org key加密，完整详情草稿绑定scope/revision；users/groups/externalId/opaque按原样保留，更新前新GET检测变更（无严格CAS）。owner/admin和符合上游permissions的经理创建，集合manage门控；删除前持久隔离，失败零HTTP。单元/headless/真实owner与全组织经理CRUD、集合级经理更名与创建拒绝、普通成员拒绝已验证。批量delete与bulk-access未实现 |
| 集合成员/群组访问 | GET `/api/organizations/{orgId}/users/mini-details`、`/groups`；保存使用PUT集合路径 | `CollectionAccessDetails`及绑定目录的CollectionAccess草稿；原生姓名/邮箱/群组名称选择、只读/隐藏/管理控件和确认。membershipID/globalUserID核验、feature开关、未修改或未列出条目/未知字段保留；改已有访问前持久隔离整个目标组织（个人/其他组织保留），之后必须侧栏显式重新核验恢复。单元配置/失败/身份回归；真实mini目录及直接成员限制优先group、取消直接分配后group回退与AutoFill已走产品接口。fixture isolate为no-op，实际持久层另由Swift替身测试 |
| 其余组织管理路由 | GET `/api/organizations/{orgId}/users`；POST `/users/invite`、`/users/{memberId}/confirm`；PUT `/users/{memberId}`、`/users/{memberId}/revoke`、`/users/{memberId}/restore`；POST `/groups`（组织路径均挂`/api`） | **仍仅集成fixture调用，不是产品功能**。成员生命周期、groups自身/policies管理UI/API待实现；无SMTP时上游自动接受既有用户，未验证邮件邀请接受 |

组织只读详情目前提供非秘密标准字段及Login密码/TOTP认证操作，隐藏密码占位未提供更细只读详情；组织项目状态/批量/copy/export、冲突字段重基、legacy共享和完整组织策略管理仍缺。新sync清组织草稿，不把个人冲突保稿规则扩大到已撤销组织。详见 [组织实现与边界](organization-vault.md)。

完整路由审计已由协调者提供。固定源码缓存：`/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`；原始路由抽取 `routes.txt` 在同一父目录（含未注册声明，不能直接把每行当启用API）。后续须逐模块核对 `routes!` 和 main挂载后补足每条注册路由，而不是把客户端尚缺功能标成上游限制。

本轮测试、隔离容器证据、续做步骤见 [精确交接](vaultwarden-implementation-handoff.md)。
