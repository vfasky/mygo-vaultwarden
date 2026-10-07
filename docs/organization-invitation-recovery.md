# 组织邀请与账号恢复登记

本模块已接原生表单与固定 Vaultwarden 1.37.4 回环；它不是完整的管理员账号恢复产品。完整卡仍 **INCOMPLETE**，群组/策略管理、既有成员恢复登记与退出、管理员改密码/恢复 MFA 等仍需继续实现。

## 产品入口与授权

- 侧栏「创建或加入组织」→粘贴当前服务器邮件链接→「核验邀请策略」。读取当前认证 profile，已 accepted/confirmed 的同一 membership 不再发 accept，提示同步核对确认及恢复登记状态。受邀状态不出现在服务器 profile 中，最终 JWT 与成员状态验证仍由服务器完成。
- 策略不要求恢复时，显示接受确认。要求恢复时，明确告知：组织恢复私钥持有者能恢复此账号并访问个人密码库；用户必须从独立可信渠道取得完整 DER/SPKI 公钥，并点击「同意账号恢复并接受邀请」。不把服务器回传的公钥直接当作用户可信输入。
- `InvitationAcceptance` 的字段私有，绑定 server/account/revision/authorization epoch、organization/membership、token、策略原文数据和组织公钥。提交前重新读 profile、policy 与 public key。任何不同都拒绝旧确认；刷新安全 checkpoint 改变 epoch 后也拒绝旧确认。已执行或未知结果的确认不可再次使用。
- 锁定/取消阻止尚未发送的请求；POST 已发后取消/锁定/服务失败为未知结果，原生表单不能重试。重新进入流程仍先从服务器读取 accepted/confirmed 状态，避免邮件发送等后续步骤失败后重复 accept。服务器没有跨 profile/policy/key 读取与 accept 的 CAS；并发政策修改仍可能导致服务器拒绝或部分成功，须同步核对。
- 原生组织管理→「账号恢复公钥」可读取公钥并通过可信渠道交给受邀人。新建组织现在生成独立 RSA 恢复钥对；旧组织的所有者可确认初始化缺失钥对，已有公钥不轮换、不替换。初始化失败或返回身份/密文不符为未知结果，先重新读取。密钥初始化本身不替成员 enrollment。

## 协议、密钥与传输

固定服务器：`7c188967e7a467b19b2757bc3326f9cf3ccae327`（1.37.4）。固定官方 clients：`5983f56ce0cf924eea56c7d8f066f7885825a7ce`。

| 操作 | 固定路由 | 本应用入口 / 边界 |
|---|---|---|
| 读自身成员状态 | GET `/api/accounts/profile` | 提交前核对账号/email与同 org/membership，已接受不重复 POST；不是完整 profile 管理 |
| 邮件 token 读策略 | GET `/api/organizations/{orgId}/policies/token?token=…` | 当前已认证 client；严格列表/org/type 唯一性与分页检查，识别 type 8 `autoEnrollEnabled` |
| 组织公钥 | GET `/api/organizations/{orgId}/public-key` | 2048–8192 bit RSA、E=65537、严格 Base64 DER/SPKI；缺失/损坏不得包装 user key |
| 缺失钥对初始化 | POST `/api/organizations/{orgId}/keys` | 所有者原生确认；RSA 私钥 PKCS8 由组织64B key type2加密、公钥明文；服务端不允许替换完整已有钥对 |
| 创建组织附恢复钥对 | POST `/api/organizations` 的 `keys` | 与组织新64B key同时生成；已有多步骤失败同步核对规则不变 |
| 接受与自动登记 | POST `/api/organizations/{orgId}/users/{membershipId}/accept` | `token` 与可选 `resetPasswordKey`；后者为 RSA-OAEP-SHA256 type3 包装当前 user key，绝非 org key/master password |
| 查看恢复登记结果 | GET `/api/organizations/{orgId}/users/{membershipId}/reset-password-details` | 本轮仅隔离测试夹具读取，用于验证真正服务保存的密钥链；尚无管理员恢复原生流程 |

依据：服务器 `organizations.rs:927–957,1236–1289,1939–1963,2763–2779,2890–3012`；`auth.rs:128–145,734–737`；`user.rs:283–320`。官方 `apps/web/src/app/auth/organization-invite/accept-organization.service.ts` 中 `prepareAcceptRequest`、`resetPasswordEnrollRequired`、`prepareAcceptAndInitRequest` 明确规定包装 user key 与创建组织钥对。官方源码为固定 commit；GitHub tree 公共API限流后通过 gh-proxy 读取同提交 tree，实际两个 TS 文件 raw 原站成功读取。

`Client.request` 现在将固定相对路由的 query 单独放入 `URL.RawQuery`，保留服务器 base path；拒绝跨 host/绝对 URL、fragment、反斜杠、点路径、编码路径替代和无效 query。现有 HTTPS/loopback、禁止重定向、响应上限与 refresh checkpoint 机制保留。邀请 fragment 使用 `EscapedFragment`，参数只解码一次，防止 `%2B/%26` 被再次解释。错误不打印 token、邮件正文或返回的密钥。

## 可重复验证

```sh
GO_BIN=$(bash scripts/resolve-go.sh)
MYGO_VW_SMTP_TEST=1 "$GO_BIN" test ./internal/vaultwarden -run '^TestLiveSMTPInvitations$' -count=1 -v
```

测试自己构建纯 Go SMTP sink（仅容器回环1025、仅收 example.invalid、不转发），自己创建唯一带标签1.37.4容器，发布唯一 host 回环端口并使用 `/vault-fixture` base path。SIGNUPS_VERIFY=false 只为虚构账号注册，组织邀请仍真正经 SMTP 投递并从 MIME text/plain 解析邮件链接。SMTP spool、临时 Linux binary 与测试 JWT key 副本只在 Go `t.TempDir`（本轮 TMPDIR）内，私密文件0600；测试清理先核对容器 ID+label，再删除该容器与自有卷，随后删除临时目录。

回环覆盖普通与恢复策略两种邀请：invite/reinvite邮件各一封、JWT接受、可信SPKI确认、确认后组织key可用；错误邮箱、本地basepath、重复参数、cancel、伪造签名、有效签名但过期 token、改链接邮箱后服务器拒绝错误身份、accepted 后再次读取拒绝、`UseGroups=false` 角色修改拒绝。过期 JWT 仅用本测试刚创建容器的 RSA 签名钥构造，绝不读取用户服务密钥。

恢复回环经管理员测试HTTP读取真实 `reset-password-details`，验证：当前组织key → 加密组织RSA私钥 → `resetPasswordKey` → 恰好该受邀账号user key。没有执行任何真实账号恢复/密码重置。

单元/故障测试覆盖：未同意/公钥不同零请求、policy/key改变零写、外组织policy拒绝、损坏公钥、revision/epoch改变、checkpoint失败零请求、已消费确认拒绝、503未知结果零重试、POST期间Close取消且不能复活、既有恢复key不覆盖、私钥加密与公私钥匹配、query转义/跨host/basepath防护。headless覆盖邀请入口、准备前无接受按钮、取消与锁定撤销、组织恢复key初始化确认；不等于真实窗口/安装/Keychain/平台MFA测试。

## 剩余边界

- 完整策略业务表单和客户端执行（特别主密码策略检查）尚未实现；本模块只实现接受邀请所需的 reset-password auto-enroll 分支，不能声称所有策略已覆盖。
- 既有成员 `reset-password-enrollment` 登记/退出、管理员恢复密码/双因素、账号user-key轮换及失败恢复仍缺。profile accepted 但登记未完成会阻止重复accept，需后续恢复登记原生流程解决，不能宣称自动修复。
- public key 的可信来源靠用户独立渠道确认；读写间无服务端CAS。公开确认内容不是服务器签名的组织身份凭据。
- 组织RSA初始化的旧组织HTTP成功路径已做mock crypto/权限测试；本轮真实回环覆盖新建组织钥对与恢复登记，不外推旧组织初始化真实验证。
- 本轮没有 Swift 源码改动，没有真实 macOS 窗口/Keychain/AutoFill 安装或线上邮件验证；任何 SMTP 测试均为本地自有夹具。
