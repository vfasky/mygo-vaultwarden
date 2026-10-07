# 组织密钥、权限与原生读写

整卡仍为 **INCOMPLETE**。本阶段提供已有组织的读取、组织项目新增/编辑、个人项目共享和组织 Login 的安全填充投影。组织自身创建/修改/退出/删除、成员/集合/群组/策略管理仍未接产品；集成测试的这些 fixture 操作不能算作产品完成。

## 密钥和身份

固定 Vaultwarden 1.37.4 `user.rs:264–330` 的 `profile.privateKey` 与 `accountKeys.publicKeyEncryptionKeyPair.wrappedPrivateKey` 两种包装均可读取，同时存在必须一致。新版对中的 SPKI 公钥必须与 PKCS8 私钥匹配；仅允许 type-2 包装、无尾随数据的 RSA PKCS8、2048–4096 位且指数65537。成员密钥支持 `3.` RSA-OAEP SHA256 和 `4.` RSA-OAEP SHA1，输出必须64字节，其他编码、签名格式、截断/额外分隔符和错误哈希拒绝。

`Organization.ID` 是组织 ID，`OrganizationUserID` 是成员 ID，`UserID` 必须等于当前全局账号。只从 `profile.organizations` 的 confirmed（status=2）且 enabled 成员解包；accepted-only 的 organizationsNew 不授予密钥；两份列表同时存在时对应身份/密钥/权限 DTO 必须一致。支持明确角色0/1/2/4，不按角色大小推导写权限。组织名称是服务器明文，集合名称由组织密钥解密。

RSA 与组织对称密钥只在一次受 session 锁保护的操作中存在。组织 key byte slice 用毕清除，不持久化独立解密缓存、不塞显示列表；私钥的 D/prime 做尽力清除，Go 大整数、RSA 内部缓存和字符串复制无法保证所有历史内存副本清零。完整原始 sync 仍仅存在 Swift 的认证加密 payload 内。主应用的组织和集合显示元数据只在认证解锁后构建，新增 `displayCredential` 组织/集合/可读属性用 `json:"-"`，不会扩展未认证桥元数据。

## 有效权限和产品操作

读取现有项目以服务器 sync 的显式 `edit` / `viewPassword` 为依据；缺失字段失败关闭。它已包含 full-access 角色/群组，以及每个集合的直接用户权限覆盖群组结果；不把原始群组许可再 OR 进去。目标集合新增/共享同时要求已确认成员、相同组织和明确的 `readOnly=false`、`hidePasswords=false`。所有集合的 readOnly/hidePasswords/manage 字段必须存在；跨组织集合引用拒绝。当前对特殊管理角色允许但 readOnly/hidePasswords 仍为真的目的集合采取保守拒绝，完整管理能力待实现。

| 原生入口 | 方法/路径 | 行为与边界 |
|---|---|---|
| 侧栏组织/集合；「我的密码库」独立个人过滤 | GET `/api/sync` 本地解析 | 认证后组织/集合/条目列表；viewPassword=false显示受保护占位，不解密秘密；只读成员可查看非秘密标准字段，Login密码/TOTP走认证显示复制 |
| 集合→新增→八类型选择 | POST `/api/ciphers/create`，`/admin`别名未调用 | 默认Login，可切换1–8类型；新随机独立item key由目标org key包装；目标集合明确，不支持隐式无集合组织创建；组织真实回环目前验证Login |
| 组织项目→查看与编辑→保存 | PUT `/api/ciphers/{id}` | 复用无损标准字段编辑、密码历史和URI checksum；保留item key、unknown、FIDO2，原样server revision/encryptedFor；需要edit/viewPassword；reprompt使用单项目30秒授权 |
| 个人项目→共享到组织/集合→确认 | PUT `/api/ciphers/{id}/share`，POST别名未调用 | 当前草稿先按原item key加密，再仅把独立item key包装给org key；目标组织/集合显式确认；不保留个人副本；同key的附件包装key、FIDO2及未知扩展保持；不上传/下载附件 |
| 登录项目显示/复制密码或TOTP | 本地 `WithOrganizationSecret` +现有Swift认证桥 | 与个人相同scope/revision、短期限和剪贴板门控；只读且viewPassword=true可以使用；隐藏密码不能绕过授权；主密码验证不取消reprompt属性 |
| 同步后系统候选 | 最小 Login 投影 | 只有确认启用且viewPassword=true、未删除/归档、reprompt=0的组织Login进入原有认证payload；不含org key/集合/成员对象。删除/撤销后的成功sync显式替换，Swift原有CAS/index撤销流程保持 |

共享时没有独立item key的legacy项目明确拒绝；不能把user key包给组织，也没有假称只改organizationId就完成共享。同key下未知/附件/FIDO2的保持已有httptest；真实服务器共享只测标准Login。跨key的完整legacy重加密及附件/FIDO2处理、组织copy/import/export、组织状态操作/批量管理、隐藏密码模式的有限详情展示仍未完成。

## 锁定、同步与离线

组织写入与个人写入共用请求取消、refresh checkpoint先持久化和写入未知结果门控。share/create路由非整体事务，任何非200响应都要求同步核对，不允许盲重试。组织更新保留server revision冲突错误，但尚未提供组织字段比较重基。组织草稿在成功全量同步时清除（包含组织reprompt输入和共享草稿），避免保留已撤销组织明文；用户需要重新打开当前版本。新snapshot revision撤销旧grant并尽力清除应用拥有的秘密剪贴板。锁定清组织/集合/编辑器；正在写入的私有草稿等待取消完成后释放，迟到结果不能恢复UI。

**离线不能知道服务器刚发生的成员或集合撤销。** 离线读取与填充只受最后一次认证快照、scope/revision/lease及本地锁定约束；成功新sync才反映服务器撤销。本阶段没有通知连接、远端实时撤销证明，也没有宣称网络失败可以推断权限仍然有效。

## 证据

- `organizations_test.go`、`organization_vectors_test.go`：两种OAEP、兼容字段、身份错配、disabled/accepted/revoked、只读/隐藏/reprompt、缺集合权限字段、跨组织、checkpoint失败、取消和Close取消在途写入、真实主密码派生的组织grant与旧revision拒绝、秘密借用及隐藏密码TOTP/密码拒绝。
- `organization_share_test.go`：独立key重新包装，附件key/filename、FIDO2、opaque大整数保持，跨组织目标拒绝，legacy账号key拒绝，目的集合只读/隐藏拒绝、非事务错误结果未知。
- OpenSSL固定向量：`testdata/organization-rsa.json`是本轮生成并公开提交的**测试专用**2048位RSA私钥；明文为字节0…63。用 `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`、`openssl pkcs8 -topk8 -nocrypt -outform DER`，然后 `openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256`（另一次两处sha1）生成固定密文。不是用户密钥或生产凭据。
- `organization_ui_test.go`：headless组织/集合过滤、新建类型选择、编辑、只读、隐藏密码、reprompt入口、共享选择确认/取消、锁定与成功sync清组织草稿/导航。
- 隔离1.37.4：真实owner创建fixture组织→解密集合→新增Login→修改密码含history→个人Login共享→sync；成员注册/邀请accepted拒绝→确认→编辑；只读/隐藏的直接用户权限优先同集合可写group；删除直接分配后group生效；多集合AND有效权限；集合访问收回与成员revoke撤回投影；owner设置reprompt→投影排除→主密码授权后再编辑。
- 本轮Go全量test/build/vet/race通过，Swift50测试与bridge typecheck通过。没有官方客户端/CLI组织互操作、真实窗口视觉、签名安装、Keychain/Touch ID、系统AutoFill、SMTP/邮件接受流程验证；fixture使用无SMTP时上游自动accepted的既有账号流程。具体命令、时间和容器清理见交接。
