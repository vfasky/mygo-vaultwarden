# 组织密钥、权限与原生读写

整卡仍为 **INCOMPLETE**。本阶段提供已有组织的读取、组织项目新增/编辑、个人项目共享和组织 Login 的安全填充投影。组织自身创建/资料修改/退出/删除及集合CRUD、成员/群组集合访问配置现已接原生产品；成员单人生命周期与角色、邀请链接表单已接产品，SMTP真实接受/恢复自动enrollment尚缺；群组自身/策略管理仍未接产品，其集成fixture不能算作完成。生命周期和本机隔离详见下节。

## 成员流程与角色变更（第十一轮）

组织管理→成员：单邮箱邀请、重新邀请、撤销/恢复/移除与角色编辑；侧栏「创建或加入组织」提供邮件邀请链接接受确认及自身共享公钥。成员公钥确认要求通过独立可信渠道取得完整Base64 DER/SPKI，精确比较后再次GET成员及global user公钥，仅把org key用该RSA公钥包装。未实现官方词组指纹；自身公钥从本机认证私钥推导。邀请链接仅接受当前server/base path/email并拒绝重复参数，不跟随任意外部URL，服务端JWT签名验证仍是权威。自动加入账号恢复的邀请尚未实现，不向管理员自动分享user key。

`member_management.go`的私有目录绑定scope/revision并核对本账号membership/global账号映射；单人写入避免上游批量多邮箱部分执行的隐式重试。移除自己、修改自己角色先持久隔离，普通sync不能取消。最后owner由服务器实时守卫；角色/成员写入未知结果只能同步核对，不能重复提交。其他成员关系冲突保留草稿，自身已隔离时优先清理失效权限下的管理表单。

`member_roles.go`从真实直接collection/users与group/users构建角色草稿，不能从会省略集合的member详情或有效权限推断直接分配。UseGroups=false时上游隐藏历史群组，但角色PUT仍删除重建GroupUser，因此零写入阻断，解释需管理员启用群组后重新加载；不提供丢弃隐藏关联绕过。普通/集合级经理切换保留直接分配及groups/opaque。固定1.37.4角色PUT对access_all目标会删除直接集合分配且不重建：owner/admin/全集合经理晋升前，界面列明可读集合名/权限、全组织访问和降级不自动恢复，必须私有草稿绑定consent显式确认。提交前重新读全部关系，角色/身份/关系改变使旧确认失效；仍无服务端CAS，存在GET→PUT竞态，不声称绝对无损或事务。

协议/密码/故障/headless测试及隔离1.37.4验证边界逐项见[覆盖矩阵](vaultwarden-api-coverage.md)。真实无SMTP邀请/确认/角色清直接关系且保留groups/降级/撤销恢复/重新邀请移除与最后owner拒绝已验；邮件真实token接受、SMTP、恢复enrollment、实际Keychain/安装/窗口/系统扩展未验。

## 集合CRUD与访问配置（第十轮）

组织导航→「管理当前组织」→集合管理，可新建、读取、更名、删除集合，或「配置成员与群组访问」后按姓名/邮箱、群组名称分配访问。只读、隐藏密码和管理权通过业务控件编辑，管理权不能与只读/隐藏并选。配置保存须再次确认。锁定/同步/隔离会关闭并清理表单；后台请求使用独立副本，迟到结果不能重开表单。

`collections.go` 的 `CollectionDraft` 绑定scope/revision/组织/集合。`CollectionDetails`调用完整details而非sync投影；`SaveCollection`保留完整users/groups/externalId、未知顶层和未修改访问条目的未知字段（含大整数）。仅名称用组织key加密，目录姓名/邮箱和权限是上游明文管理元数据。修改前GET核对原详情，有差异返回冲突、保留当前表单供核对；**服务器没有集合CAS，GET与PUT间仍有竞争窗口**。数组重排按冲突保守拒绝，不声称事务或严格CAS。任意非200或不匹配成功响应都按未知结果，不自动重试。目录中没列出的旧访问条目继续保持，不因更名或编辑别的条目被清空。

`collection_access.go`读取 `/users/mini-details` 和启用时的 `/groups`。users ID始终是membershipID，与global userId不同；验证本账号member映射、重复账号/成员、组织归属；新增/变更只能选择本次认证目录内的对象。普通成员不能管理；集合级经理仅管理有manage的集合，使用mini-details无需组织用户完整列表权限。全组织经理创建权由固定上游三项permissions联合推导，profile没有accessAll字段。owner/admin可创建，创建/删除/更新的最终权限仍由服务器判定。UseGroups关闭时不请求群组目录、不构造空配置覆盖既有未知分配。

名称更新不隔离。修改已有集合的访问或删除集合均先通过既有Swift `quarantineOrganization` 原子持久隔离，再允许任何HTTP（包括保存前详情GET）；隔离失败零HTTP。此处保守隔离整个目标组织，个人库和其他组织仍可用。隔离后成功、失败、取消或未知结果都不自动撤标记。正常保存后也需从侧栏「重新核验：组织名」明确确认→新sync及账号/成员/RSA校验→restore发布；此路径恢复访问而不重试原集合写入。集合删除解除关联、不删除组织cipher。集合批量删除/bulk-access尚未实现，成员生命周期和群组自身管理不属于本节完成范围。

验证：Go单元覆盖opaque保持、目录ID混淆、未知分配保持、stale详情阻断、scope/revision/刷新checkpoint、隔离失败零HTTP、取消/Close未知结果；headless覆盖角色入口、业务权限控件、确认和锁定清理。隔离1.37.4实际owner/全组织经理CRUD、集合级经理详情/mini目录/更名及禁止创建、普通成员拒绝管理；真实成员只读/隐藏和直接权限优先group、删除直接分配后group回退改用产品集合接口验证，含AutoFill投影。真实HTTP fixture的isolate回调仍为no-op，持久存储用既有Swift52测试；未运行真实系统Keychain/扩展/窗口。具体命令与清理见最新交接。

## 组织生命周期与持久隔离（第九轮）

侧栏「创建组织」输入组织名称、账单邮箱和默认集合名；已有组织→「管理当前组织」，owner可读取并修改资料，普通成员仅退出。创建使用新的随机64字节org key，以当前账户经验证的RSA公钥OAEP SHA256包装；默认集合名用type2加密。组织名和账单邮箱按服务器协议明文保存。创建的可选组织RSA恢复key对尚未生成；没有将这一点伪装为服务器不支持。Owner删除需危险确认和当前主密码，由已认证的KDF参数计算masterPasswordHash，服务端最终验证。退出由服务器实时检查最后owner，不能以离线成员计数替代。组织创建政策/权限拒绝仍由服务器强制；客户端完整策略管理尚缺。

`LeaveOrganization/DeleteOrganization`要求独立isolate回调，先借用SessionCheckpoint中的unlock key在Swift存储层提交本机组织隔离，再发HTTP。隔离失败、旧revision、错误scope或取消在dispatch前阻止请求；所以此路径无需以全账号logout作为正常处理，也不会宣称服务器已操作。请求发出后错误、取消/Close及非200均不能盲重试，未知/非事务失败保持隔离。原生取消使用「取消并锁定密码库」，调用现有锁定屏障；迟到回调不能恢复界面。

新增可选 `VaultData.quarantinedOrganizations`，仅存在认证AES-GCM payload内，旧快照缺字段按空处理。它按当前scope与组织ID持久隔离；服务器原始sync字节（含opaque大整数、新旧profile组织字段、集合与cipher）不做JSON重编码，不产生跨字段不一致的半删除。Go读取Documents/organizationVault时统一排除对应文档、组织key和集合；恢复列表只给组织名，组织已不存在时给普通占位名。Swift按原始cipher.organizationId剔除对应Login投影，在文件锁/CAS下原子写新payload、新snapshot ID与revision，保留其他组织/个人条目和当前session，旧lease及候选身份失效。旧组织密钥与cipher仍是不可经产品读取的服务器密文，隔离不是安全擦除磁盘历史。

普通publish必须认证旧快照，合并已持久隔离标记；即使服务器暂时返回旧成员授权，普通同步也不能撤标记。saveSession保留payload和标记。主应用采用Swift规范化后返回的vault；独立AutoFill解锁只收到已过滤credentials，不收到完整vault/session。`publish`默认不返回vault，bridge主应用路径显式includeVault。主密码包装损坏时不能悄悄覆盖旧快照而擦除隔离，需显式本机撤销；未来KDF/key轮换需提供旧unlock授权，当前Swift测试覆盖，Go用户key轮换尚未实现。

侧栏「重新核验：组织名」→明确确认→新GET sync，经Go验证当前confirmed/enabled成员、全局用户ID/memberID分离、RSA组织密钥链后，调用专用恢复发布。Swift在同scope/expectedRevision下再次检查当前成员身份，移除指定组织标记，其他标记保持。网络失败、accepted、错误用户或member/account混淆不得恢复。恢复不会再次发送原退出/删除；已经成功退出/删除仍无当前授权，保持隔离；重新邀请确认后可在用户同意下恢复。全账号显式logout会删除整个快照和标记，后续登录从服务器重建。

本轮证据：Go management/isolation单测，Swift52测试（新增持久隔离与恢复、独立store重新打开、模拟扩展读取、旧lease、checkpoint/普通sync保留），headless创建/成员确认取消/隔离保留个人与session/迟到回调/恢复入口；隔离1.37.4真实创建、资料GET/PUT、最后owner拒绝、普通成员退出、密码删除。测试未安装系统扩展，未运行真实窗口/Touch ID/Keychain；存储测试用MemoryKeys，不是平台认证实测。中途Swift三项旧测试失败后修正：publish默认继续省略vault，换包装key需旧key授权，损坏包装需明确撤销后重建。最终结果见交接。

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
