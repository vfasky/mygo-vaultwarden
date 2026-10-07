# 完整 Vaultwarden 实现：第六轮阶段交接

**INCOMPLETE — 整卡未完成，禁止据此启动 Review 或合并。** 协调者通过 `contact_supervisor(need_decision)` 批准本轮在跨Go/Swift敏感操作模块与历史删除完成、验证后，精确交接并续启同卡。下一进程直接推进冲突比较/显式重基，然后组织RSA/权限/共享管理和全部原整卡范围；不能把本轮子集当整卡完成。

## 分支与提交

- 唯一项目写入目录为分配的 `board-2-vaultwarden-api` 工作树，分支 `waku/board-2-vaultwarden-api`。主目录 `/Users/vfasky/code/mygo-vaultwarden` 未写入、暂存、提交、stash/reset/clean；用户app/watch、其他容器、凭据均未操作，未访问生产服务，未启动子代理。
- 本轮起点 **f4efc008f20ec3e7c7484e7e50bd02839b61125c**。保留所有前序提交，包括 `0d258d2` 个人导入导出和 `5a48a35` 格式扩展名。不要重导入、回退或重做已验证导入导出。
- **ad6aef0**：个人reprompt主密码短授权、密码/TOTP显示复制、Swift认证lease与敏感剪贴板、协议/Swift/headless/真实回环验证。
- **cbe30c5**：密码历史确认清除；只允许原历史的有序子序列，禁止伪造/重排；保留未删除条目和未知扩展，密码修改仍自动记录刚替换的旧密码。
- **ddb2ca5**：最终入口审计补批量reprompt/viewPassword拒绝；ID-only单项状态API移为测试专用，partial transport收为内部；补历史旧稿/锁定迟到回归。
- 最后交接文档提交的最终HEAD以 `git log -1` 为准；本段实现HEAD不代表允许回退。

## 本轮产品与安全边界

详见 [敏感操作说明](sensitive-operations.md)、[API矩阵](vaultwarden-api-coverage.md) 和 [前序备份格式](personal-backup.md)。

| 路径 | 已完成的实际授权/产品行为 | 仍未完成或明确限制 |
|---|---|---|
| 读取/打开reprompt项目 | 列表仅受保护标题占位，`RequiresPassword`允许打开验证表单；`AuthorizePersonalItem`用当前认证session的domain-separated snapshot unlock key、当前KDF验证主密码；30秒能力绑定session、scope、snapshot revision、源密文SHA256 | 个人项目限定；组织/未知reprompt/viewPassword=false拒绝。不能仅凭公开revision获得能力 |
| 编辑与保存 | `ReadPersonalCipherAuthorized`、`UpdatePersonalCipherAuthorized`；保持reprompt=1，完整PUT保留既有未知字段，同key；操作前及刷新checkpoint之后、HTTP发送前复核 | UI到期关闭并清空未保存表单，事前明确告知；无自动续期。组织策略未实现 |
| 项目复制 | `CopyPersonalCipherAuthorized`新随机item key，源grant复核；reprompt标志保留 | 完整copy对附件/FIDO2/未知扩展仍严格拒绝；不可通过删除草稿字段绕过源schema检查 |
| 单项状态 | UI只调用`ChangePersonalCipherStateAuthorized`，带原文档、权限和grant；刷新后guard复核 | 原`ChangeCipherState`与`SetCipherPersonalMetadata`名称仅在`cipher_transport_test.go`存在，供测试路由断言/自有fixture清理。生产只保留内部transport；不能把这些测试helper接UI |
| 批量/清回收站 | `ChangePersonalCiphers`在整批网络请求前拒绝reprompt或viewPassword=false，UI明确要求单项验证后处理；不静默跳过受保护项目 | 批量逐项授权仍未接入；清空选区含受保护项目时整批阻断，需单项处理 |
| 导入导出 | 继承前序真实产品闭环；导出reprompt继续拒绝，不会借用旧grant | 导出逐项验证尚缺；导入用户选择的备份文件可以创建reprompt=1新项目并保留标志，这是新增操作，不是读取/修改现有受保护项目 |
| 密码/TOTP | 登录编辑页「显示已保存密码/显示当前验证码/复制已保存密码/复制当前验证码」；只用认证快照的已保存内容；显示最长30秒，TOTP不越本周期，reprompt不越grant剩余时间 | 不复制未提交草稿；参数范围、系统剪贴板边界见专文；历史明文显示沿用已有控件，独立短时认证显示尚待统一 |
| 历史清除 | 「清除密码历史」→确认/保留；确认仅改草稿，保存才PUT；有序子序列验证防伪造/重排，剩余未知字段原样保留 | 当前UI提供清除全部；API允许删除任意子序列，UI逐条选择未提供。结果未知不重试；冲突比较/显式重基仍待实现 |

### revision、取消、锁与线程

- `BindSnapshotRevision`只能由认证后的UI lease调用，本身不授予项目权限。grant不是序列化token，字段私有，仅进程内使用；不能跨session/server/account/项目或变更后的密文。
- 主密码KDF在Session.mu之外运行；完成后复核epoch、closed/stopping、ctx取消、revision。主密码byte buffer用后清理，不保留原密码；Go/Swift运行时仍不能证明清零全部字符串副本。
- `persistPendingLocked`安全checkpoint成功后立即递增authorizationEpoch，**即使UI尚未收到新revision也已撤销旧grant**。如果protected写入因此被拒绝，不会向服务器发出该写入；UI采用checkpoint后关闭旧授权表单。checkpoint失败维持阻断。
- 表单到期、lock/logout/切换清除新增显示/密码验证内容。旧回调受UI epoch保护；复用既有`completeCipherMutation`在锁定迟到响应后清理私有草稿。历史旧稿与迟到回归已明确覆盖。
- 秘密复制/显示只在同步UI事件执行，没有从worker/网络响应复制的路径。`WithPersonalSecret`锁顺序为Go Session.mu → Swift主线程（调用已经在UI线程）→ snapshot文件lease；receiver不得回调Session。Swift worker进入时先切主队列再取文件锁，禁止拿文件锁等待UI。UI lock不等待Go Close，Close异步取消/清理。

### Swift桥与剪贴板

- 新桥协议1：`copySecret`、`authorizeSecretDisplay`和`clearSecretClipboard`。前两者需scope、expectedRevision、临时借用的unlockKey、secretNotAfter毫秒时间；copy另带最大64KiB UTF8文本。`withSecretCopyAuthorization`先密码解包再`withCurrentLease`线性化到复制，最终检查deadline仍在(0,30]秒；回执不含秘密或owner。
- `SensitiveClipboard`仅保存随机owner/count；每次复制写入concealed/transient提示。timer最长30秒（TOTP/grant更短则提前），lock/logout/切换/正常退出和观察到外部revision失效时尽力清理；旧timer不能清后续复制、外部同值写入不能被内容相等判断误清。
- **注入测试**：同值/异值外部写入、后续copy/旧receipt、owner或count不匹配、长度界限、主动清理。**真实NSPasteboard测试**：仅独立随机命名board，验证写入owner、外部同值保留及本应用清理；不接触通用剪贴板。
- **Swift认证测试**：错误key+正确公开revision、过期/过长deadline、旧revision、lock/logout均不进入复制body。现有store测试覆盖账号替换与迟到认证撤销；不把这些内存key测试说成真实Keychain验证。
- concealed/transient只是提示，不能防止其他应用/历史管理器读取。NSPasteboard无跨进程原子CAS，最后检查至清理之间仍有外部竞态；强杀/崩溃或尚未观察到的外部锁不能保证立即清理，后者仍有到期清理。

## 实际执行验证

Go统一使用 `GO_BIN="$(bash scripts/resolve-go.sh)"`。以下都实际执行：

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" test -race ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
swift test --package-path macos
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
MYGO_VW_TEST_URL=http://127.0.0.1:32780 "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
git diff --check
```

- 最终生产代码入口封闭后：Go root **0.695s**、协议 **0.554s**、dev-debug cached；race root **3.174s**、协议 **3.021s**、dev-debug cached（本轮首次race实际 **7.848s**）。build/vet/diff check退出0。最后仅新增旧稿历史断言后root test **0.687s**通过，不为断言重跑无关平台验证。
- Swift最终版本实际 **50 XCTest、0 failures**，测试 **0.147s** / wall **0.150s**；bridge typecheck退出0。后续Go历史/批量改动不改Swift，未无理由重复平台验证。
- 真实回环最后执行：PBKDF2 **0.44s**、Argon2id **0.23s**、TOTP **0.63s**，总 **1.31s** / package **1.428s**，通过。包含reprompt创建→sync排除AutoFill→真实密码验证→读取→PUT保持标志→新keycopy保持标志→清理；八类型历史/CRUD已有测试继续通过，新增真实历史清除保持当前密码。
- 本轮**没有安装/执行官方CLI**，输出明确 `official CLI interoperability not requested`；不能借前序官方CLI结果称本轮验证了官方secret/reprompt互操作。
- 初次Go回归旧测试将任何reprompt editor视为泄露，随后区分空的验证表单与明文表单；用`RequiresPassword`独立于Editable保持元数据边界。修正后全量通过。
- 新测试：`totp_test.go`含RFC6238全部18向量、固定Steam向量、边界/畸形参数；`item_authorization_test.go`覆盖错误密码、跨session、文档/权限替换、expiry/revision/撤销/关闭/取消、checkpoint后零写入；`personal_secret_test.go`覆盖认证参数/已保存值/过期表单/错误native授权/锁定/陈旧copy；`password_history_test.go`保留扩展、大整数、草稿不变、禁止伪造/重排/重复、清除并同时换密码；另有批量六种操作权限零请求和Swift上述测试。
- **未验证**真实原生窗口/安装、通用剪贴板用户流程、系统Keychain/Touch ID、AutoFill交互、SMTP、WebAuthn或SSO。headless/命名board/协议回环不替代这些。

## 自有资源清理（已完成）

- 成功使用容器 `mygo-card2-01a114d0-vw`，ID **8634ca2b631f5950ac8cd36a3a5e7003a1dc7fdd08141aaa4d6947c6be15fb25**；label `mygo-test-owner=01a114d0`；loopback **127.0.0.1:32780**；数据bind为本轮 `$TMPDIR/vw-secret-data`→`/data`。
- 镜像ID **sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216**，inspect labels确认版本1.37.4、commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`。
- 清理前按完整ID inspect核对label/镜像/mount后 `docker rm -fv <完整ID>`成功；删除仅本轮scratch `vw-secret-data`，`test ! -e`确认不存在；`docker ps -a --filter name=mygo-card2-01a114d0-vw`无输出。账号和数据库仅为测试随机example.invalid，随自有数据删除。
- 初次容器 **d7827ee4...**未bind scratch即被立即移除（含其匿名volume）；第二次 **812c7325...**因测试环境`PASSWORD_ITERATIONS=5000`低于服务器启动下限100000而退出，已移除；最终容器使用服务器默认设置，不弱化启动限值。未改用户Docker资源、镜像或已有容器。
- 仅留无凭据Swift测试输出于scratch；无本轮CLI/profile安装或外部认证数据。

## 下一进程已批准方向与入口

1. 先保留所有新提交并读本交接/coverage。**冲突比较+显式重基优先**：现有 `cipherEditor`保留document/fields/revision，`completeCipherMutation`对ErrConflict保草稿、MutationUncertainError锁定重复提交，完整sync位于`network.go`。实现保留本地草稿和服务器最新原始对象的用户可见比较/选择；不能静默覆盖最新unknown字段，不能自动重试结果未知写入，不能把服务器约1秒revision容差当严格CAS。reprompt重新比较/解密也需新的有效能力；不可续借旧grant。
2. 随后组织key链、授权与collections/共享/组织管理：完整原始sync已经在`VaultData.Sync`保存；目前`PersonalEntries`跳过组织，`personalDocumentLocked`拒绝组织。`cipherItemKey`目前只有个人owner key；不要把organizationId改一下就共享。实现SPKI公钥、PKCS8私钥、RSA-OAEP type3 SHA256/type4 SHA1解包，结合角色/群组/readOnly/hidePasswords/manage/accessAll和policies授权；memberId与userId严格区分。
3. 固定Vaultwarden源码缓存 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`，tag对象`54a40806c990da2def7acd5a3152edc530c59b79`，commit`7c188967e7a467b19b2757bc3326f9cf3ccae327`，归档SHA256`d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7`。前序routes.txt在父目录，有未注册声明，须对routes!与main挂载核对。
4. TOTP已实际读取固定SDK `39dbb510f5eae82f5cbfd527b0f70a01d5626ec1`，缓存 `/tmp/pi/01a114ab-b4d7-702d-ad3e-13eac28463f8/official/totp.rs`；已实现无需重查。Bitwarden clients固定`5983f56ce0cf924eea56c7d8f066f7885825a7ce`；前序导出格式及CLI证据见`personal-backup.md`，不重做。
5. 后续仍须完成：组织import/export、附件/FIDO2/未知扩展完整备份/copy；附件binary/multipart/外部URL禁Bearer/MAC/大小/两阶段失败补偿/安全临时文件；Send seed16/HKDF/password/fragment/send_access/文本文件owner与接收UI；注册/验证/profile/主密码邮箱KDF/用户key轮换恢复/删除清库/security stamp、MFA各provider管理与平台SSO/WebAuthn、devices/auth requests/domains/emergency/recovery；SignalR MessagePack通知与断线sync；大库桥、query/binary/multipart/Retry-After；完整逐注册路由矩阵及所有模块真实互操作、原生交互验证。

继续同一卡，不自审、不完成、不合并。前五轮详细证据可用 `git show f4efc00:docs/vaultwarden-implementation-handoff.md` 获取。
