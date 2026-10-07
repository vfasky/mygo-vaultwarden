# 完整 Vaultwarden 实现：第五轮阶段交接

**INCOMPLETE — 整卡未完成，禁止据此启动 Review 或合并。** 本轮完成个人原生文件导入导出后继续调查了 reprompt/秘密/TOTP；在剩余上下文不足以可靠实现跨 Go/Swift 安全剪贴板时，协调者通过 `contact_supervisor(need_decision)` 批准精确交接、清理和续启同一卡。整卡目标与原验收不变，没有将下一模块调查计为实现。

## 工作树与提交

- 唯一写入项目目录：`/Users/vfasky/Library/Application Support/Waku/worktrees/board/56a21c6a-f119-465b-ae4e-7e77f68151bd/board-2-vaultwarden-api`，分支 `waku/board-2-vaultwarden-api`。
- 本轮起点 **e54ac2673ef1135897dee72cb73634a80da867d5**；保留全部前序阶段，包括 baseline `4b0a910`、`331b1c4`、八类/离线库 `7ae7560`、文件夹/批量 `15a0567`、细节编辑 `7f0a408`、复制 `0dab306`。不要回退/重导入。
- 本轮主实现 **0d258d2**：20文件、个人原生导入导出、MyGo八类备份、官方CLI互操作。
- 后续安全细化 **5a48a35**：两种导出强制不同扩展名；无扩展名时补全，错误扩展名在触碰文件前拒绝，避免应用格式伪装官方JSON。最后交接提交另含导入导出面板期间其他管理入口的禁用状态修正，最终HEAD见 `git log -1`。
- 主目录 `/Users/vfasky/code/mygo-vaultwarden` 没有修改、暂存、commit、stash/reset/clean；用户app/watch及其他容器没有操作。没有读取用户凭据、访问生产vault或启动子代理。主目录dirty合并问题仍由协调者处理。

## 已实现与精确边界

详见 [个人文件格式与互操作](personal-backup.md) 及 [API矩阵](vaultwarden-api-coverage.md)。

- 顶栏「导入导出」连接真实 `mygo.Dialog.Open/Save`，不是raw API壳。选择格式/逐项导出范围，默认当前列表，可显式选整个个人库中活动/归档/回收站；同时包含全部个人文件夹（含空文件夹）。导入显示项目数、文件夹数、归档/回收站数和逐项类型/标题，明确确认创建新副本而非覆盖。
- **Bitwarden兼容JSON `.json`** 是官方camelCase `{encrypted:false,folders,items}`。以固定 clients `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 的 `CipherExport`、各section export、`BitwardenJsonImporter` 为据。只支持该版本真实可表示的1–7类，且所选范围中有Passport、回收站、>5条history、不可重建checksum/不一致legacy alias、登录附加设置/密码修订时间、空白名称/备注、亚毫秒history时间时整体阻断并提示MyGo格式。库中未勾选的Passport不妨碍兼容子集。官方该版本不导入Passport是格式限制，**不是Vaultwarden不能保存8类**。
- **MyGo备份 `.mygovault`**：`format:"mygo-vaultwarden-personal-backup",version:1,encrypted:false,folders,items`。与官方格式严格互斥，未知版本拒绝。1–8类标准字段、四类custom、notes、多URI/checksum/legacy alias、登录设置、全部history、日期与folder引用保留。不含用户key/item key/token/账号凭据；尚不支持附件、FIDO2、未知扩展、有旧key依赖的字段，遇到时整体拒绝，不能称任意数据完整备份。组织不导出；reprompt在再次验证完成前拒绝导出。
- 导入32MiB/10,000项目与文件夹上限，拒绝重复JSON键、非UTF8、混合/未知格式、畸形类型/date/URI策略/folder引用。**第一次服务器写入前预检并加密全部项目**；每项独立随机64字节key，经当前user key包装。先建folder并映射ID，再POST cipher，回收站项随后PUT `/delete`。服务器生成新的创建/修订/删除时间；归档日期可原样保留。原始history内容不截断。
- 刷新仍先checkpoint落盘；scope/revision/epoch与取消/锁定检查；任何导入写入失败立即停止并保留已创建ID、失败/未知项，不重试。成功/失败后全量sync；UI按已知ID报告存在性并要求核对内容和状态，未知ID不假装核对成功。取消不假装回滚已完成服务器写入。
- 文件读取仅有界普通文件；逐目录描述符+`O_NOFOLLOW`拒绝符号链接；0600随机临时文件、fsync、`linkat`原子不覆盖发布。已有文件/符号链接/并发创建目标均拒绝，需新文件名。对话框期间不保留导出明文缓冲，返回后重新核对并解密。失败、取消、锁定或陈旧revision回调删除本次临时文件、不发布目标。无覆盖旧文件功能，不承诺崩溃后自动清扫或运行时所有字符串副本可证明清零。
- 没有改Swift schema/桥或AutoFill；仍通过既有sync→完整加密vault→最小Login投影，不乐观插入凭据。

## 官方互操作与固定源码

- npm独立官方CLI **`@bitwarden/cli@2026.5.0`**，实际 `bw --version` 为 `2026.5.0`；安装命令 `npm install --prefix "$TMPDIR/bw-cli" @bitwarden/cli@2026.5.0 --ignore-scripts --no-audit --no-fund`。没有改项目依赖。tarball SHA1 `3a5a65abd2fa36c0da17ef6a0b751b8bed2cdcbd`，SRI见 `personal-backup.md`。npm没有gitHead，不宣称包等同固定源码commit的构建。
- CLI每次使用Go `t.TempDir()`中的独立 `BITWARDENCLI_APPDATA_DIR`；密码与session只放子进程env，未写日志/文档或参数。真实账号为本用例随机 `example.invalid`，用户现有CLI profile完全没有触碰。
- 命令方向：`bw config server <测试HTTPS relay>` → `bw login <随机测试邮箱> --passwordenv <测试环境变量> --raw` → `bw import bitwardenjson <测试兼容JSON>` → `bw sync` → `bw list items` 和 `bw list items --archived` → `bw export --format json --output <测试文件>` → MyGo解析/导入官方文件 → `bw logout`。
- CLI强制HTTPS；测试用 `httptest.NewTLSServer` 代理至自有回环容器，并通过子进程 `NODE_EXTRA_CA_CERTS` 信任临时测试证书。没有关闭TLS验证或修改CLI。relay随test关闭。
- 实际验证：官方CLI解密 **1–7类**全部标准字符串、name/notes/favorite、四类custom（含linkedId）、多URI与匹配策略、password history；日期按同一时间比较，custom缺省/null按语义比较。官方导出的整个文件被MyGo接受并写回；MyGo八类格式另行在真实1.37.4导入/再导出，确认history、归档和回收站。**这不是8类完整官方互操作，也不是附件/FIDO2/未知字段互操作。**
- 固定官方源码缓存本轮仍在 `/tmp/pi/01a114ab-b4d7-702d-ad3e-13eac28463f8/official/`（各 `*.export.ts`、`bitwarden-json-importer.ts`、`individual-vault-export.service.ts`等）。只留无凭据源码缓存，CLI安装及profile已清理，下一轮需要时按固定版重新获取。

## 测试与实际执行结果

Go统一 `GO_BIN="$(bash scripts/resolve-go.sh)"`。

```sh
"$GO_BIN" fmt ./internal/vaultwarden ./
"$GO_BIN" test ./...
"$GO_BIN" test -race ./...
"$GO_BIN" build ./...
"$GO_BIN" vet ./...
swift test --package-path macos
swiftc -typecheck -parse-as-library -module-name SnapshotBridge macos/Shared/*.swift macos/Bridge/SnapshotBridge.swift
MYGO_VW_TEST_URL=http://127.0.0.1:32777 MYGO_BW_CLI="$TMPDIR/bw-cli/node_modules/.bin/bw" "$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
git diff --check
```

- 全部最终通过。最后格式扩展名细化后的Go test root **0.691s**，协议cached（本轮 **0.564s**）；race root **3.043s**，协议cached（本轮最终全验证 **2.882s**），dev-debug cached（本轮 **7.369s**）。最终交接入口禁用状态修正后再跑：root test **0.695s**、race **3.052s**，协议/dev-debug cached；build/vet退出0。
- Swift本轮实际重新执行：**44 XCTest、0 failures**，总 **0.213s** / wall **0.217s**；bridge typecheck退出0。没有把继承结果说成本轮运行。
- 最后真实回环：PBKDF2 **19.63s**（含官方CLI）、Argon2id **0.26s**、TOTP **0.57s**，总 **20.46s** / 包 **20.591s**，全部通过。文件扩展名和最终纯UI禁用修正不改协议，未为这些无关改动重跑真实互操作。
- 新测试：`backup_test.go`、`backup_safety_test.go`、`backup_integration_test.go`、`backup_file_test.go`，覆盖八类字段往返/新key、兼容子集/Passport阻断、unknown/FIDO2/附件/权限/reprompt、无效/混合/重复键零请求、folder映射/部分未知结果/软删、checkpoint失败、scope混淆、Close取消不继续、0600/链接/并发目标/取消/锁定/旧revision/格式扩展名、headless确认与预览清理。
- 真实测试过程中曾因官方CLI拒绝HTTP而失败（补测试TLS relay解决）；非UUID夹具folder被SDK拒绝（换合法UUID）；默认CLI list不显示archive（加入显式archived查询）；JS日期规范化和缺省null导致过严测试比较（改按时间/字段语义比较）。连续调试撞到自有服务unauthenticated 429，重启自有容器清内存限流后端口由32776变32777，旧端口一次连接失败；更新实际端口后完整回归通过。不是生产请求或产品绕过限流。
- **未验证**实际Open/Save窗口/安装、Keychain/Touch ID、AutoFill交互、SMTP/WebAuthn/SSO；headless/Go/官方CLI不能代替这些。

## 自有资源清理（已执行）

- 容器 `mygo-card2-01a114ab-vw`，ID **`ece0aae5e0611e1d2a22253d8cf40d9f3111240432329f09239df3f08d32a1d1`**，label `mygo-test-owner=01a114ab`；镜像1.37.4 ID `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`。挂载仅本轮scratch的 `vw-backup-data`→`/data`；loopback初始32776、最后32777。
- 清理前inspect核对ID、label、镜像和挂载；按完整ID `docker rm -fv` 成功。按名字筛选 `docker ps -a` 无输出。
- 删除本轮scratch `vw-backup-data`、独立 `bw-state`、`bw-cli`安装、安装日志及package元数据，逐路径确认不存在。Go `TestLiveVaultwarden*` 临时目录剩余 **0**（包括测试token/profile/导出/证书）。测试内部还清理各用例相对起点新建的cipher/folder。无本轮容器/账号数据库/CLI token遗留；没有清理其他资源。

## 下一轮直接继续：已批准的安全秘密模块（尚无实现）

不要重做导入导出或重导入baseline，先读最新HEAD。调查及协调结果如下，**仅方向批准，不算已落代码**：

1. **reprompt**：主密码再次验证后只给短时、当前scope+本地revision+item的授权；锁定/账号切换/迟到回调/授权过期都撤销。再次解密与复制前检查viewPassword/reprompt，组织后续按实际权限。`Session.passwordUnlock`保存domain-separated snapshot unlock key及KDF配置，可用现有`DeriveSnapshotUnlockKey`验证，不要存原主密码。现有 `ReadPersonalCipher`、`EncryptCipherDocument`/copy仍拒绝reprompt；不可只改flag绕过。
2. **剪贴板接口已批准**：MyGo v0.2.15 `modules.go`只有ReadText/WriteText/Clear，没有changeCount/ownership或sensitive标记。因此通过Swift桥实现：`NSPasteboard.changeCount`+每次随机owner双重校验，固定30秒、lock/logout/账号切换/正常退出尽力清理；旧timer不能清后来本应用复制或用户后来复制的同值内容。串行化本应用操作，内存只保留标识/计数；concealed/transient仅兼容提示，不保证禁止其他应用读取/历史/同步；系统无跨进程原子CAS，不作绝对外部竞态保证。
3. **授权接口约束**：必须有当前认证session/lease及scope+revision，不能只凭公开revision；payload限长、无秘密日志/状态/回执，owner不是vault授权。Go/Swift bridge需要明确版本及失败处理，不影响AutoFill。`SnapshotStore.unlockWithPassword` + `withCurrentLease`可作为已有认证/线性化参考；如果用session的snapshot unlock key，复制key必须借用后清除，不能增加认证前泄露。锁定后的迟到响应不能写pasteboard。复制密码与TOTP复用此路径。
4. **验证方向**：注入pasteboard模型覆盖外部同值/异值、连续copy/旧timer、lock/logout/切换、revision变化、错误授权、退出；Swift回归+bridge typecheck+Go生命周期。真实底层测试只能用独立命名pasteboard，不改用户现有通用剪贴板；模拟不等于真实已验证。
5. **TOTP源码**：固定clients `5983f56.../libs/common/src/vault/services/totp.service.ts`只调用SDK。已读固定SDK **`39dbb510f5eae82f5cbfd527b0f70a01d5626ec1`** 的 `crates/bitwarden-vault/src/totp.rs`，缓存上述official目录中的`totp.rs`。支持base32、otpauth、steam，SHA1/256/512。其parser会默认/夹紧部分参数，本客户端需明确安全参数范围，不把未知算法或畸形输入静默当成功；加入RFC6238与固定Steam向量、时间边界、短时显示/复制UI。当前还未写生成器/显示/复制代码。
6. MyGo正常退出事件是`mygo.App.OnWillQuit`/`OnQuit`；UI可用 `Context.After`定时更新，敏感输入仍应遮掩并独立短时显示。不要切成普通可复制输入却绕过受控剪贴板。

## 原整卡未完成范围（全部保留）

- 任意附件/FIDO2/未知扩展的完整copy/backup、组织import/export、官方加密导出/ZIP与完整互操作。
- reprompt短授权、密码/TOTP显示复制、历史删除、冲突比较/显式重基。
- 组织SPKI/PKCS8 RSA-OAEP type3/4 key链、角色/群组/manage/readOnly/hidePasswords/accessAll权限与策略、collections/共享、组织CRUD/退出、成员邀请接受确认撤销恢复、groups/policies/events/Public API目录/API keys/账号恢复。
- 附件binary/multipart独立传输、0x02/IV/HMAC/CBC、外部URL禁Bearer、大小/MAC/URL、两阶段补偿、安全临时文件；Send seed16/HKDF/password/fragment/send_access/文件与文本owner/接收完整UI。
- 账号注册/邮箱验证/profile/keys/主密码/邮箱/KDF/用户key轮换恢复/删除/清库/security stamp、其他MFAprovider/管理、SSO/WebAuthn平台交互、devices/auth requests/domains/emergency/recovery、SignalR MessagePack通知/断线sync。
- 桥4MiB大库边界、query/multipart/binary/Retry-After、逐注册method/path/别名/权限/UI与真实上游边界的完整矩阵。
- 上述模块的crypto/权限/故障/真实互操作；真实原生窗口/安装/Keychain/AutoFill/SMTP/WebAuthn/SSO验证。

固定Vaultwarden源码仍为 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`，commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`，tag对象 `54a40806c990da2def7acd5a3152edc530c59b79`，归档SHA256 `d31a3ef5456619cfe424f0586f4ecadd186e22513a93bbeab6bc2f09cda803a7`。前四轮细节见 `git show e54ac26:docs/vaultwarden-implementation-handoff.md`。

继续同一卡，不自审、不完成、不合并。
