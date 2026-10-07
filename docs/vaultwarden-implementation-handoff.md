# 同卡续作交接：附件 binary / transport 内部基础

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 本进程从 `16308ec0cb212e26d6f91c85b0944702d757f21d` 续作。协调者经 `contact_supervisor` 明确批准：因本进程剩余上下文不足，完成本增量验证、精确交接、干净提交后续启同一 #3；只计内部基础，不能宣称附件功能可用。最新 HEAD 以 `git log -1` 为准。恢复历史与 `recovery/vaultwarden-96bc7ef` 均未改动，主目录及用户资源未操作。

## 本轮直接交接

- 新增 `internal/vaultwarden/attachment_crypto.go`：`attachmentEncryptedSize`、`encryptAttachment`、`decryptAttachment`、包内 `attachmentSpool.file/size/close/rewind`。0x02+IV16+MAC32+CBC-PKCS#7；HMAC输入IV+ciphertext；明文0–512MiB，密文65–536870977字节。64KiB分块、0600临时spool；先验证完整MAC再写明文spool，失败/取消不返回结果；空文件/截断/额外尾字节/溢出/坏MAC/坏填充均有测试。没有文件发布API，后续必须以受控lease原子不覆盖发布。
- 新增 `attachment_transport.go`：`(*Client).downloadAttachment(ctx,signedURL,ciphertextSize,key)` 与 `uploadAttachment(ctx,cipherID,attachmentID,token,encryptedSpool)`。下载独立client、无Bearer/cookie/device/referer、HTTPS外部URL或已配置同HTTP回环origin、禁redirect、精确大小与identity encoding、5分钟上限。上传只支持当前vault下direct v2，multipart字段data、固定attachment.bin、已知Content-Length、磁盘流，不通过JSON/4MiB桥。**外部预签名上传未实现**；任意uploadURL不得交给带Bearer的direct函数。底层不refresh/retry/delete，Session须负责checkpoint与未知结果。
- 官方固定SDK39dbb5 `attachment.rs::AttachmentFile::decrypt`已确认：无attachment.key的legacy v1内容用user/org key；有key内容用attachment key，filename/key用cipher key。无key附件跨组织需要binary迁移，不能把账户key包装给组织。官方`test_attachment_without_key`向量已纳入本地测试。固定来源链接、准确API形状和限制见 **[docs/attachments.md](attachments.md)**，下一轮不要重新研究已核实的布局。
- Vaultwarden1.37.4 `post_attachment_v2`返回attachmentId/url/fileUploadType=0和cipherResponse或cipherMiniResponse；url是`/ciphers/{id}/attachment/{attachmentId}`API相对路径。`post_attachment_share`先删除再上传，非原子，未调用。源码缓存 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`。本轮固定SDK原文下载到 `/tmp/pi/01a116cb-ae3d-7666-9072-dffae31009a5/sdk-attachment.rs`、`sdk-symmetric.rs`，临时文件会清理，持久来源锚点已写专题。
- 新增测试 `attachment_crypto_test.go`、`attachment_transport_test.go`、`attachment_transfer_failure_test.go`。官方binary oracle、8MiB+3/边界/碎片Reader、逐字节篡改/所有截断、0600/取消清理；真实httptest HTTPS跨origin signed下载无凭据/签名保持/302禁跳；8MiB multipart、恶意ID零请求、307禁跳、401/500/过长响应/断开只一次POST且无DELETE。测试不是自有1.37.4回环，不能替代真实个人/组织附件验证。
- 本轮使用 `GO=$(bash scripts/resolve-go.sh)`；`go test ./...`通过（root3.344s、vaultwarden8.932s、dev-debug4.814s），`go vet ./...`、`go build -o "$TMPDIR/mygo-attachment-foundation" .`通过；最终`go test -race ./...`通过（root8.982s、vaultwarden14.908s、dev-debug7.317s，passwordstrength cached）。早期定向`-run '^TestAttachment'`两次均通过；补齐加密返回前最后一次ctx检查后，`go test -race ./internal/vaultwarden -run '^TestAttachment' -count=1`通过（1.753s），`git diff --check`通过。没有Swift/ABI改动，不重跑或冒称本轮Swift/AutoFill/Keychain/窗口/签名验证。未启动容器/外部账号，临时产物只在本会话TMPDIR。

## 下一进程明确入口

1. 直接接Session v2元数据回执身份/attachmentID/uploadURL核验→direct上传→sync核对；先refresh+checkpoint，再在各阶段检查scope/revision/epoch/reprompt/type15/pending/组织隔离。`authenticatedGuardedLocked`在`authenticated.go`，写policies应在binary派发前重新核验；checkpoint不得绕过已撤销授权。未知結果不自动重试或DELETE可能成功的文件，失败补偿须有确定回执/状态核对。底层HTTP方法目前不暴露为公开产品API。
2. 接原生文件选择/附件列表/下载发布/删除/取消与锁定，不经JSON桥输文件；复用安全不覆盖写入模式，但文件临时发布必须在MAC与最终授权通过后。blocked arbitrary Reader无法仅靠ctx中断，产品文件/HTTP输入需自有可关闭资源。大小/超时限制明确显示，不能把512MiB当无限传输。
3. 自有隔离1.37.4个人和组织附件回环+官方互操作，再legacy完整跨key迁移（FIDO2、standard/history/URI aliases/attachment key+filename、无key binary）与Send。现有独立item-key共享未改，legacy和所有附件产品仍未完成。
4. 旧交接账号/MFA/策略/组织/桥等全范围保持。协调者另有用户新请求的moejs兼容性/性能只读评估，本卡本轮保持goja，不主动迁移评分实现/依赖，等待协调者结论。

---

# 历史交接：组织创建策略与官方主密码评分基础（16308ec）

**以下是前轮历史证据，非本轮新增或重跑。** 前轮从恢复后的 `96bc7efdbf27ffd5a75ee523219714f2f90545fb` 直接续作，没有重做恢复、重置历史或移动持久恢复引用。原完整范围不缩减。

当前工作树：`/Users/vfasky/Library/Application Support/Waku/worktrees/board/56a21c6a-f119-465b-ae4e-7e77f68151bd/board-3-vaultwarden`，分支 `waku/board-3-vaultwarden`。`recovery/vaultwarden-96bc7ef` 必须保留，不移动/删除；不操作已清理 #2 目录。没有修改主目录、用户 app/watch/真实凭据/生产服务，没有启动子代理。前轮 type16/sourceIndex/恢复 controller 等详细历史见 `git show 96bc7ef:docs/vaultwarden-implementation-handoff.md` 与专题，不重做。

## 1. 组织创建 type3 产品消费

- `internal/vaultwarden/organization_management.go:SaveOrganization`：仅新建分支，在随机 key/RSA 生成与创建 POST 前取得私有认证 `/api/sync` 策略；`operationPolicies.singleOrganization` 限制 confirmed 普通成员/经理创建另一组织，owner/admin 豁免。派发前组合原 revision 门控和 policy scope/revision/epoch 门控；资料 PUT 不被误禁。原生「创建或加入组织」已有创建按钮直接调用本 API，因此无需新 UI；返回可显示的中文策略错误。
- `policy_execution.go` 从 authenticated confirmed policies 解析 type3，不用调用者 VaultData 授权。服务器 disabled、本机 quarantine 都不豁免；accepted/invited 不是 confirmed。`pending_policy.go` 的 pending type3 先阻断创建，直到既有专用恢复清除精确记录；没有改 Swift schema。
- `organization_creation_policy_test.go`：10 个 role/status/disabled/quarantine/pending 场景，包含旧本地无 policy 而最新服务器限制；cancel/Close 的在途 GET 零 POST；refresh/checkpoint 失败、旧授权不能继续、重新认证后恢复，且操作策略不外泄。既有管理测试 helper 改用实际 HTTP `/sync` fixture，没有注入私有权限。
- `policy_execution_integration_test.go` 新增 `single-organization-creation`：自有 1.37.4 普通成员受限、隔离不能绕过、owner 产品创建成功。额外组织仅存在于一次性容器；后续集合选择改为目标 org 精确匹配。

固定服务器源码缓存仍可读：`/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/`。固定 commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`，`src/api/core/organizations.rs:187` 创建约束，`src/db/models/org_policy.rs:282–343` 的 `is_applicable_to_user/check_user_allowed`。

**协调者已确认的信息可见性决策**：客户端可判定部分预检；邀请目标角色及跨账号状态由认证服务器强制校验。profile 不提供未接受邀请的目标 role，policies/token 只有 policy，管理员无权读取对方 sync/其他组织/2FA。不能从未验证 JWT 授许、读服务器私钥或将普通成员约束强加给 owner/admin。缺关键事实不宣称本机判定通过，仅将用户已确认请求交给现有认证端点最终校验；失败不伪成功、不重试、不继续发 key/改密码。已有邀请 policy/key 可信确认、user-key 包装、epoch/隔离全部保留。**新真实 SMTP 场景（普通 member 受限、owner/admin 真实角色豁免、拒绝后无后续 key 操作）本轮未跑，须继续补；完整管理员账号恢复产品也仍待实现。**

## 2. 固定官方 zxcvbn 基础（不是改密产品）

- `internal/passwordstrength/strength.go`：`Evaluate(ctx,password,email,userInputs)` 仅返回整数 Score 与 GuessesLog10；`CheckMinimum` 用 `score >= minComplexity`、空密码永不满足。尚未接注册/改密/enforceOnLogin 等账号消费者，不能算 type1 全量执行，也不把此 API 单独当作完成用户的完整产品任务。
- 固定 clients `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 的 `libs/common/src/tools/password-strength/password-strength.service.ts` 和 package-lock：原始 npm **zxcvbn 4.4.2**，821792-byte dist/完整词典未改写。lock SHA512 已比对，dist SHA256 `f42c651f40506acb6b662490f338dd47a5951d3312039c4ab8fe5090484f351a` 有自动检查。
- 固定 `goja v0.0.0-20261007120015-921e62952efd` 解释器；复用仅固定程序编译结果，每次独立 runtime。显式禁 sourcemap 文件读取，无 filesystem/network 宿主绑定，输入作为函数参数。官方 JS UTF-16、trim/lowercase/邮箱 local-part regex 拆词、`bitwarden/bit/warden` 与用户词去重保持。原始日期估计用当前年份，测试 oracle 固定 2026 年。
- 资源界限：口令/邮箱各 1024 UTF-8 bytes，最多 64 用户词、每词 1024 bytes、总输入 16384 bytes；超限/非法 UTF-8 返回错误而非截断。初始化/运行 2 秒、caller cancel、栈 1024。没有硬内存配额，也不承诺 Go/JS GC 字符串清零。异常只返固定错误，不返密码/token/sequence/栈。
- `strength_test.go` + `testdata/generate-vectors.cjs/vectors.json`：**28 个独立 Node 官方 oracle**，五档评分、日期、字典/leet/键盘/重复、品牌、邮箱/附加用户词、中文/emoji/土耳其大小写/BOM/NBSP/组合字符/NUL/空输入；评分+guesses_log10 比对。另测全部最低评分阈值、输入界限、取消、并发词典隔离。首次 UMD 装配缺 exports 和一次测试逗号错误曾失败，均已修复；最终完整测试通过。
- 来源、完整性、具体阈值与边界见 `internal/passwordstrength/README.md`；扩充既有 `THIRD_PARTY_NOTICES.md`、保留原声明，加入原始 MIT/BSD/Apache 许可证副本；`scripts/collect-licenses.sh` 将嵌入资源许可证按声明相对路径一起收集。go.mod/go.sum 固定新增引擎及依赖，tidy 同时把已有直接使用的 x/sys 从 indirect 分类移到 direct，版本未改。
- 原生 type1 管理表单文案只说明主密码变更/登录执行尚待接；README、coverage、策略专题同步真实完成边界。

## 本轮最终验证

工具链一直用 `GO=$(bash scripts/resolve-go.sh)`；临时产物只放本轮 `$TMPDIR=/tmp/pi/01a116af-8d0e-7600-8645-9032bf88bb9c`。

- `"$GO" test ./...`：root **3.432s**、passwordstrength **2.296s**、vaultwarden **6.987s**，dev-debug cached，通过。
- `"$GO" vet ./...`、`"$GO" build -o "$TMPDIR/mygo-singleorg-strength-app" .`：通过。
- `"$GO" test -race ./...`：root **9.376s**、passwordstrength **15.722s**、vaultwarden **15.542s**、dev-debug **7.813s**，通过。
- `MYGO_VW_POLICY_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLivePolicyExecution$' -count=1 -v -timeout=90s`：body **2.52s** / package **2.645s**，新 `single-organization-creation` **0.05s**，其余既有政策回环全过。只建唯一名称/label 的 1.37.4 回环 Docker + example.invalid 账号，cleanup 按完整 ID + label 核验。结束后 `docker ps -a --filter 'name=mygo-policy-' --format '{{.ID}} {{.Names}}'` 无输出。
- `TARGET_BUILD_DIR="$TMPDIR/bridge-singleorg-output" CONTENTS_FOLDER_PATH=SingleOrgStrengthCheck DERIVED_FILE_DIR="$TMPDIR/bridge-singleorg-derived" ARCHS=arm64 MACOSX_DEPLOYMENT_TARGET=14.0 CODE_SIGNING_ALLOWED=NO bash scripts/xcode-build-bridge.sh`：实际桥编译 exit 0。
- `bash -n scripts/collect-licenses.sh`、实际收集到 `$TMPDIR/strength-collected-licenses`、用 `cmp` 比对打包后的 zxcvbn/goja 许可证：通过。
- `git diff --check`：通过；新增许可证保留原文件。最终提交/clean 状态见进程最终报告。
- 没有修改 Swift/AutoFill 源码或 ABI，不重复前轮 Swift63/AutoFill typecheck，并且**不声称本轮重新通过**。没有真实 Keychain/Touch ID、窗口预览、签名安装/系统 AutoFill 实测。Go-only live receipt 仍不能替代 Swift 落盘链。

## 下一进程从这里继续原整卡

1. **优先 legacy 完整共享 + 附件共用基础，再 Send**。已定向读 `organization_write.go:SharePersonalCipher/writeOrganizationCipher`、`cipher_copy.go:validateCopyObject/copyAuthorizedPersonalCipherDocument`、`cipher_document.go:transformCipher`。现状：独立 item-key 共享重包装且 opaque/附件/FIDO2 同 key 保留；legacy 无 item key 仍拒绝。`transformCipher` 只处理当前标准字段，不处理 FIDO2/附件；不能仅包装 user key 或只改 organizationId。完整 legacy 跨 key 要逐标准字段、URI checksum/legacy alias、history、custom、FIDO2、attachment key/filename 正确转换；无 attachment key 的历史附件可能需下载/解密/重新上传，尚未在本轮核实完整 DTO 或实现，**不要把这个推测当已验证协议**。
2. 附件 binary/multipart、外部预签名不带 Bearer、MAC/大小/取消、有界传输、0600 临时文件、两阶段补偿/未知结果核对和原生入口；附件不能走当前 JSON/4MiB 桥。随后文本/文件 Send 的 owner/receiver 全流程。路由与来源继续按原 coverage 固定审计核对，不猜。
3. 补上述真实 SMTP policy role 场景；管理员恢复随其产品验证。账号产品接 type1 时复用本轮精确评分基础，不重写字典；还需真正长度/字符/政策来源/登录及轮换恢复规则，不能把评分函数当完成。
4. 全部原范围仍保留：账号/MFA/SSO/WebAuthn/设备/应急/恢复/通知、大库桥、组织 state/bulk/copy/export/conflict、reprompt批量/导出、无ID数组冲突、URI前缀/正则、完整路由矩阵等。当前 `docs/vaultwarden-api-coverage.md` 与原卡是范围权威；此次交接不缩减。
5. 只有**整卡完成后**协调者才创建独立 Review/合并；本增量只用于续启同 #3。
