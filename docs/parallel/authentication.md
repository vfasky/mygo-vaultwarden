# Card #10：MFA、SSO、macOS AuthenticationServices

本卡仅增加独立组件，**尚未挂接主应用**。基线包含账号卡，未回退14bbaf0；保留Goja/MyGo版本。未修改client.go、account_*、main/ui/network、现有Swift存储或工程配置。所有新文件均在授权路径。

协议来源固定为Vaultwarden **1.37.4** `7c188967e7a467b19b2757bc3326f9cf3ccae327` 的 `src/api/identity.rs`、`src/api/core/two_factor/*.rs`、`src/sso.rs` 与Bitwarden clients **5983f56ce0cf924eea56c7d8f066f7885825a7ce** `apps/web/src/connectors/duo-redirect.ts`。使用现有coverage指定来源，不把空`/api/webauthn`当作Passkey登录。

## Go接口

### 密码 + MFA登录

`Client.LoginMFA(ctx,email,password,remembered,prompt) (MFALoginResult,error)`：prelogin KDF、本机认证hash、0 TOTP / 1 Email / 2 Duo OIDC / 3 YubiKey OTP / 7 WebAuthn，5 Remember自动尝试，8恢复码。5分钟上下文，最多4次token请求（3次人工挑战）；错误返回可重新建立登录流程，不后台自动重试。服务器新的挑战替换旧metadata；密码不传服务器。重用既有KDF/crypto和账号`AccountPasswordPolicy.Check(...,login=true)`处理成功token中的MasterPasswordPolicy。

- `MFAChallenge{Providers map[string]json.RawMessage,Attempt,SendEmail}`：Providers来自可信服务器HTTPS响应。`prompt(ctx,challenge)`必须遵循取消。Email回调只在本次登录有效、只支持服务器提供的provider1，使用同一email/device/hash请求`/api/two-factor/send-email-login`。
- `MFAResponse{Provider,Token []byte,Remember,ConfirmRemoveAllMFA}`：函数消费并清空Token slice；密码由调用者清空。0/1输入数字码，3输入YubiKey产生的OTP，2输入DuoFlow产物，7输入经WebAuthnBinding核验的credential JSON。未知provider拒绝。
- `MFALoginResult{Session,RememberToken,RemovedAllMFA}`：Session仍需正常sync、账号身份、加密快照回执核验。RememberToken属秘密，必须按server+账号+device ID存到安全存储，不能当access token；失败的Remember应清掉本地旧值，新值替换旧值。清库/删除账号/退出时撤销本地令牌。
- **恢复码是关闭全部MFA**：必须先展示影响并设置ConfirmRemoveAllMFA，发送provider8。成功时RemovedAllMFA=true。恢复码登录中任何失败都可能发生在MFA已删除之后，不能以错误推断未执行，需重新核验服务器状态；服务器会清除所有设备Remember token。不是可重复使用的普通备用码。
- Go字符串、JSON与系统SDK副本无法证明物理清零；绝不日志输出密码、OTP、challenge token、恢复码、授权URL或token响应。

### 管理和账号敏感验证

`Session.MFAManage(ctx,op,AccountSensitiveInput,fields,confirmed,persist) (json.RawMessage,error)`：Session锁、beginOperation、refresh/checkpoint复用账号模块。密码本地解包比对user key后使用`accountProofLocked`生成hash；protected-action OTP与主密码互斥，不复制hash逻辑。fields禁止注入masterPasswordHash/任意endpoint，只允许以下字段。返回设置密钥/恢复码仍属秘密，调用者清除RawMessage。

| op | 方法/路径（默认 `/api/two-factor/`） | fields |
|---|---|---|
| list | GET `/api/two-factor` | 无，不需proof |
| get-recover | POST | 无，需confirmed |
| disable | PUT | type（0/1/2/3/7） |
| get-authenticator | POST | 无 |
| authenticator | POST | key, token |
| get-email / get-duo / get-yubikey / get-webauthn | POST | 无 |
| send-email | POST | email |
| email | PUT | email, token |
| duo | POST | host, clientId, clientSecret |
| yubikey | POST | key1..key5, nfc（必需bool） |
| get-webauthn-challenge | POST | 无 |
| webauthn | POST | id（1–5）, name, deviceResponse |
| delete-webauthn | DELETE `webauthn` | id；固定版本只接受主密码，拒绝OTP |
| request-otp | POST `/api/accounts/request-otp` | 无，不需proof |
| verify-otp | POST `/api/accounts/verify-otp` | otp，不需proof |

注册/启停/删除/发送设置码必须confirmed。修改请求失败包装MutationUncertainError，禁止根据HTTP400/500或断线宣称回滚；刷新/预发送失败也保守归为需核验。服务端最终校验设置字段及组织策略。verify-otp会消费protected OTP；不要先verify再将同一码用于另一敏感操作。登录Email OTP和protected OTP是两种不同用途。

### Duo

`NewDuoFlow(server,AuthUrl,epoch)`验证HTTPS、`api-*.duosecurity.com`或`api-*.duofederal.com`、授权路径、服务器连接器`/duo-redirect-connector.html?client=desktop`。仅从可信服务器返回JWT的payload提取state用于关联，不声称客户端验证JWT签名；Duo和VW负责签名/nonce验证。`Complete(callback,epoch)`只接受精确`bitwarden://duo-callback`、单个code/state，比较state并一次性返回`code|state`字节，拒绝重复query、错误来源、管道分隔符与重放。Close取消，5分钟过期。

### SSO和vault解密

`Client.BeginSSO(ctx,redirect,epoch)`请求`/identity/sso/prevalidate`，产生随机256bit state、PKCE verifier及S256 challenge，返回SSOFlow与`/identity/connect/authorize`授权URL。VW作为OIDC客户端处理上游nonce及ID-token校验，本机不自行解析ID-token为登录成功。

**固定服务器desktop回调只支持**`bitwarden://sso-callback`或`http://localhost:8065`至`:8070`（精确URL，无路径）。不能自创MyGo scheme；现有Bitwarden客户端scheme冲突由最终集成处理。Swift浏览器桥走bitwarden scheme；如选loopback，需要最终集成实现本机listener及浏览器生命周期，不要把ASWebAuthenticationSession的HTTP scheme参数冒充已实现listener。

`SSOFlow.Exchange(ctx,callback,epoch[,prompt])`：来源scheme/host/path、服务器iss、state、query唯一性、5分钟/epoch/单次使用核验；错误回调不发送授权码。通过绑定后单次消费，网络未知不自动重放。可传MFA prompt继续服务器MFA挑战，最多4次token请求。SSO挑战的SendEmail为nil（无法用未解锁主密码伪造send-email-login proof）；server单一Email provider会自动发送码，多provider需要服务器/客户端兼容配置。Close取消进行中的HTTP及遵循ctx的prompt。回调必须由启动的系统认证会话交回，不可来自任意网页postMessage。

Exchange返回完整token RawMessage（秘密），**不会安装Session或打开vault**。`Client.UnlockSSOVault(ctx,tokenReply,email,password)`再prelogin→本地KDF→解包64B user key，创建未发布Session；原始密码不发送。仅支持master-password wrapped key，缺wrapper显式失败。key connector、trusted-device enrollment、新SSO账号建库不在该解锁实现中，不冒充可用。集成必须只传本flow返回的token，核验登录账号email与sync profile，并调用现有policy/快照发布契约后采用Session。

### WebAuthn

`ParseWebAuthnOptions(server,raw,register,epoch)`接受provider7原始metadata或get-webauthn-challenge响应，返回RPID、二进制challenge、user ID/name、allowed/excluded IDs及Binding。

`NewWebAuthnBinding`/`Validate(rawCredential,epoch)`要求HTTPS、RP与服务器host精确一致（支持server路径）；绑定challenge、origin、webauthn.get/create、credential ID、allowed list、2分钟、epoch、一次性消费。assertion还核验RP hash与UP标志；不伪造签名/计数器/attestation核验成功，最终由VW完成。拒绝crossOrigin、错误origin、错challenge、RP hash、重复JSON字段及重放。保留原始clientDataJSON字节，绝不重写origin或challenge。

平台桥仅支持AuthenticationServices平台凭据；旧U2F AppID扩展及外部USB安全密钥需另行平台能力，不能把它们标成已覆盖。

## 原生UI及最终集成清单

根`auth_ui.go`提供`newAuthForm`/`authFormView`：provider选择、密码遮掩的token输入、Remember、恢复码二次确认、取消清输入、scope/epoch/sequence拒绝迟到结果。`auth_management_ui.go`提供管理字段、读取/启停/删除、敏感proof输入、二次确认、结果遮掩及失败核验提示。两者都不使用全局app，不自行启动网络。管理表单结果由scheduler转为面向用户的字段/说明，不直接显示原始服务器JSON；注册安全密钥流程由scheduler接平台桥。

#14最终集成必须：

1. 主登录选择接LoginMFA/BeginSSO；scheduler在派发及采用结果前核验当前scope/epoch/sequence，账号切换/锁定取消context并Close表单、SSO/Duo/WebAuthn对象。每个Request用完Close；过时返回的Session立即Close。UI仅在UI线程调用。
2. 新MFA provider2/7按钮分别开启系统浏览器/凭据控制器，不让用户手工输入JSON；普通码输入仅用于0/1/3/8。Duo AuthUrl、WebAuthn原始metadata须来自当前挑战。
3. 将`macos/Authentication/VaultAuthentication.swift`加入app专用源目标（排除Tests/main.swift），注册Go/Swift JSON/回调适配层并持有NSWindow与桥对象。Swift `VaultWebAuthn.start(rp,challenge,userID,userName,allowed,excluded,completion)`；断言userID/userName=nil，注册使用服务器User字段；result Data先经Binding.Validate，再交provider7或MFAManage(webAuthn)提交id/name/deviceResponse。注册id/name由管理UI收集并绑定当前待注册操作。
4. 配置签名、`com.apple.developer.associated-domains`的`webcredentials:<RP>`和服务器AASA。macOS12+基础API，已有excluded credentials注册需macOS14+；旧系统显式失败，避免忽略排除列表。不改现有存储桥文件。
5. `VaultAuthenticationBrowser.start`返回系统会话URL；用SSO/Duo flow做精确来源/state检查。Close/取消必须调用Swift cancel，桥处理重复/迟到系统回调并返回取消错误。URL scheme/entitlement/注册冲突和loopback方案由集成落实。
6. Remember安全存储、账户撤销、完成登录后的sync/账号核验/主密码policy/安全快照发布复用现有契约。注册/管理结果要在当前账号下重新读取核验；UI不得把未知失败当作无副作用并自动重复POST。

## 验证证据与局限

已执行：

- `go test -tags headless ./... -timeout=90s`：通过。
- `go test -race -tags headless ./... -timeout=90s`：最终全部新增组件完成后全包通过，无race报告。
- `go vet -tags headless ./...`：通过。
- `swiftc -typecheck macos/Authentication/VaultAuthentication.swift`：通过，包括真实AuthenticationServices请求、凭据字节桥及取消实现。
- 新增Go测试：管理proof复用/字段注入拒绝、所有provider线协议、SSO PKCE/恶意来源/重复query/重放/取消/epoch、Duo state、WebAuthn origin/crossOrigin/重放、原生恢复码确认/清理/迟到结果、服务器500修改未知。
- `MYGO_MFA_TEST_URL=http://127.0.0.1:32794 go test ./internal/vaultwarden -run '^TestLiveMFA$' -count=1 -v`：真实注册、TOTP注册/错误码拒绝/新时间片成功登录、Remember复用、恢复码登录删除所有MFA及后续无MFA登录通过。
- `MYGO_MFA_SMTP_URL=http://127.0.0.1:32795 MYGO_MFA_SMTP_SPOOL=<scratch>/smtp-mail go test ./internal/vaultwarden -run '^TestLiveMFAEmail$' -count=1 -v`：真实Email设置发码/启用/登录发码、protected-action邮件proof通过。

真实fixture为卡片独占容器`mygo-auth-10-01a1173c`、`mygo-auth-smtp-10-01a1173c`，镜像`vaultwarden/server:1.37.4`，image `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`。只有loopback随机端口、易失/data及新example.invalid账号。SMTP sink复用仓库测试程序，仅在独占容器执行，不转发邮件；二进制/邮件spool只在session scratch，不安装服务，不触碰用户账户。结束删除两容器及含秘密spool。

失败证据：首次根UI测试字段名AccountID编译失败后改为契约Account；SMTP测试首轮错误假设注册总会发邮件，修正为遵循返回token/EmailSent；取消测试夹具未读请求体导致超时，修正后通过。Swift新增`macos/Authentication/Tests/main.swift`的XCTest字节编码测试**未执行**：工具链返回`no such module 'XCTest'`，未安装依赖或切换运行方式；这不影响生产桥typecheck通过，但不能算平台测试通过。

尚未验证：真实Duo租户、YubiKey硬件、WebAuthn/Touch ID签名系统窗口与associated domains、真实SSO IdP/nonce交换、多provider SSO邮件重发、生产存储与主应用桥接。HTTP fixture不是这些环境的替代证据；Swift字节测试亦不是实际认证测试。主应用接线、完整平台注册及UI完整旅程留给最终集成卡。
