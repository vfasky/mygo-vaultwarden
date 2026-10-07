# #24 跨设备登录发起端交接

实现基于当前 main 上已合入的 #10/#11，不改公共 Session、主程序、认证、账号或存储核心。新增文件均为 `internal/vaultwarden/device_login*.go`、根 `device_login_*.go` 与本文。协议固定为 Vaultwarden **1.37.4**，commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`：

- [identity.rs](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/identity.rs)：`password_login`、`ConnectData.auth_request`。
- [accounts.rs](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/accounts.rs)：`KnownDevice`、`post_auth_request`、`put_auth_request`、`get_auth_request_response`。

## 协议和状态

`Client.BeginDeviceLogin(ctx,email,expectedScope,epoch,check)` 首先调用 `/api/devices/knowndevice`，使用 base64url `X-Request-Email` 与 `X-Device-Identifier` headers。必须传入既有账号 ID；不猜测未知账号 ID，不允许给未登记设备冒充此能力。之后复用 #11 的 `BeginAuthRequest` 生成独立临时 RSA 2048 位密钥、随机 accessCode 与五分钟请求。`check(scope,epoch)` 必须线程安全，检查当前 server/account、应用 epoch 和锁定状态。

`Metadata()` 只返回公开请求信息。审批设备必须经可信独立渠道核对请求端显示的完整 SHA-256 公钥指纹。不能把服务器 GET 返回的公钥直接当可信钥。发起端不复制、不保存或记录私钥、accessCode、user key、MFA token。原协议的 response GET 必须携带 code query；沿用 #11 已脱敏的 request 错误，不暴露 URL 到 UI、日志、剪贴板或外部跳转。

`Run(prompt)` 仅允许调用一次：

1. 匿名通知只投递安全轮询提示；每两秒定时轮询补偿不可用 socket，通知重连也会触发重读；提示合并且 grant 仅由一个工作循环执行。
2. 匹配请求 ID、公钥、审批结果后复用 `TakeUserKey` 单次解包。仅在该次 grant 的栈内保留被 Take 清除前的 accessCode。
3. 真实身份交换字段为 `grant_type=password`、`username=email`、`password=accessCode`、`authrequest=request UUID`，以及固定 desktop/device/scope 字段。审批密钥从不当 Bearer。服务器还要求相同来源 IP；设备/IP 来源变化必须重新发起。
4. 使用服务器 `twoFactorProviders2` 对接已有 MFAChallenge/MFAResponse，最多四次 token HTTP。支持固定版本的 0/1/2/3/7；8 恢复码须显式确认删除全部 MFA。不提供 `SendEmail`：该接口需要主密码 hash，不能以 accessCode 代替；仅支持服务器自动发码的 Email 路径。Duo/WebAuthn 经已有原生桥产生并验证响应。恢复码失败也可能已删除 MFA，沿用 #10 的需重新核验约束。
5. MFA 成功后服务端单次消费 authrequest。网络/重定向/5xx/畸形 token 等未知交换关闭 flow，不自动重放；重试按钮创建新钥、新 accessCode 和新请求。明确 MFA challenge 允许继续同一请求。取消不会假称删除服务器请求，也不会回滚已完成的 grant。
6. 成功 token 创建绑定 expected account 的 Session，再调用正常 Sync，核对 profile ID、规范化 email、token/profile wrapped key、策略和组织身份。额外用批准 user key 解包并核验 profile 的账户 RSA 私钥，即使空库也拒绝错误 user key。缺少可验证账户私钥的老旧/特殊账号失败关闭，未实现 enrollment 或自动修补。
7. 只有全部通过才返回 `DeviceLoginResult{Session,Sync,RememberToken,RemovedAllMFA,RequiresPasswordForSessionPersistence:true}`。不解析未验证 JWT 作为身份证明。

拒绝会删除服务器请求，固定版本随后返回 HTTP400；与来源/IP/code失效无法安全区分，`ErrDeviceRejected`/UI 明确表示“拒绝、移除或来源变化”。期限/取消、未知设备、账号变化、MFA、未知交换保留不同错误来源。调用方需遵守 prompt 的 context，不能提供无限阻塞 callback。

`Close()` 取消等待、HTTP、MFA和通知，并关闭已经返回的 Session；成功后停止五分钟审批计时器，Session 由其宿主生命周期控制。保留该 flow 至 logout/lock/切号/替换会话时 Close。父 context 同样会撤销返回 Session，不能给 Begin 传入一个在采用结果后立刻取消的短命 context。应用还须在发布和采用结果处再次检查 scope/epoch/存储 lease；旧 callback 不能更新后来的账号。

## 无主密码的存储边界（已与协调者确认）

没有伪造 `PasswordUnlock`。首次返回的 `Sync.PasswordUnlock=nil`、`Sync.Session=nil`。已有存储 `publish` 禁止没有密码包装的 savedSession，`savedLocked`/refresh checkpoint 也要求真实密码包装，因此：

- 初始会话只在当前运行期、当前 access token 有效期内使用。锁定或 token 到期后重新审批/主密码登录；不承诺后台续期。
- 无主密码时，不持久化 Session 或明文 user key。仅可走现有系统认证保护的无 session credentials/vault 快照路径，为 Swift AutoFill 提供最小投影。不能宣称 Go 主界面可在重启后恢复完整 vault 解密或网络会话。
- 不能覆盖已有密码包装快照；保留原快照。替换账号/快照须既有显式撤销、CAS 与发布契约，AccountRecovery/pending 屏障优先。此模块不调用任何存储写入 API，无自动降级或修改 header 的旁路。
- `RememberToken` 仍是敏感数据，仅可按 server/account/device 经既有安全存储处理，不得显示或作为 access token。

显式后续 `flow.BindPassword(ctx,password)` 使用同账号 prelogin KDF，在 Session 锁外派生，解包当前已验证的 wrapper 并 constant-time 比较审批 user key；调用 token 返回的 `AccountPasswordPolicy.Check(...,login=true)`。原始密码与 hash 均不发送。提交时重查 ctx、宿主 epoch、Session 活跃状态、账号、授权 epoch、revision、wrapper 和 user key；错误密码、切号、换 wrapper、并发 sync、锁定或取消不会安装迟到包装。只安装真实 domain-separated snapshot unlock key，不写现有快照。**绑定后必须重新 Sync，通过正常认证 publish/lease 回执安装**，再使用现有 RestoreSession/refresh/checkpoint 流程。输入 password 由调用方立即清除。密码绑定是显式用户操作，最终集成可在登录成功后提供此步骤。

## 独立原生 UI

`NewDeviceLoginPanel(client,email,scope,epoch,DeviceLoginHost)` / `View` 提供已知设备说明、公钥指纹、等待/MFA/拒绝/过期/取消/未知结果、手动新请求与当前运行期限制。

- `Dispatch` 必须用 `window.Update`，panel 的 Start/Cancel/Close/View 仅在 UI 线程调用。
- `Check` 捕获正确 scope/epoch/锁定状态；工作线程和 UI 采用前都检查。
- `Accept(flow,result)` 在 UI 线程重查生命周期和存储要求。成功才接管 flow；失败 panel 关闭 Session。成功后关闭 panel 不关闭已接管的 flow，集成必须在锁定/退出等处 Close flow。
- 普通 MFA 复用已有原生 `authForm`，含恢复码二次确认、取消清理。2/7 只显示系统操作按钮，调用 `Platform(ctx,challenge,provider)` 接 #10 的 Duo/WebAuthn 原生桥，不让用户输入 JSON。未提供平台桥则不展示这些按钮。Remember 持久化仍由安全宿主承担。
- 取消关闭本机句柄，UI 明确服务器请求可能保留至到期，迟到批准不会在本机登录。重试是新请求，绝不再次调用旧 Run。
- 没有全局 app map，没有主导航/生命周期接线，也没有系统剪贴板、深链、秘密日志。

## 验证

已执行：

- `go test -race -tags headless ./... -count=1 -timeout=120s` 全包通过；原生面板测试在 headless UI 环境执行。
- `go vet -tags headless ./...` 通过。
- `MYGO_DEVICE_LOGIN_TEST=1 go test -race -tags headless ./internal/vaultwarden -run '^TestDeviceLoginLive1374$' -count=1 -v -timeout=180s` 真实 1.37.4 通过。测试自行创建唯一 label/name 的易失容器，只绑定127.0.0.1随机端口、随机 example.invalid 两个账号，每个账号先登记发起设备再用另一设备审批。第二账号启用真实 TOTP，等待新时间片后通过 MFA。包括未知设备拒绝、真实拒绝请求后的400、grant→sync→真实密码条目解密、服务器拒绝已消费 code 的二次 grant、主密码绑定、导出/恢复会话后的真实 refresh 与 sync。
- 容器清理先按完整 ID 核对唯一 `mygo.fixture` label，再删除容器和匿名卷；不访问用户设备/生产凭据。
- 单元/race 覆盖正确 grant 字段与无 Bearer、MFA无伪造邮件 proof、错误 user key/账号、批准后切号、未知交换不重发、通知不可用的轮询补偿、取消/拒绝/期限、单次 Run、错误/正确主密码、绑定期间 wrapper/epoch/revision 替换与取消/锁定、恢复会话材料、原生 UI 迟到 MFA/结果拒绝、恢复码确认与错误状态。

真实恢复测试的 checkpoint 回执是测试 stub，不是实际 Keychain 写入；存储原接口未改动。无密码结果不包含 savedSession 的断言并不替代 Swift 真实系统认证测试。没有验证真实 Touch ID/Keychain、签名安装、人工带外核对、平台 Duo/WebAuthn 窗口、邮件 MFA、多网络/IP迁移或主 app 完整 UI 旅程。轮询补偿测试及已有通知模块测试覆盖离线提示语义；本卡未搭建真实网络断线注入设施。

修正并重跑的历史失败：初始 mock 缺固定版本 `organizationsNew/policiesNew` 导致协议拒绝；真实回环首轮恢复未提供 checkpoint，被正常安全拒绝，随后明确使用测试回执 stub；新增 live 测试曾使用不存在的 CipherDocument.ID，改为解密字段取 ID。全部相关检查随后通过，未把这些首轮失败计为通过。Go 字符串/RSA大整数/SDK副本受 GC 管理，不能承诺物理清零所有副本。

本卡提交供独立 Review，未自行合并。#14 负责导航、生命周期、实际存储提交与原生平台桥连接。
