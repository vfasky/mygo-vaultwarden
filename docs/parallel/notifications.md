# #11 设备授权与通知模块交接

协议基线：Vaultwarden **1.37.4**，commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`。核对 [accounts.rs](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/core/accounts.rs) 和 [notifications.rs](https://github.com/dani-garcia/vaultwarden/blob/7c188967e7a467b19b2757bc3326f9cf3ccae327/src/api/notifications.rs)，并实测独有 loopback Docker。只新增卡片前缀文件；未改 main/network/client.go、公共 Session、存储、账号、Send、Swift、go.mod。复用已有 `golang.org/x/net/websocket`。

## 设备与授权请求

- `Session.Devices/CurrentDevice` 使用当前认证 scope；`RegisterDevicePushToken` 只登记当前 Session 的 deviceIdentifier；`ClearDevicePushToken(..., confirmed)` 必须显式确认。PUT clear-token **不是登出/撤销会话**；服务端可能清除相同 identifier 跨账号的推送登记，push 关闭时可能成功但无动作。没有实现 APNs 或推送 relay。
- 所有认证操作沿用 `beginOperationLocked`、`authenticatedLocked` 的 Close 取消、scope 检查、refresh/checkpoint 和不重试写请求规则。只读列表不要求离线 vault lease；**释放 user key 的审批必须使用经 `AcceptAuthenticatedSnapshot` 安装的 vault**，并在 GET/PUT 前验证相同 epoch/revision。刷新使审批失效，由集成重新同步并重建 UI。
- `Client.BeginAuthRequest` 生成独有 2048 位 RSA 公私钥与 32 字节随机 accessCode。1.37.4 要求设备 identifier/type 已注册；不是无条件首次设备登录入口。临时句柄最多 5 分钟，绑定传入 ctx；`Close` 先取消请求再清理引用。没有持久化临时私钥、code 或明文 user key。
- `PendingAuthRequest.Poll` 只返回审批元数据；访问 `/response?code=...`，错误不会携带 URL/code/server body。诊断 String/GoString 隐去句柄秘密。`TakeUserKey` 核对请求 ID/公钥/批准状态，解包 type 3 RSA-OAEP-SHA256 user key，只可成功消费一次；返回的字节由调用者负责 clear。它**不安装会话/存储，不取代已有登录和快照认证流程**。Go 字符串/RSA 大整数由 GC 回收，不能承诺所有复制品物理清零。
- `AuthRequests(pending=false/true)`、`GetAuthRequest` 对应列表/待处理/单项；`RespondAuthRequest` 在写前重新读请求。批准必须 `confirmed=true`，且传入请求设备经带外核对的完整公钥。仅把服务器返回的公钥直接当成可信公钥是错误集成。服务器已批准请求拒绝重复审批；拒绝发送空包装密钥，服务器会删除请求。不会发送主密码 hash。
- `DevicePanel` 是独立 MyGo 原生 UI，显示设备、请求来源/IP/时间、公钥 SHA-256 指纹；批准必须先点击“已在请求设备核对完整指纹”，再确认批准；拒绝也需打开具体请求后确认。推送清除有单独危险确认、结果和未知结果状态。面板未挂到主 app；发起端 API 已有，完整跨设备登录 UI/会话安装留最终集成，不能把 API 测试当成实际用户跨设备操作已完成。

## Start / Stop / callback 契约

认证：`session.StartNotifications(lifecycleCtx, scope, checkpoint, callback)`。

匿名：`pending.StartNotifications(lifecycleCtx, expectedScope, callback)`。匿名 hub 的 token 是请求 UUID，**不是 accessCode**。当前接口要求已知 expectedScope（既有账号的设备审批）；不提供未知账号身份发现，也不能把匿名消息当成批准证明。

返回 `NotificationStream`：`Stop()` 立即取消，可从 callback 调用；`Wait()` 等待退出，**不得在本 stream 的 callback 内调用 Wait**；退出后 `Err()` 给出终止原因（主动取消为 ErrCancelled）。认证准备/checkpoint 失败及 callback 错误终止 stream；传输/协议错误进入重连。业务 callback 串行执行，必须遵守 context。任何不遵守取消、无限阻塞的 callback 都会阻碍 Wait，不能由 socket 层强行终止。

最终集成必须：

1. 在认证存储提交且 Session/scope 就绪后建立一个生命周期 ctx。为通知 callback 和 `DeviceHost.Check` 捕获账号、应用 epoch、解锁状态；设备面板还要捕获当前认证存储 revision。`Dispatch` 只能通过 `window.Update` 投递 UI 任务。
2. `NotificationSync` 只触发已有 `SyncWithCheckpoint` → 受信存储发布/lease 回执 → UI 安装流程；**在发布和 UI 更新处再次核对当前 lease**。通知没有任何 vault 内容可拼接。重复、乱序通知都按安全重读提示处理，可以由集成已有同步队列合并。
3. `NotificationAuthRequest/AuthResponse` 触发 `AuthRequests` 或匹配 pending 的 `Poll`；匿名通知必须再次轮询。`RequestID` 只能用于关联请求，不能证明请求已获准。
4. `NotificationLogout` 在发出 callback 前已关闭该 Session，取消网络认证能力。callback 仍必须核对应用的账号/epoch 再撤销对应存储/UI；**不要因 Session 已 closed 就跳过应用登出**。其 scope 不允许影响后来切换的账号。
5. lock/logout/账号切换/替换 Session **先 cancel lifecycleCtx、Stop stream、Close DevicePanel/PendingAuthRequest，再撤销/更换存储及 Session**。Session.Close 也使 socket 的每秒检查失败；每个消息交付前检查当前 token/账号。旧 token 的迟到消息不会交付，新连接重新取得当前 token。已交给 callback 的工作仍必须由集成 lease 在提交边界拦截。
6. 关闭后在非 UI callback 工作线程 `Wait()` 回收 goroutine。解锁只能由原有用户认证流程发起，再创建新的 panel/stream；通知不会后台解锁。存储 `docs/parallel/storage.md` 的 revision/snapshot/scope lease 与 checkpoint 回执继续有效，没有新增通用存储写入旁路。

## 传输边界

直接连接 `/notifications/hub` 或 `/notifications/anonymous-hub?token=UUID`；**无 negotiate 猜测请求**。认证 bearer 置于 Authorization header，不进 URL。沿用规范化 server 与子路径，只允许 TLS 或已有 loopback HTTP 例外；不跟随重定向。握手文本 `{"protocol":"messagepack","version":1}\x1e`，检查 `{}` + RS 回复；之后只收 binary（含延续帧）。

SignalR 7-bit 长度前缀与 MessagePack 分别解码，支持一个 websocket 帧中多个消息和跨帧消息；64 KiB 单帧/消息、64 KiB+5 累积缓冲、5 字节长度前缀、12 层深度、4096 节点、2048 map entries。拒绝非规范长度、重复 map key、未知标签、非法 UTF-8、尾部数据和超限；时间戳扩展只跳过，不作为排序/授权依据。1.37.4 目标 `ReceiveMessage` 与拼写 `AuthRequestResponseRecieved` 精确匹配，payload 账号不匹配即拒绝，logout 必须匹配 UserId。组织通知允许 nil UserId，仍仅触发连接已绑定账号的完整同步。

15 秒主动 SignalR ping，5 秒写超时、45 秒读超时、10 秒握手超时、15 秒连接超时，标准 websocket ping/pong 由已有库处理。重连采用 1–2 秒起、最高 16–32 秒随机抖动退避；每次拨号前及订阅成功后各要求一次恢复同步/轮询，覆盖停线漏消息和先读后订阅窗口。websocket 不可用时也在重试间隔要求安全重读；没有猜测服务器消息序号或直接应用增量 vault。恢复提示 `Reconnected=true` 也用于首次连接，并非证明此前已有连接。

## 已执行验证

- `go test -race ./internal/vaultwarden . -count=1 -timeout=120s`：完整两包通过。
- `go test ./internal/vaultwarden -run '^$' -fuzz '^FuzzNotificationDecoder$' -fuzztime=10s -parallel=2`：353213 次执行通过，未发现 panic。
- `MYGO_VW_NOTIFICATION_TEST=1 go test -race ./internal/vaultwarden -run '^TestDeviceNotificationLive1374$' -count=1 -v -timeout=150s`：实际 1.37.4 设备列表/当前设备/推送登记与清除路由，auth create/list/pending/get/poll/approve/RSA key/reject，认证 hub 文件夹更新、auth 请求/响应，匿名 hub 响应通过。只注册 example.invalid 随机账号；volatile 容器只发布 127.0.0.1 随机端口；清理先核对完整 ID 的唯一 `mygo.fixture` label 再 rm。结束 `docker ps -a --filter name=mygo-notification- ...` 无残留。
- 单元/race：1.37.4 结构向量、固定 ping 二进制向量、每字节截断、畸形/深层/超大长度/重复 key、跨账号/错误请求 ID、文本帧/超大实际 websocket 帧拒绝、分片/重复/倒序只发重读提示、断线恢复、服务端 logout 关闭 Session、旧 token 迟到载荷丢弃、Stop/Close 取消 HTTP/socket、未确认与错公钥零写入、批准 user key 单次解包、重复批准拒绝、原生 UI 确认/取消/关闭和迟到结果不复活、未知写入结果提示。
- 首轮定向测试曾发现 closed Session Start 未立即拒绝；已加入 active guard 后重新通过，没有把失败报为通过。

未验证真实 APNs/推送 relay、真实双设备用户核对、主 app 生命周期注册、生产签名安装、最终存储 UI 端到端，以及跨设备完成登录 grant。回环推送接口通过不证明系统通知交付；模拟服务器 logout 和重连测试不替代真实生产撤销行为。实际1.37.4测试未调用真实 logout 端点。心跳/超时参数有实现，未用45秒实墙时间跑全部超时组合。独立 Review 仍是合入前必需步骤。
