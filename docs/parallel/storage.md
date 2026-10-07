# #9 大库离线存储与有界桥交接

基线：`14bbaf0ec2f176c598560883cc895f4dcd24405d`。仅本 Board 分支按卡片授权 reset；未改主工作区、recovery ref、账号/Session/Send/组织业务、UI、MyGo 或构建配置。未引入 SQLite/SQLCipher。

## 完成的接口与部署要求

保留 `storageRequest` / `storageReply` 的 JSON schema、Go `nativeStorageCall`、C 符号 `mygo_snapshot_execute` 及旧的 4 MiB 单次 ABI。新的 Go `boundedStorageCall(input, frameCall)` 将发布、显式恢复、隔离、checkpoint、解锁、reindex 封装为多个有界调用。业务调用方不需分页，不需新注册；Go 和 Swift 动态库必须一起更新。旧桥收到分块操作会拒绝，**不能自动重试发布或静默降级到旧整包路径**。

控制操作 `status/settings/lock/logout/retryCleanup/clearSecretClipboard/copySecret/authorizeSecretDisplay` 保留直接 ABI，尤其 lock/logout 不等待传输互斥锁，因此可撤销正在认证或下载的数据。原应用生命周期/epoch 验证仍由最终集成保持。

新传输实现位于已有 `macos/Shared/SnapshotFiles.swift`，不需要 pbxproj 新源登记；生产 bridge 与 AutoFill 已直接编译全部 Shared 源验证。新增 `BridgeHarness.swift` 只在显式 `-D SNAPSHOT_BRIDGE_TESTING` 的测试动态库中生效；生产配置没有测试环境变量路径、MemoryKeys 或系统副作用跳过入口。

## 分块 ABI 与限值

所有帧仍通过同一 C 符号，JSON `operation` 为 `__transfer_v1`。示例（摘要需实际计算，不是授权证明）：

```json
{"operation":"__transfer_v1","action":"begin","total":5242880,"digest":"64位小写SHA256十六进制"}
{"operation":"__transfer_v1","action":"append","handle":"返回的UUID","offset":0,"data":"base64页"}
{"operation":"__transfer_v1","action":"finish","handle":"返回的UUID"}
{"operation":"__transfer_v1","action":"read","handle":"返回的UUID","offset":0}
{"operation":"__transfer_v1","action":"cancel","handle":"返回的UUID"}
```

- 原始每页最多 256 KiB；Go 为帧响应分配 512 KiB，页 JSON/base64 小于该限值。原 ABI 的 4 MiB 参数检查未增大。
- 请求/响应各最多 64 MiB；每进程仅一个活动或正在执行的传输。取消正在执行的事务后，直到其 executor 返回前也不能开始另一个，避免反复取消堆积大缓冲。
- 自 begin 起单调时钟 60 秒绝对寿命，不按页延长。独立 timer 撤销句柄；下一次访问也检查过期。执行输出的认证 lease 另外受 60 秒及当前版本约束。
- `begin` 返回随机 UUID，只是同进程传输 capability；没有认证能力。`append` 必须严格连续，越界/重复/乱序/缺页/错摘要均在业务 executor 之前拒绝，并销毁该句柄。未知句柄不撤销另一个合法句柄。
- `finish` 只执行一次；完成后返回响应字节数和 SHA256。`read` 也严格连续，末页消费后销毁句柄；失败、取消、重复读取、过期都不能重放。Go 汇总后检查长度和响应摘要，并清理可控帧/结果缓冲。
- SHA256 用于发现传输完整性差错，**不是认证 MAC**。认证仍由原始密码包装/Keychain、AES-GCM、scope/revision/snapshot 验证完成；不信任上传摘要授许。
- 只有原有白名单业务操作可以在 finish 执行。错误回复不含秘密；成功输出每页通过原认证回执建立的 `SnapshotLease`，在 `state.lock` 内核对相同 revision、snapshot ID、scope 和到期时间后复制页面。刷新、锁定、登出或另一进程替换会使后续页失效。Go 从不采用不完整响应。
- 传输不接收路径、文件描述符、外部句柄或文件名，不落明文 spool；进程崩溃直接丢失内存句柄。重新打开存储只能从已原子提交的 AES-GCM 密文恢复。

状态机：`begin → uploading → finish/executing → downloading → consumed`。任何本句柄协议错误进入 revoked；cancel/expiry 在所有阶段撤销。执行期间释放传输锁，不阻塞取消或直接 ABI 撤销。执行结束后若已取消，丢弃回复；不能承诺取消已完成的原子发布会回滚，因此调用方必须刷新并重新认证，不自动重发写操作。

## 存储与迁移

AES-GCM envelope、header AAD、主密码包装、Keychain userPresence 和 App Group 均沿用。存储状态格式仍为1；vault v1/v2/pendingPolicy、URI.sourceIndex、安全候选过滤及旧格式迁移规则不变。没有新的弱化候选兜底。普通 sync 继续合并旧认证 pending/隔离记录；专用恢复仍需要原完整记录。

为支持原有最高32 MiB原始 sync的base64及AES envelope开销，状态密文文件上限由16 MiB变为96 MiB，认证明文 payload限制64 MiB；header候选仍最多10000，sync ciphers仍最多100000，session仍64 KiB。传输中的全库与最小AutoFill凭据是不同字段：主应用认证可返回完整vault/session；独立AutoFill默认lease只有过滤后的凭据，不返回vault/session。当前仍是一个加密payload，AutoFill解密会临时解析完整vault以检查策略，**不是按需磁盘解密或恒定内存分页存储**。

新二进制仍读旧小快照；旧二进制会拒绝超过其16 MiB限制的新文件，回退旧版本不受支持。旧payload无vault或来源索引时继续按原规则失败关闭候选，成功新sync才迁移。显式空credentials保留 `[]`，会真正替换旧候选；附件仍走独立文件通道，不放入该桥。

`SnapshotFiles` 继续 O_NOFOLLOW/普通文件限制、0600临时密文文件、fsync/原子rename/跨进程flock。错误帧不进入发布；文件写入被拒绝时保留已有密文，不能被当作空库。原 Keychain journal 与未知提交结果边界未改变。进程重开不恢复旧内存lease；独立store必须重新认证。

## 可复验验证

以下命令均在本Board树执行，产物在 `$TMPDIR`，没有真实Keychain/用户快照/系统候选/剪贴板写入：

```sh
swift test --package-path macos --scratch-path "$TMPDIR/swift-build"
xcrun swiftc -emit-library -O -swift-version 5 -module-name SnapshotBridge -module-cache-path "$TMPDIR/swift-modules" macos/Shared/*.swift macos/Bridge/*.swift -o "$TMPDIR/libSnapshotBridge-final.dylib"
xcrun swiftc -typecheck -swift-version 5 -module-cache-path "$TMPDIR/swift-modules" macos/Shared/*.swift macos/AutoFill/*.swift
xcrun swiftc -emit-library -O -swift-version 5 -D SNAPSHOT_BRIDGE_TESTING -module-name SnapshotBridgeHarness -module-cache-path "$TMPDIR/swift-modules" macos/Shared/*.swift macos/Bridge/*.swift macos/Tests/BridgeHarness.swift -o "$TMPDIR/libSnapshotBridgeHarness-final.dylib"
SNAPSHOT_TEST_BRIDGE="$TMPDIR/libSnapshotBridge-final.dylib" SNAPSHOT_TEST_HARNESS="$TMPDIR/libSnapshotBridgeHarness-final.dylib" go test -race . -run 'Test(StorageTransfer|NativeStorage|NativeLarge|KernelExecutablePath|SaveSession|Snapshot)' -count=1 -timeout=45s
go test . -count=1
/usr/bin/time -l swift test --package-path macos --scratch-path "$TMPDIR/swift-build" --skip-build --filter 'SnapshotStoreTests.testLargeVaultIndependentStoreCheckpointAndEmptyReplacement|SnapshotTransferTests'
```

- Swift全套70项通过：新增5 MiB分块双向回传、坏摘要/缺页/重复/乱序/过大页/资源上限/foreign handle/过期/取消执行期间禁止再开/读取重放与撤销。
- 新增10 MiB sync实测密文超过原16 MiB上限；发布→独立store主密码解锁→session完整恢复→独立AutoFill候选→token轮换→旧分页lease拒绝→锁定→重新解锁→空库替换与旧key撤销。文件拒写测试通过且原成功密文完全不变。
- 原有MAC/header/wrapper篡改、错误scope、Keychain取消、候选版本、并发store CAS、文件symlink、旧schema/sourceIndex、pendingPolicy普通sync/checkpoint保留及专用恢复测试继续通过。
- Go race含真实生产动态库5 MiB上传并在非业务操作处安全拒绝（不访问系统容器），以及测试配置动态库的5 MiB完整sync双向发布/密码解锁/session恢复/错key拒绝/checkpoint/lock迟到拒绝。测试配置只替换容器、Keychain和OS副作用，分块及Bridge执行业务代码与生产共用。
- 首次认证桥测试因headless测试进程没有AppKit主线程循环，在lock的系统剪贴板清理等待而超时；测试配置隔离该系统副作用后，以上显式45秒timeout的race命令通过。没有将首次超时报为通过。
- 内存指标：第一次10 MiB store+5 MiB分块选定测试 `/usr/bin/time -l` 报最大resident set 363085824 bytes，约346 MiB。包含测试进程与夹具，不是64 MiB最大负载的峰值保证。传输保留数据有硬界限，但JSON/base64/CryptoKit/Swift与Go副本仍可使RSS高于单缓冲上限；未做32 MiB满sync的稳定RSS基准，不宣称常数内存。

没有验证签名安装、真实Touch ID/Keychain、Safari/系统AutoFill填充、真正断电/进程kill故障或跨独立OS进程压力；重开、多store并发、flock及注入失败是自动化代理证据。主应用生命周期接线仍由集成保持。端到端平台运行不能由typecheck代替。

## AccountRecovery后续适配（协调者确认独立卡）

**AccountRecovery轮换journal尚未落地，交后续适配卡，不能用现有普通publish当同等恢复保证。** 不新增猜测的payload字段、generic写入旁路或自动清除屏障。轮换生产功能必须等待账号#7的确切types、完整对象转换器和后续存储适配完成。

可扩展的受信事务位置是 `SnapshotStore` 现有 `files.locked` 范围：比较expected revision/scope，解包当前快照密钥，打开认证payload，验证旧屏障，生成完整新认证payload并原子写入，返回同revision/snapshot/scope的lease；桥在withCurrentLease中回执。后续需专门定义 begin/query/complete/未知结果保留/显式恢复及清除协议，并使普通publish/saveSession/reader保留或尊重屏障。旧session/解锁材料/完整vault/newkey/完整待发请求只能进入认证加密payload，写前失败必须零轮换HTTP；现有通用publish接口本身不提供这些保证。
