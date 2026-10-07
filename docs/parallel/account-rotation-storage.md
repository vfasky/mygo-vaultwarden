# #17 账号轮换的持久恢复适配

本卡基于当前 Board main 工作树实现，未重置基线、未改主目录、恢复 ref、账号算法、组织/Send 业务或主 UI。账号合同来自 `docs/parallel/accounts.md` 与 `internal/vaultwarden/account_change.go` 的真实 `AccountRecovery` v1；桥沿用 #9 的 C ABI / 256 KiB 分块 / 64 MiB 硬上限。新增根 `account_rotation_storage.go` 和其测试属于本卡明确授权范围。按 Review 返修授权，本卡已将 `macos/Shared/AccountRecovery.swift` 注册到正式 Xcode 工程的 AutoFill Sources，补齐已编译 Shared 源的强依赖；主 app 的生产桥脚本通过 Shared glob 包含它。#14 仍负责后续业务入口/认证桥装配。

## 持久状态和兼容边界

- `AccountRecovery` 原始 JSON 字节完整保存在 AES-GCM payload 的 `accountRecovery.record` 内（base64 只是 JSON 表示，不是加密）。旧 session、旧 unlock、完整旧 VaultData、新 user key、完整服务器请求、未知扩展均留在这些原始字节中，不重新编码原记录，不进日志或公开 status。
- journal 另含 version=1、binding `{operationId, oldRevision, epoch, recordHash}`、phase 和可选独立恢复登录 `checkpoint`。SHA256 只核对字节一致性；认证由原密码包装/AES-GCM/scope 完成。journal 不给请求重放权限。
- Begin 核验认证 scope/server/account、当前 revision、旧解锁 key/config、完整旧 session 与 VaultData（sync 原字节、pendingPolicy、隔离记录），在同一个 `state.lock` 中一次原子落盘 journal+屏障，再返回专用回执。所有秘密仍只落密文；临时文件 fsync、rename、目录 fsync 均检查成功。rename 后 fsync 错误属于结果未知，**不允许 POST**，须重新认证 query。
- 屏障快照使用认证 header **format=2**，普通快照仍 format=1，外层文件仍 format=1。旧版本 `SnapshotState.validate` 只接受 header format=1，因此拒绝 pending 快照，不能静默吞掉新增 journal。新 reader 验证 header format 与加密 journal 同时存在。未识别的 payload/VaultData/journal/binding 外层字段失败关闭，不能被本 writer 重写丢失；原 AccountRecovery 和 sync 的未知字段保留原字节。更高 schema 应升级版本并失败关闭，而不是回退 writer。
- 状态只公开 `recoveryPending` 布尔值（由 header format 派生），不公开 operation/kind/material。Begin/Query/Result/Checkpoint 只能通过认证专用桥读取 journal。普通 status 不能成为授权材料。
- Begin 改 revision 和 snapshot ID，候选列表清空；旧 candidate/lease 失败。普通 publish、组织/策略恢复、saveSession、密码/Keychain解锁、secret显示/复制、logout 都拒绝屏障。Lock 可以推进 revision，但保留密文 journal；重开、超时、普通 checkpoint、其他账号/operation 的迟到结果不能清屏障。候选清理仍按现有索引服务异步完成，已交给系统的填充不能撤回；旧候选再次取密码会被拒绝。
- Recovery Result 只改变 phase：prepared → confirmed / unknown / not-dispatched，同值可重复，不能跨 phase 回退。Confirmed 也不开放旧数据。Query 不修改状态；缺记录与重复清除失败关闭，不借用另一个操作的回执。
- Verified resolve 在同一认证事务内校验完整 binding、当前 revision、显式用户确认、权威状态/全资源核验声明及新 sync 摘要，合并保留所有原 pendingPolicy/组织隔离，再写完整新 vault/session/password wrapper。先 journal 新 AES key ID，再创建新 Keychain 项；失败时旧记录/旧 key 保留。只有新快照落盘后才清 journal、撤原快照身份并退休/删除旧 Keychain 项。清理失败按原 retiredKeys 机制重试。删除账号为独立 mode=delete，只接受 kind=delete 且已 confirmed 的记录和用户明确确认，先写 tombstone 再删除 key。
- 所有输入/输出继续受 64 MiB 硬限。恢复期间同时保留全旧 vault、完整请求和新 key，JSON/base64 也有开销，因此可轮换的最大 sync 小于普通 publish 的最大 sync；超限失败关闭且零 POST。未改成明文 spool、SQLite、无限内存桥或放宽大小限制。

## Go 精确接线

```go
newAccountRecoveryStorage(state *snapshotStatus, epoch uint64,
    currentEpoch func() uint64, key []byte,
    call func(storageRequest) storageReply) (*accountRecoveryStorage, error)

(*accountRecoveryStorage).Begin(vaultwarden.AccountRecovery) error
(*accountRecoveryStorage).Query() (storageReply, error)
(*accountRecoveryStorage).Result(vaultwarden.AccountChangeResult) error
(*accountRecoveryStorage).Checkpoint(vaultwarden.SessionCheckpoint) error
(*accountRecoveryStorage).ResolveVerified(vaultwarden.SyncResult,
    userConfirmed, authorityVerified, resourcesVerified bool) (storageReply, error)
(*accountRecoveryStorage).DeleteConfirmed(userConfirmed bool) (storageReply, error)
(*accountRecoveryStorage).Close()
```

这是已编译、已运行的存储实现，不是待实现回调。`Begin` 可直接赋给 `vaultwarden.AccountRecoveryPersistence`，同步等待认证落盘回执后才返回 nil。它运行在 Session 锁内，绝不调用会再锁 Session 的方法。`currentEpoch` 必须是线程安全的 UI 生命周期读函数（例如 atomic.Load），不可访问 Session；每次桥调用前后检查，不能传永远固定返回值的占位函数。操作 journal 中 epoch 是开始时的 UI epoch；重启新 UI epoch 独立检查，Query 后仍保留原操作 binding。

#14 按下面顺序接线：

1. 从当前已认证快照建立 adapter，传实际 UI epoch、旧 snapshot unlock key 和 `callStorage`。账号 prepare 期间继续使用原 `saveSessionCheckpoint` 生命周期；如果 prepare/checkpoint 推进快照 revision，必须按最新成功回执重新建立 adapter，不能沿用先前 revision。
2. `session.CommitAccountChange(ctx, plan, confirmation, checkpoint, adapter.Begin)`。只要 Begin/回执/epoch检查失败，账号代码就不派发轮换 POST。不要因 bridge 传输结果未知自动重发 Commit 或 Begin；先关闭旧 adapter、用当前 status 定位 revision、使用旧主密码重新认证 Query 相同 operation。
3. 在当前 UI 生命周期中 `adapter.Result(result)`；它核对 result 的 scope/kind/operation/previousRevision，且永不开放旧离线许可。若 UI epoch 已改变，禁止迟到结果写入；之后通过新的恢复 UI Query 记录即可，prepared 也按未知保守处理。保存 phase 失败不会撤销开始时的恢复屏障。
4. 用户显式进入恢复流程后，关闭旧 Session（不能用 journal.OldSession 重新授权普通离线或网络操作），重新登录并完整同步。恢复登录 refresh checkpoint 用 `adapter.Checkpoint`，新 token 单独加密持久保存，绝不覆盖不可变 OldSession。恢复 Query 返回的 `storageReply.Recovery.Record/Checkpoint` 是秘密，使用完 `Recovery.Close()`；解码 `AccountRecovery` 后也调用其 `Close()`。
5. 转换/恢复层用权威服务器 wrapper 核验旧/新材料，完成全部 cipher/folder/Send/组织/紧急授权检查。partial / unknown / 无法识别字段时保留 journal，不盲重试请求，不随机再生成 key，不因 HTTP失败选旧 key，不因 HTTP成功直接选新 key。本卡提供完整恢复材料和持久状态，不重新实现 #6/#12/#13 的密码学转换算法。
6. 只有用户明确确认且上述权威核验完成，才调用 `ResolveVerified(fresh, true, true, true)`。三个参数是**可信 controller 的证明声明，不能来自 UI 任意布尔参数，也不能只因 Sync/HTTP200 就设 true**；与账号层 `AccountRotationCoverage`、已有 `AcceptAuthenticatedSnapshot` 同样，不能抵御任意恶意同进程代码。`fresh` 必须来自此次新登录的完整结果。同步数据摘要绑定该次核验到实际写入数据，scope/operation/revision/epoch另由 adapter 和 Swift CAS核对。
7. 回执成功且 UI epoch仍匹配后，用 `freshSession.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision)` 安装快照（使用桥返回的合并隔离/policy版本）。Resolve已经原子发布，不再调用普通 publish。`DeleteConfirmed(true)` 是用户确认销毁本机恢复副本的删除分支。即便 phase=not-dispatched，也不恢复旧网络会话：仍按显式新登录/完整核验路径完成。
8. Lock/account switch 必须先推进 UI epoch、撤旧 Session/UI能力，并 Close adapter；Swift lock会保留恢复记录。由于单快照模型，pending期间普通logout/账号替换被拒绝，必须显示恢复入口，不能把 busy 当作空库。

桥 operation 为 `accountRecoveryBegin/Query/Result/Checkpoint/Resolve`，请求使用已有 scope/expectedRevision/unlockKey + recoveryBinding/recoveryRecord/recoveryPhase/recoveryResolution；全部走 #9 分块协议。恢复分页也在每页检查专用 recovery lease；lock/写入使后续页失效。删除回复分页用精确 tombstone revision 核对，不能借 signedOut 丢失后续写入。

## 实测证据

全部测试使用本卡临时目录，不接触用户凭据或快照。以下命令已执行（产物/日志在 `$TMPDIR`）：

```sh
swift test --package-path macos --scratch-path "$TMPDIR/swift-build"
xcrun swiftc -emit-library -O -swift-version 5 -D SNAPSHOT_BRIDGE_TESTING -module-name SnapshotBridgeHarness -module-cache-path "$TMPDIR/swift-modules" macos/Shared/*.swift macos/Bridge/*.swift macos/Tests/BridgeHarness.swift -o "$TMPDIR/libSnapshotBridgeHarness.dylib"
xcrun swiftc -emit-library -O -swift-version 5 -module-name SnapshotBridge -module-cache-path "$TMPDIR/swift-modules" macos/Shared/*.swift macos/Bridge/*.swift -o "$TMPDIR/libSnapshotBridge.dylib"
xcrun swiftc -typecheck -swift-version 5 -module-cache-path "$TMPDIR/autofill-modules" macos/Shared/*.swift macos/AutoFill/*.swift
SNAPSHOT_TEST_HARNESS="$TMPDIR/libSnapshotBridgeHarness.dylib" go test -race -tags headless . -run 'Test(NativeAccountRecovery|AccountRecoveryAdapter|NativeLargeAuthenticatedSnapshot)' -count=1 -timeout=60s
go test -tags headless ./...
go test -race -tags headless ./...
MYGO_RECOVERY_TEST_URL=http://127.0.0.1:32798 SNAPSHOT_TEST_HARNESS="$TMPDIR/libSnapshotBridgeHarness.dylib" go test -race -tags headless . -run '^TestLiveAccountRecoveryStorage$' -count=1 -v -timeout=110s
```

- Swift75项通过，其中新增5项 recovery测试：错scope/operation/hash/revision/key/缺receipt拒绝；Begin前拒写保留原密文；独立store重开/lock/Unknown/checkpoint保留原材料；Keychain create注入失败保留旧journal/key；专用替换保留pendingPolicy/隔离、换新key、撤旧lease与旧密码wrapper、重复清除拒绝；删除必须confirmed+明确receipt；原始record未知字段保持逐字节一致。最初测试文件有字面占位及private访问级别编译错误，修正后全套通过，没有把初次失败算通过。
- 真 C ABI 回环：同一正式 Swift execute/transfer 实现，测试宏仅切换隔离目录、MemoryKeys和OS副作用。Begin→Query→Unknown→恢复checkpoint→lock/新epoch/reopen→Verified resolve→旧key拒绝/新session可用；错误operation与缺回执不采用；Go race通过。另有原5MiB完整快照回归通过。
- 真实 Vaultwarden **1.37.4** image `sha256:faa140d1177106cf8802d06e6c42e607985f7944994e5bd38e2feb5cefa17216`，独占 `mygo-recovery17-01a11755`，label `mygo.account.card=17`，127.0.0.1随机端口，`--tmpfs /data` / `--rm`，自建example.invalid账号。真实注册/登录/创建独立item-key登录条目；目录权限拒写使 `CommitAccountChange` 零POST；第一轮正常确认并持久完成；第二轮代理在服务器已响应后丢弃响应返回502，账号结果Unknown，记录与两套key仍可恢复。lock/重建adapter后重新登录完整sync，核对新session user key与journal新key一致，条目标题/密码正确，然后专用完成并安装真实认证回执。总计恰好2次轮换POST，故障无自动重试；`-race`通过。已停止独占容器，--rm清除了易失数据和测试账号。

- 最终新增 `recoveryPending` 回执核验后，以 `libSnapshotBridgeHarness-final.dylib` / `libSnapshotBridge-final.dylib` 重建两种桥，再跑包含生产C ABI分块的定向race；重新创建独占容器端口32799复跑真实故障回环，均通过并再次清理容器。`go vet -tags headless ./...`、最终全包race、`git diff --check` 均通过。

## Xcode 工程登记返修验证

本次保留 `8202cbb` 全部存储实现，仅改 `project.pbxproj` 中 AccountRecovery.swift 的 PBXFileReference、PBXBuildFile、group 与 AutoFill Sources，以及本文档。没有 Go/Swift 源码变化，因此没有重跑上一节的全量 Go/race/Swift 测试。

逐一解析实际 PBXNativeTarget/buildPhases/fileRef 清单：

- `AutoFill` 的 Sources 为 `AutoFill/CredentialProviderViewController.swift`，以及 `Shared/` 下的 `VaultCredential.swift`、`SnapshotTypes.swift`、`SnapshotFiles.swift`、`ProtectedSnapshotKeys.swift`、`SnapshotStore.swift`、`SnapshotIndex.swift`、`SnapshotPolicy.swift`、新增 `AccountRecovery.swift`。新源恰好登记一次。原有 `SecretCopyAuthorization.swift` / `SensitiveClipboard.swift` 不在扩展清单，本次不扩大登记范围；最初采用“所有 Shared 文件必须进扩展”的检查因此失败，改为检查实际依赖此类型的 target 后通过。
- `MyGoVaultwarden` 没有 PBXSourcesBuildPhase，通过 `scripts/xcode-build-go.sh` 调用 `scripts/xcode-build-bridge.sh`；后者原有 `Shared/*.swift` / `Bridge/*.swift` 包含 AccountRecovery.swift，无需新增 app Sources。

以下命令在本卡 scratch 内执行，未读取 `.local` 签名配置、未安装或运行用户 app：

```sh
# 修复前在8202cbb复现：exit 65，BUILD FAILED。
xcodebuild -project macos/MyGoVaultwarden.xcodeproj -scheme AutoFill \
  -configuration Debug -derivedDataPath "$TMPDIR/account-recovery-before" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build

# 修复后只构建实际AutoFill target，产物/中间件/模块缓存全在独立scratch。
xcodebuild -project macos/MyGoVaultwarden.xcodeproj -target AutoFill \
  -configuration Debug \
  SYMROOT="$TMPDIR/account-recovery-after/Build/Products" \
  OBJROOT="$TMPDIR/account-recovery-after/Build/Intermediates.noindex" \
  SHARED_PRECOMPS_DIR="$TMPDIR/account-recovery-after/Build/PrecompiledHeaders" \
  CLANG_MODULE_CACHE_PATH="$TMPDIR/account-recovery-after/ModuleCache.noindex" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build

# 使用未改动的生产桥脚本，验证主app的Shared glob路径。
TARGET_BUILD_DIR="$TMPDIR/account-recovery-bridge/Products" \
  CONTENTS_FOLDER_PATH=MyGo.app/Contents \
  DERIVED_FILE_DIR="$TMPDIR/account-recovery-bridge/Derived" \
  ARCHS='arm64 x86_64' MACOSX_DEPLOYMENT_TARGET=14.0 \
  CODE_SIGNING_ALLOWED=NO bash scripts/xcode-build-bridge.sh
xcrun lipo -info "$TMPDIR/account-recovery-bridge/Products/MyGo.app/Contents/Frameworks/libSnapshotBridge.dylib"
git diff --check
```

修复前错误明确为 `SnapshotTypes.swift:125/240` 找不到 `AccountRecoveryJournal`，以及 `SnapshotStore.swift:276–278` 找不到 `AccountRecoveryBinding/Resolution/Journal`。修复后真实 Xcode AutoFill **BUILD SUCCEEDED**，arm64 和 x86_64 的 `AutoFill.SwiftFileList` 均包含新源，完成两架构编译/链接并产出未签名扩展。构建仅有无 AppIntents 依赖的 metadata 提示，以及无 active architecture 时构建全部架构的提示。生产脚本成功产出 arm64+x86_64 通用桥动态库。日志分别为 `$TMPDIR/account-recovery-before.log`、`account-recovery-after.log`、`account-recovery-bridge.log`（scratch 会随会话清理）。这是真实 target 构建证据，不以 SwiftPM/glob typecheck 代替。未执行主 app 的完整 Go 构建/安装，未宣称 #14 轮换入口已经装配。

## 未验证边界

未验证：真实Keychain/Touch ID、签名App Group安装和系统AutoFill填充、OS进程kill/机器断电故障。独立store/adapter重开与写失败注入是崩溃边界的代理证据，不声称实际断电测试。真实轮换回环有一个独立item-key条目，其他资源经过真实枚举为空；非空组织/紧急/Send/legacy跨资源partial修复仍需相应转换lane和最终集成验证。新旧全部材料在未知阶段保留，未知/部分状态不允许完成，本卡不宣称能自动修复服务器非事务部分轮换。GC/Swift Data/string副本不能证明物理清零；这里只清理可控Go缓冲并按密文/Keychain提交顺序销毁持久材料。
