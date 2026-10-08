# #38 跨账号恢复记录、目标阻断与 runtime 原生短许可

本卡仅在 Board 工作树实现独立存储接缝。没有修改主 controller、main/UI/network/login、session_storage.go、账号轮换算法或 Go runtime_secret.go。RuntimeSecret 与专用目标本机认证是协调者在本卡运行期间明确追加的范围。#14 负责真实 Session proof、网络/权限/reprompt、用户确认、生命周期回执采用及最终业务接线；本卡不宣称主应用入口已经装配。

## 持久合同

输入是 `internal/vaultwarden/account_recovery_plan.go` 的真实 RecoveryDispatch / RecoveryOperationResult。管理员没有目标 oldSession/oldUnlock。记录保存原 dispatch JSON 字节及其 SHA256 `summaryHash`，它是不可变操作描述摘要，**不是请求 bodyHash**。原生核对 operationId、actor、target、描述、AuthorizationEpoch、hostEpoch、开始时真实 storageRevision；PreviousRevision 保存在不可变描述中，由 #12 的 Session guard 验证。它不能被冒充成原生快照 revision。

`SnapshotState.format=2` 新增独立 AES-GCM `targetRecovery` 容器（version=1），最多 1024 条记录、4 MiB 密文，单描述最多 32 KiB；operationId 32 个小写十六进制字符，摘要 64 个。所有 email、影响说明、操作、核验证据摘要、保护投影均在密文内。只公开 `targetRecoveryPresent` 布尔值；它表示容器存在，包含 resolved 历史，不表示尚有未决操作。认证 Pending/Query 返回具体记录。未知 schema、密文损坏、缺 key 均失败关闭，不当成空库。

元数据使用独立 Keychain service `yz.sh.mygo-vaultwarden.target-recovery-v1`，`WhenUnlockedThisDeviceOnly`、不同步。它只能解密操作/保护元数据，不能解密/包装 vault 密钥。原 vault Keychain 项仍要求 userPresence；没有创建旧 vault 的非认证后门。logout 删除旧 vault key，但保留元数据 key 和容器。首次创建 metadata key 后磁盘写失败可能留下只有元数据用途的孤立 key，下一次重用；不会遗留新 vault 能力。已完成记录目前也不自动清除；达到上限拒绝新增，不静默淘汰未决操作。

所有状态变更在同一个跨进程 state.lock 内完成，临时文件 fsync→rename→目录 fsync 后才成功。Begin 一次写入记录和目标屏障；fsync/桥/生命周期/回执未知都返回错误，BeforeDispatch 因此零 POST。不能自动新建操作或重发请求；重新认证 Pending→Select→Query 同一操作。修复了普通 publish 在最终 rename/fsync 未知后按旧 write-ahead journal 删除新活跃密钥的窗口：一旦尝试最终提交，catch 不使用旧 journal 删除可能已经提交的 key。

旧 reader 只接受外层 format=1，看到本卡格式会拒绝，不能忽略目标屏障继续写。普通 publish/lock/checkpoint/logout 保留整个容器。自目标 Begin 轮换 snapshot ID、清空候选但保留加密 vault/现存 #17 journal；foreign target 不改 actor snapshot ID/内容，NoLocalTarget 只陈述本机单快照是否属于目标。元数据写仍推进全局存储 revision，因此旧全局 CAS lease 需要按新回执刷新；它不是清空/冻结 actor。format=2 索引使用 revision 作为提交 token，实际 credential recordID 仍绑定 snapshot ID；旧异步索引写不能越过目标 clear。目标的密码解锁、Keychain解锁、secret/candidate lease、session checkpoint和普通 publish都被拒绝，无关 actor 可继续认证读取/发布。

phase 为 prepared / confirmed / unknown / not-dispatched / verified / resolved。Result 依据 IsolationAttempted/Dispatched/Confirmed/Unknown 转换，不能从 HTTP 错误推断回滚；confirmed 也不解除屏障。UI关闭或迟到 Result 保留 prepared 即可查询。不重放网络。

## Go 接口（均已实现）

```go
newTargetRecoveryStorage(state *snapshotStatus, hostEpoch uint64,
    currentEpoch func() uint64, actorUnlockKey []byte,
    call func(storageRequest) storageReply) (*targetRecoveryStorage, error)

newTargetRecoveryRuntimeStorage(state *snapshotStatus, hostEpoch uint64,
    currentEpoch func() uint64, authority targetRecoveryRuntimeAuthority,
    call func(storageRequest) storageReply) (*targetRecoveryStorage, error)

newTargetRecoveryLoginStorage(state *snapshotStatus, hostEpoch uint64,
    currentEpoch func() uint64, fresh vaultwarden.SyncResult,
    evidence targetRecoveryVerification,
    call func(storageRequest) storageReply) (*targetRecoveryStorage, error)

(*targetRecoveryStorage).Begin(vaultwarden.RecoveryDispatch) error
(*targetRecoveryStorage).Result(vaultwarden.RecoveryOperationResult) error
(*targetRecoveryStorage).Receipt() *snapshotStatus
(*targetRecoveryStorage).Pending() (storageReply, error)
(*targetRecoveryStorage).Select(targetRecoveryRecord) error
(*targetRecoveryStorage).Query() (storageReply, error)
(*targetRecoveryStorage).StageVerified(vaultwarden.SyncResult, targetRecoveryVerification) (storageReply, error)
(*targetRecoveryStorage).ResolveVerified(vaultwarden.SyncResult, targetRecoveryVerification) (storageReply, error)
(*targetRecoveryStorage).InspectLocalTarget() (storageReply, error)
(*targetRecoveryStorage).ResolveVerifiedWithLocalAuthentication(vaultwarden.SyncResult, targetRecoveryVerification) (storageReply, error)
(*targetRecoveryStorage).Close()
```

Begin 可以直接作 RecoveryBeforeDispatch，不调用任何 Session 公共方法或读取 app 可变字段。currentEpoch 必须是线程安全实际生命周期读函数。`Receipt()` 是最近成功原生回执的独立副本；失败/未知原生调用清除回执。#14 在 Begin 成功后、callback 返回 nil 之前，通过线程安全 host 接缝采用原生 revision。不能把缓存的旧 status 当成成功回执。runtime actor 与持久 target 可能不同：此时回执 Scope 仍是本机 target，**不能把该 revision/scope 当成 actor Session 的快照授权**。它只是存储 CAS 回执。

普通工厂要求当前确实有 actor 快照及其密码 wrapper key。临时在线 actor 用 runtime 工厂，传 `targetRecoveryRuntimeAuthority{Scope,Generation,DeadlineUnixMS,LeaseID,OperationID,SummaryHash}`；原生验证实际活跃的 purpose=recovery lease，且 op/summary 精确相等。该工厂不使用虚假的 actor unlock、旧持久账号的授权或 bool。记录 NoLocalTarget 根据真实持久 snapshot 的 scope 计算。runtime 校验在落盘前后执行，期间撤权/过期会保留 prepared 并报错，不能 POST。

失去旧快照（如 logout）后，用经过新登录和完整核验的 Login 工厂查询自己的记录。它的 fresh 数据及 evidence 只授予恢复查询/完成权限，不授予普通离线 lease，不自动发布缓存。Pending 返回认证可见记录；Select 会再次向原生 Query 核验，不能直接相信 UI 提供的记录。原 binding.HostEpoch 是开始时的生命周期，重开 adapter 的 currentEpoch 独立校验。Close 清理可控缓冲；`targetRecoveryRecord.Close()` 清描述缓冲，若 Inspect 返回 `Recovery` 则还须调用既有 `Recovery.Close()`。

`targetRecoveryVerification` 是可信 controller 从本次实际新认证/完整sync派生的证明摘要：AuthorityHash、KeyHash、MembershipHash、MFAHash、ConfirmationHash、AuthenticationEpoch。即便某维度不适用，也应散列明确核验出的不适用结果，不能塞常量冒充核验。storage不会证明服务器真实状态、读取他人 vault、替代 #12 密码学/成员权限检查或把 HTTP200 当作证明。证明与实际新 vault.sync/session/unlock 摘要、binding、target 和本次 expectedRevision 持久绑定。它不能抵御任意恶意同进程代码，#14必须保持证明构造入口属于可信 controller。

## Resolve、本机旧目标及并存屏障

自目标 Resolve 原子发布 fresh snapshot，并保留既有 pendingPolicy/组织隔离。另一个 actor 当前缓存存在时，Resolve 只写 verified 及其证明，不覆盖 actor；之后该 target 发布必须精确匹配已核验 vault/session/unlock 三个摘要才能原子标记 resolved。普通 publish 无权放开 prepared/unknown/confirmed 屏障。

多个操作可指向同一目标。先对每个操作 `StageVerified`；它只保存证明，仍拒绝普通目标 lease。只有所有相关未决操作都分别验证并绑定相同 fresh 材料，最终目标发布才能完成这些 verified 记录。其他 target 的记录及 #17 journal/policy 不会被顺便清除。缺一个证明时不会部分清屏障。

runtime actor 可以在本机 snapshot 属于 foreign target 时记录+阻断，不解密或伪造 target 旧材料，原密文保留。由于不能盲丢其中未知保护，尚未读取保护投影的这种 blocked target logout 会 busy；可以走专用本机认证恢复，非永久不可用。普通已认证 self Begin 会把现有 policy/组织隔离投影加密保存进记录，因此 logout 后删除旧 vault key仍不会丢这些限制，fresh恢复时合并投影。

`InspectLocalTarget` 和 `ResolveVerifiedWithLocalAuthentication` 是用户显式选择的恢复动作，**不得在 BeforeDispatch 或 Session 锁内调用**。它们读取既存 target 的 userPresence Keychain AES key，认证全部密文并在对话框前后核对 revision/snapshot ID/op/target；对话框不持文件锁。Inspect 只返回保护投影，以及若存在则返回原 #17 AccountRecoveryJournal所需材料，不返回普通旧session/vault或离线lease。Local Resolve在原生内部使用该 AES key合并旧保护、发布已验证的新target，然后退休旧key；AES key不返回Go。取消、缺key、密文损坏、错误scope/revision均保留屏障。

如现存 #17 AccountRecoveryJournal 未解决，Local Resolve返回 `account_recovery_pending`；不得用fresh sync吞掉它。Inspect允许用户认证后取得原journal，#14必须先走#17独立算法/核验。#17专用完成仍保留target屏障，只返回恢复回执和空候选；最后再完成target。Keychain成功只说明旧本机材料可读，绝不是远端恢复完成证明。

## runtime 短许可 C ABI

独立源 `macos/Shared/RuntimeSecretBridge.swift`，不读取/写入快照、Keychain或系统AutoFill。生产主线程短调用，没有同步dispatch/main等待；不在主线程返回 `wrong_thread`。#14的Go Session proof和调用绑定仍归其owner。符号：

```c
int32_t mygo_runtime_secret_execute(const uint8_t *request, intptr_t requestLength,
                                   uint8_t *output, intptr_t capacity);
```

输入UTF-8 JSON，operation=`activate|authorizeDisplay|copy|revoke`；必需字段 `purpose` (`secret|recovery`)、`scope{server,account}`、`generation`(UInt64)、`deadlineUnixMS`(Int64)。activate不带leaseID；recovery用途额外带 `operationID` 和 `summaryHash`。其他调用精确带回 `leaseID`、原deadline、scope/generation/purpose以及recovery绑定字段。copy额外带UUID `requestID`和`secret`。回执 `{ok,code,leaseID?,generation?,deadlineUnixMS?}`。输入最多96KiB；输出capacity必须1024…96KiB；返回正数为实际长度，-1非法buffer，-2编码/容量失败。指针不逃逸、不在原生保留secret正文；Go负责清输入输出缓冲。

单进程最多一个secret lease和一个recovery lease，同一generation可以各持一个用途。新generation必须单调递增，且使旧许可失效；相同generation的重复activate只返回同一个不可猜256bit leaseID、不能改scope/deadline/op/summary，不延长期限。该用途一旦撤销/过期，同generation不能重激活；取得新的真实授权后由host提升generation。deadline必须在未来30秒内，Go必须取实际授权、令牌、reprompt有效期的最短值。原生同时使用wall与固定monotonic上限，墙钟回退不会续权。

AuthorizeDisplay/Copy只接受secret用途；recovery用途不显示/复制秘密，也不单凭secret许可授恢复写权。recovery在native只用于绑定存储操作，本身不授远端/离线权限。copy每lease最多64个requestID、秘密最多65536 UTF-8字节；同ID同值重试不重写剪贴板，同ID异值拒绝。撤销/超时只清本lease仍拥有且changeCount+随机owner一致的内容，不抹用户后续复制或另一lease内容；重复revoke/迟到请求返回invalid_lease且不产生副作用。显示隐藏/清理仍归Go；不声称物理擦除、撤回已被外部读取或填入系统的密码。系统pasteboard无跨进程原子compare-clear，现有双重changeCount检查仅是最佳努力。

## 验证与限制

全部临时目录/模块缓存/构建产物位于本卡 `$TMPDIR`。Swift测试使用MemoryKeys/私有假clipboard；C ABI harness宏只替换真实OS副作用、允许测试线程同步调用，实际execute/存储/传输/lease状态机仍是真实实现。没有读取用户真实Keychain、密码库、app/watch或运行容器，没有触碰用户剪贴板。

已执行：

```sh
swift test --package-path macos --scratch-path "$TMPDIR/target-swift-build"
xcrun swiftc -emit-library -O -swift-version 5 -D SNAPSHOT_BRIDGE_TESTING \
  -module-name SnapshotBridgeHarness -module-cache-path "$TMPDIR/target-swift-modules" \
  macos/Shared/*.swift macos/Bridge/*.swift macos/Tests/BridgeHarness.swift \
  -o "$TMPDIR/libTargetRecoveryHarness.dylib"
SNAPSHOT_TEST_HARNESS="$TMPDIR/libTargetRecoveryHarness.dylib" go test -race -tags headless ./...
xcodebuild -project macos/MyGoVaultwarden.xcodeproj -target AutoFill -configuration Debug \
  SYMROOT="$TMPDIR/target-xcode/Products" OBJROOT="$TMPDIR/target-xcode/Intermediates.noindex" \
  SHARED_PRECOMPS_DIR="$TMPDIR/target-xcode/PrecompiledHeaders" \
  CLANG_MODULE_CACHE_PATH="$TMPDIR/target-xcode/ModuleCache.noindex" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO REGISTER_APP_WITH_LAUNCH_SERVICES=NO \
  ARCHS='arm64 x86_64' ONLY_ACTIVE_ARCH=NO build
TARGET_BUILD_DIR="$TMPDIR/target-production/Products" CONTENTS_FOLDER_PATH=MyGo.app/Contents \
  DERIVED_FILE_DIR="$TMPDIR/target-production/Derived" ARCHS='arm64 x86_64' \
  MACOSX_DEPLOYMENT_TARGET=14.0 CODE_SIGNING_ALLOWED=NO bash scripts/xcode-build-bridge.sh
xcrun lipo -info "$TMPDIR/target-production/Products/MyGo.app/Contents/Frameworks/libSnapshotBridge.dylib"
xcrun nm -gU "$TMPDIR/target-production/Products/MyGo.app/Contents/Frameworks/libSnapshotBridge.dylib"
```

Swift全套89项通过，新增8项target恢复测试与3项runtime测试。覆盖self/foreign/no-local/未知目标邀请、同op幂等与异绑定拒绝、缺key/未知版本/损坏/目录拒写、lock/logout/reopen、缺证据、多操作逐一核验、准确目标失效及actor继续可用、#17 journal并存、policy/隔离保留、runtime foreign旧wrapper不可解→本机认证取消/成功、旧key拒绝、短许可重复/限量/过期/墙钟回退/错误用途/代际/剪贴板ownership。真实C ABI+Go race覆盖目标生命周期、目录拒写回调失败、无旧actor快照runtime授权、foreign本机认证Resolve和原生runtime四操作；全包race通过。不是用mock/typecheck代替桥执行。

实际Xcode AutoFill Sources登记TargetRecovery、TargetRecoveryLocalAuthentication及其RuntimeSecret/SensitiveClipboard依赖；正式工程两架构编译链接成功。生产桥脚本Shared glob自然包含新源，lipo确认x86_64+arm64，nm确认mygo_runtime_secret_execute和mygo_snapshot_execute。关闭签名与LaunchServices注册，未安装/运行app。

初期出现并已修复的验证失败：SyncResult指针层级编译错误、Swift测试DTO let字段及投影变量遮蔽编译错误、C ABI MemoryKeys元数据读取错误；组合命令一次触及60秒工具时限，后续独立全包race命令成功。没有将失败/超时当成通过。

未实测：真实Touch ID/Keychain交互与取消、系统剪贴板、已签名AppGroup/系统AutoFill、机器断电、真实服务器恢复和#14最终UI/Session接线。本机认证取消是MemoryKeys注入，磁盘失败是隔离目录权限注入；它们不等同实际断电。AES/JSON和Swift/Go可控缓冲尽量清理，不能证明所有语言运行时副本物理清零。磁盘全历史回滚/主动删除整个存储及Keychain并非本协议提供的防回滚保证。
