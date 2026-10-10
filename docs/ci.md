# CI 与验证边界

## 常规检查

`.github/workflows/tests.yml` 在 Linux 与 macOS 14 上使用 Go 1.27.1 执行 `go test -tags headless` 和 `go vet`；macOS 另跑 `-race`，并分别执行 `macos` 与 `macos/Authentication` 的 Swift 测试。Go JSON 日志作为 artifact 保留，包含每个测试的 pass/fail/skip；整个命令成功不能说明其中被跳过的 live 测试已运行。

macOS 先用 `scripts/ci-build-harness.sh` 编译 `SNAPSHOT_BRIDGE_TESTING` 动态库，再通过 `SNAPSHOT_TEST_HARNESS` 交给 Go 原生协议测试。此库使用临时目录和 MemoryKeys，不访问用户 App Group、Keychain 或系统凭据索引。它只能证明隔离 C ABI 的协议行为。`scripts/ci-check-fixtures.sh` 检查生产包没有导入 `internal/testfixture`；同包测试通过泛型和回调注入避免依赖循环。

本地复现：

```sh
export GO_BIN="$(bash scripts/resolve-go.sh)"
bash scripts/ci-check-fixtures.sh
# macOS；TMPDIR 应指向当前测试独占的临时目录
bash scripts/ci-build-harness.sh "$TMPDIR/libSnapshotBridgeHarness.dylib"
SNAPSHOT_TEST_HARNESS="$TMPDIR/libSnapshotBridgeHarness.dylib" "$GO_BIN" test -race -tags headless ./...
"$GO_BIN" vet -tags headless ./...
swift test --package-path macos
swift test --package-path macos/Authentication
```

## 可选 live 夜间任务

`.github/workflows/live.yml` 提供每日 UTC 03:23 和手动入口。默认跳过 live job，并在 summary 明确说明“未运行”。维护者配置仓库变量 `MYGO_LIVE_CI=1` 后允许夜间消耗 Docker/下载资源；也可在手动运行中勾选 `run_live`。无需真实用户账号、SMTP 服务、Keychain、签名身份或注入登录秘密。

`scripts/ci-live.sh` 只选以下已有自供应入口：

| 测试 | 原有 opt-in | 覆盖范围 |
|---|---|---|
| `TestLivePersonalRelease` | `MYGO_PERSONAL_RELEASE_TEST` | 自建 SMTP/Vaultwarden 实例中的个人发布链路 |
| `TestLiveVaultFinishing` | `MYGO_VW_FINISHING_TEST` | 附件、备份、组织资源完成核验 |
| `TestLiveRotationCipherResources` | `MYGO_ROTATION_CIPHER_TEST` | 密钥轮换与附件材料 |
| `TestLiveRecoveryLifecycle` | `MYGO_RECOVERY_SMTP_TEST` | 独立实例中的恢复生命周期 |
| `TestLiveSMTPInvitations` | `MYGO_VW_SMTP_TEST` | 本地收信器、邀请与加入组织 |

入口自己创建唯一容器名、回环端口和临时数据，结束时按容器完整 ID 与 `mygo.fixture` 所有权标签清理。恢复、轮换、资源完成测试固定到现有镜像 digest；SMTP 邀请沿用 `vaultwarden/server:1.37.4` tag，因此该项仍存在 tag 可变的复现限制。CI 不接受外部 URL；脚本清除继承的服务器地址、release-only 过滤和 `MYGO_BW_CLI`，不会借用 CLI 现有登录。

```sh
MYGO_LIVE_CI=1 bash scripts/ci-live.sh "$TMPDIR/live-tests.jsonl"
```

本地缺少 opt-in 或 Docker 时脚本退出 77，表示未执行。CI 中缺少资源许可使 job 显式跳过；已获许可但 Docker 不可用会令 job 失败并报告未执行，避免绿色结果被当作 live 通过。实际运行必须出现五个指定顶层测试的 pass 事件；只 skip、没有匹配测试或任何失败都不能通过。镜像下载、编译或 fixture 启动失败也会直接失败，不生成虚构结果。Go 子进程使用显式 `GO_BIN`，否则使用 PATH 中的 Go，不再依赖废弃的 `runtime.GOROOT`。

本次新增的是可执行配置，尚不能当作 GitHub hosted runner 或 live 服务已经通过的证据。首次启用需检查 artifact、耗时与清理结果。强制终止进程可能来不及执行测试清理；当前 CI 使用一次性 hosted runner，没有复用用户 Docker 主机。

## 仍需真实设备验证

Headless Go、race、Swift 单元测试与 MemoryKeys C ABI 都不能证明签名沙盒的文件权限、真实 Touch ID/系统认证、Safari AutoFill、配置描述文件或 IdP 系统窗口可用。发布前需在专用测试账号和签名安装上按 [共享加密快照](secure-snapshots.md) 的人工步骤逐项记录。

此 nightly 配置没有供应 Bitwarden CLI，因此可选 CLI 往返分支不在覆盖声明中。不要把普通 Go 测试里 live 的 skip、生产桥编译成功或系统候选出现写成真实端到端通过。

## 跨组件集成核对

- A3/A4 的预期策略：在线 PBKDF2 低于 100,000 次明确拒绝派生/发送证明，并引导先使用官方客户端提升账号 KDF；Argon2id 的内存上限为 1024 MiB。旧本地快照读取兼容与在线策略不同，测试夹具中的 5,000 次参数仅用于离线存储兼容。最终错误文案和边界应以 auth 组件合入后的代码与测试校验。
- A6 的目标是默认 15 分钟用户空闲锁定，后台同步不得续期；实现和事件来源由 lifecycle 组件负责，当前文档不将此目标列为已验收功能。
- C1 的领域对象拆分由集成阶段更新 [架构说明](architecture.md) 的类型、依赖及残余大对象描述。
