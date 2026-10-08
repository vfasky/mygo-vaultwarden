# 最终集成 #14 工作记录

本卡从 `69047c2` 启动，只修改独立 Board 工作树。当前为开发中检查点，**不是最终候选，不表示完整客户端已完成或已合并**。最终需包含后续已审查的 #38/#39/#40 接口并重新验收。

本轮主 controller 已接：统一 UI epoch 推进及原子 worker 时钟；短锁 scope/revision/snapshot lease；Session 锁内只保存/校验 checkpoint，UI dispatch 后才采用；退出撤销网络、组件与通知。主登录改用 LoginMFA，主密码直到认证后 policy 检查完成才清除；普通 MFA/provider8 的账号级警告、生产 Duo/WebAuthn 桥及 SSO→UnlockSSOVault 使用同一认证同步流程。账号注册/资料/敏感变更 Begin/Result、Send、设备审批、MFA 管理和通知有主窗口接线。入口位于原生“账号与设置”的账号服务区，以保留用户现有侧栏布局与截图对应行为。

检查点新增运行期 authority：只从实际设备 Session 完整 Sync 的私有摘要铸造，一次消费；独立 runtime revision 从不作为 Swift 持久 revision 使用。Sync/Close/授权变更/令牌期限撤销旧能力，临时会话不刷新 token。可继承同账号的真实本地 pending/org 隔离；再次验证主密码不隐式安装密码包装。普通读取/编辑/附件/备份/秘密展示的 controller 已增加按 epoch 捕获的存储后端路由。生产设备发起端、原生 runtime secret ABI、跨账号 target 阻断检查仍在接线中，当前不能宣称运行期主库已完整可用。

本轮实际执行通过：

- `go test -tags headless ./... -count=1 -timeout=120s`（resolve-go.sh 的 Go 1.27.1）；
- `go vet -tags headless ./...`（在运行期权限后续改动之前的一轮，最终须重跑）；
- `go test -race -tags headless . -run 'TestController|TestResourceController|TestLogin' -count=1 -timeout=120s`；
- `go test -race -tags headless ./internal/vaultwarden -run '^TestRuntime' -count=1 -timeout=120s`。

新增测试验证后台 lease 在 storage 调用期间撤销、并发检查/lock、真实主视图 Send 页面及迟到结果清理、MFA 提交确认/原账号警告/迟到 prompt；运行期测试使用真实 DeviceLogin grant+sync HTTP fixture，验证伪造/重放拒绝、secret callback不借磁盘key、不绑定密码的reprompt、到期零refresh和type15 pending。它们不是 Keychain/原生窗口/真实服务端集成验收。

实际出现并已修复的测试失败：LoginMFA remembered/RememberToken是string而非slice；新lease测试夹具缺snapshot ID/device ID最短长度；新增侧栏行挤压既有导航，已把新增服务入口放入设置；新增登录链接挤出700px窗口返回按钮，已收拢为同一操作行。没有将这些首轮失败记为通过。

协调者追加业务卡：#38 目标恢复持久化与独立 Swift runtime secret；#39 cipher/folder轮换转换/核验；#40 Send轮换转换/核验。最终必须消费已独立审查合入的接口。账号恢复不得用任意 bool/HTTP200清屏障。

固定源已核验：1.37.4 `/api/version` 是实际 Vaultwarden VERSION；`/api/config.version=2026.6.0` 是兼容版本。轮换端点按 folder→EA→组织recovery→Send→cipher 逐项 await? 后，最后保存 account private-key/master-user-key 包装。grantor不能独立读回EA wrapper，普通组织成员不能读自己的reset-password-details；协调者批准在精确版本/commit、已核验生成与收件人身份、唯一最终双包装见证及全部可读资源核验均满足时使用明确的 protocol-ordered commit evidence。尚未实现或执行该完整证据链，不把它写成独立读回核验。

真实 Keychain/Touch ID、签名安装、系统AutoFill、IdP/Duo/AASA、完整1.37.4主入口回环、Swift/双架构最终构建、CLI与大库RSS/许可证检查仍待本卡最终轮次，不借用历史模块证据替代。
