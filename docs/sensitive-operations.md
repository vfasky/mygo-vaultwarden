# 项目再次验证与敏感内容

这是整卡中的一个已接入产品的模块，完整 Vaultwarden API 仍为 **INCOMPLETE**。

个人 reprompt=1 项目保留受保护标题占位，点击「查看与编辑」先显示主密码验证表单。Go 使用已认证会话中的 domain-separated snapshot unlock key 与当前 KDF 验证主密码；不保存原密码。成功授予 30 秒、当前会话/服务器/账号/本地 snapshot revision/项目密文 SHA256 绑定的进程内能力。表单明确提示到期关闭并丢弃未保存内容。字段的 reprompt 标志保持原值；不会通过改为0绕过验证。

解密、完整更新、项目复制及单项状态操作在使用前复核 grant。刷新令牌安全落盘产生新 revision 时立即撤销全部旧 grant；慢速刷新/Keychain 操作结束后、HTTP写入发出前再次复核。UI采用新 checkpoint 后关闭受保护表单，需重新验证。组织数据、viewPassword=false、未知 reprompt 值仍拒绝；组织策略尚未实现，不能把个人授权用于组织。附件/FIDO2/未知字段的完整复制仍沿用严格拒绝。批量操作和导出尚未接入逐项 reprompt 授权，不计为完成。

登录编辑器提供「显示已保存密码」「显示当前验证码」「复制已保存密码」「复制当前验证码」。使用当前已认证快照中的已保存内容，不复制尚未提交的表单草稿。显示最长30秒，TOTP不超过当前验证码有效期，protected项目不超过grant剩余有效期。展示前也通过Swift认证snapshot lease；秘密不放状态、日志、显示列表或回执。锁定/登出/账号切换清除新增的显示/验证表单内容；无法承诺Go/Swift字符串历史副本在运行时中可证明清零。

TOTP以固定 SDK `39dbb510f5eae82f5cbfd527b0f70a01d5626ec1/crates/bitwarden-vault/src/totp.rs` 为据，支持裸base32、otpauth://totp 和 steam://、SHA1/256/512。明确资源范围为6–8位数字、1–300秒、1–1024字节解码key。展示时兼容大小写和空白分组，忽略 image 等不影响验证码的未知元数据；已知参数重复、HOTP、未知算法、非法秘密及超界参数仍拒绝，不夹紧参数。此解析器用于生成展示验证码，不作为持久输入格式验证器。RFC6238全部18个向量、SDK固定Steam `2023-01-01T00:00:00Z → 7W6CJ` 及兼容输入回归已验证。

Swift桥新增版本1 `copySecret`/`authorizeSecretDisplay`（scope、expectedRevision、临时借用unlockKey、secretNotAfter毫秒时间；copy另带限64KiB UTF8秘密）及 `clearSecretClipboard`。只有公开revision不构成授权：先`unlockWithPassword`，再`withCurrentLease`线性化复制与锁定/撤销，执行时再次拒绝过期或大于30秒的deadline。回执不带秘密或owner。Go仅从同步UI事件调用秘密路径；不允许网络迟到回调写剪贴板。

锁顺序为Go Session.mu → Swift主线程（UI调用已在主线程）→ snapshot文件lease。Swift若从worker进入，会在获取文件锁**之前**切到主队列；持文件锁时禁止等待UI。Go worker不允许通过`WithPersonalSecret`等待UI；UI锁定不等待Go Close，Close异步完成并取消请求。授权KDF在Session.mu之外运行，结束后复核epoch/关闭/取消。

剪贴板每次使用随机owner+NSPasteboard.changeCount，不保留秘密副本；定时器只保存owner/count。最长30秒（验证码或grant更早到期则提前），本应用lock/logout/切换/正常退出及已观察到的外部revision失效都会尽力清理。旧timer不能清后续本应用写入，外部后来复制相同值也保留。concealed/transient仅为兼容提示，不能保证其他应用/历史管理器不读取；NSPasteboard没有跨进程原子CAS，最后检查与清理之间仍有系统竞态。崩溃/强杀不保证执行退出清理，尚未观察到的外部锁只能依赖到期清理。

验证：Go协议/生命周期/headless测试、race；Swift注入board与**独立命名**真实NSPasteboard，测试不会接触用户通用剪贴板；Swift认证错误key、旧revision、过期deadline、lock/logout阻断。真实隔离Vaultwarden1.37.4验证reprompt创建→sync排除AutoFill→验证→读取→PUT保留标志→新key复制保留标志。原生真实窗口/安装、通用剪贴板用户交互、Keychain/Touch ID/AutoFill平台交互未验证，不能用headless或命名board测试替代。
