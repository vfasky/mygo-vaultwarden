# 共享加密快照

## 范围

共享加密快照保存 Vaultwarden 的个人登录条目。`SnapshotScope` 绑定规范化服务器地址与稳定账号 ID；旧演示 scope 仅保留兼容识别，不再提供演示数据发布入口。主密码输入和只读同步的边界见 [Vaultwarden 只读接入](vaultwarden-readonly.md)。

主应用与扩展各自可以打开共享存储，不通过主应用进程提供解密服务。主应用退出后，扩展继续使用自己的 Swift 代码和系统 Keychain。

## 组成

```text
Go / MyGo 主应用
   │ 有界 JSON 请求，工作 goroutine 同步调用 C ABI
   ▼
libSnapshotBridge.dylib
   │
   ├── SnapshotStore / SnapshotFiles / SnapshotIndex
   │              ▲
   │              │ 同一套源码
   │     Swift/AppKit AutoFill 扩展
   │
   ├── App Group：AES-GCM 密文与控制状态
   └── Data Protection Keychain：受 userPresence 保护的随机密钥
```

快照接口向 Go 返回操作状态、版本、条目数和清理状态。只有经过认证且 revision/scope 仍有效的 `list` / `listPassword` 主应用解锁操作，才返回显示元数据和加密 payload 内保存的登录会话；不会返回密码库条目的密码或随机快照密钥。会话包含在线同步所需的 refresh token、用户密钥和包装密钥，Go 验证账号、服务器、邮箱、设备标识和包装配置后恢复，并清理传输缓冲。状态查询、索引操作及 AutoFill 的默认 lease 均不返回该会话。

原始主密码和 TOTP 仅交给 Go 登录/解锁任务，不经过快照 C ABI，也不进入命令行或日志。主密码解锁只向桥接传入域分离派生的临时包装密钥；会话保存只在已认证的进程内通过有界 JSON/C ABI 传输。C 函数不在返回后保留 Go 缓冲区；敏感输入的生命周期与撤销隔离见 [只读接入说明](vaultwarden-readonly.md)。

主应用通过动态库执行快照发布和撤销；扩展直接编译共享 Swift 源码。动态库放在应用 `Contents/Frameworks`，参与 Xcode 的嵌套签名和 Developer ID 导出，不以临时 helper 或命令行参数传递秘密。

## 容器与 Keychain

两个 target 都声明相同的：

- macOS App Group：`$(TeamIdentifierPrefix)yz.sh.mygo-vaultwarden.shared`。
- 独立 Keychain Access Group：`$(AppIdentifierPrefix)yz.sh.mygo-vaultwarden.shared`。

使用 macOS 支持的 Team ID 前缀容器以覆盖当前 macOS-only 目标；这种 App Group 名称本身不授予 Keychain 权限，因此另行声明 Keychain Sharing。签名时通过 Xcode 展开前缀，并由各自的 profile 授权。将来支持 iOS 时需要重新规划注册的 `group.` 标识及迁移。

所有 SecItem 操作使用 `kSecUseDataProtectionKeychain = true`。密钥属性包括：

- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`。
- `SecAccessControl` 的 `.userPresence`。
- `kSecAttrSynchronizable = false`。
- 本应用专用 service、随机 key ID 和共享 access group。

`.userPresence` 由系统决定可用的 Touch ID / 设备认证方式，不等同于“只能用当前一组指纹”。Touch ID 入口和 AutoFill 的真正密钥读取通过 SecItemCopyMatching 授权。主应用另提供主密码解锁入口，使用主密码派生密钥解密下述包装密文，不读取或弱化 Keychain 项的访问控制。

每次读取创建新的 LAContext，设置生物识别复用窗口为 0。无交互回调直接要求 `userInteractionRequired`；底层密钥读取在禁止交互时使用 `interactionNotAllowed`，不会打开认证窗口。

## 密文格式与写入

`snapshot-v1.json` 包括控制状态、待清理 key ID、候选索引确认 token，以及可选的加密快照。服务端/账号身份、版本、条目数及主密码解锁用的邮箱、KDF 参数是公开控制元数据；凭据标题、用户名、域名、密码，以及可选的恢复登录会话均位于加密 payload 内。会话内容不出现在 header 或状态元数据中，上限为 64 KiB。

每次发布替换快照都生成新的 256-bit 随机 AES 密钥和新的 snapshot ID。CryptoKit AES-GCM 使用新的 nonce，header 作为认证附加数据；header 包含格式、scope、snapshot ID、key ID、创建时间和条目数。解密同时验证账号/服务器 scope、AEAD 标签、payload schema 和条目数量。

新同步的快照另含可选 `passwordUnlock`：公开的邮箱与 KDF 配置，以及由主密码派生包装密钥保护的随机快照密钥。Go 复用登录的 PBKDF2/Argon2id 参数派生主密钥，再用 HKDF-Expand-SHA256 和固定域 `mygo-vaultwarden/snapshot-unlock/v1` 生成 32-byte 包装密钥。Swift 使用 AES-GCM 包装，认证附加数据同时绑定完整 snapshot header 与 KDF 配置。包装密文为 12-byte nonce、32-byte 密文和 16-byte tag；错误密码、配置或跨快照替换无法通过认证。原始主密码和明文包装密钥不写入状态文件。主密码入口使本机快照具备基于主密码强度的离线解密能力，Keychain 仍独立提供设备认证入口。

旧版没有 `passwordUnlock` 的快照继续支持系统认证，重新登录并成功同步后自动获得主密码解锁能力。新发布不会沿用上个快照的包装密文；登出会连同快照删除它。

写入顺序：

1. 获取跨进程 `state.lock`，核对预期 revision。
2. 先记录待创建 key ID 的清理 journal，并更新 revision。
3. 将随机密钥存入受系统认证保护的 Keychain 项。
4. 将密文写入独占创建、0600 权限的临时文件，fsync 后原子 rename。
5. 把旧 key ID 保留在清理队列，逐项删除后再确认清理完成。

这使“创建密钥后崩溃”不会留下不受追踪的 Keychain 项。清理失败时队列保留，可重试；没有把失败伪装成已清理。

状态文件只读打开使用 `O_NOFOLLOW`，拒绝符号链接和非普通文件，限制大小；损坏、读权限失败或未知格式不会被视为一个可覆盖的空密码库。只在文件确实不存在时返回初始状态。

## 锁定、认证与填充

认证前读取一个快照版本，释放文件锁，再向系统请求密钥。认证成功后再次核对版本，防止认证窗口打开期间发生更新、锁定或登出。

主密码解锁在后台派生后，通过 `listPassword` 传入快照 scope、预期 revision 与临时包装密钥；存储先检查版本，再解密，返回前仍通过 `withCurrentLease` 再次校验。主窗口对两种解锁回执都检查 scope、revision 和 UI 代次，不接受锁定或切换账号前发起的迟到结果。认证解锁后可恢复 payload 中的在线会话；该回执仅授权当前 scope/revision 的后续同步，普通状态刷新不能恢复权限。

解密后的 lease 只存在于当前请求内存，采用单调时钟限制为 60 秒。填充提交前再次校验，并在同一个跨进程锁内调用 Apple 的 `completeRequest`，将提交和撤销排序。

- 锁定：轮换 revision，使之前的认证结果和 lease 失效；即使当前没有快照，也推进版本以阻止迟到登录发布。清除内存会话但保留已有密文及加密登录凭据，后续必须重新认证解锁。
- 账号切换：非空快照不能被另一 scope 直接覆盖，即使预期 revision 正确也拒绝；必须显式撤销旧账号后发布。
- 同步移除条目：全量替换快照时重新加密并换密钥；用 CAS 拒绝迟到写入。
- 登出：先写入无快照的 tombstone，连同保存的登录凭据一起撤销，再清理密钥和候选；密钥清理失败也不能继续使用旧快照。
- 令牌刷新：先执行 `saveSession`，在锁内核对 scope/revision，用原随机密钥及新 AES-GCM nonce 重加密完整 payload，只替换会话并推进 revision。保留 header、候选身份和密码包装；成功回执仍通过 lease 核验，迟到保存不能复活锁定或登出的会话。
- 更新期间认证成功：如果 revision 已变，丢弃结果并要求重试。
- 主应用退出：不等于登出；扩展仍能在自己的进程内认证读取有效快照。

主应用监听锁屏与睡眠事件。扩展监听锁屏、屏幕睡眠、会话失活和快照更改通知，取消 LAContext 并丢弃当前列表。通知用于及时清理；真正的正确性边界仍是文件版本检查，不能只依赖通知送达。

直接选择系统候选只需一次认证读取与提交。手动查看凭据列表需要先认证，选中后再用新 context 认证并填充，从而不会仅凭仍在屏幕上的旧列表释放密码。

已在撤销前提交给系统的填充无法追回；撤销保证作用于之后的提交。Swift/Go/CryptoKit 可能产生内存副本，本实现尽量缩短生命周期并清理可控缓冲区，不声称所有明文副本都能被证明清零。

## 系统候选一致性

`ASCredentialIdentityStore` 只接收服务标识、用户名和 record ID，不接收密码。record ID 包含随机 snapshot ID 和条目 ID，旧候选不能直接命中新快照。

系统索引和本地文件没有共同事务，因此：

- 先提交本地密文，再请求更新系统索引。
- `indexPending` 在实际回调成功且 token 仍匹配时才清除。
- `index.lock` 将多个进程的索引写入串行化，直到实际系统回调；不能因等待超时提前释放锁，让迟到写覆盖后来的清空。
- `index.lock` 与 `state.lock` 分开。系统索引服务卡住不会阻止锁定或登出撤销。
- 回调迟到时不能确认新版本；失败/进程退出后保留 pending 状态，允许认证后重建。
- 登出后的空索引可以无认证重试；有数据的索引重建需要认证解密。

即使索引暂时残留一个用户名候选，扩展仍会因 snapshot ID / revision 不匹配而拒绝返回密码。进程在系统服务接受请求后崩溃时，文件锁会释放，系统回执也可能丢失；本地文件与系统索引没有跨服务提交保证，需要在下次认证后重建索引，不能把索引是否显示候选作为授权事实。索引元数据会交给苹果系统，这是开启自动填充时的设计行为。

## 测试与人工验收

自动化测试覆盖：

- 密文中不含测试明文、重新打开存储、0600 权限。
- 每次更新随机换密钥，旧密钥清理。
- GCM 密文及 header 篡改、错误 scope、未知/损坏格式。
- 认证取消、无交互拒绝、认证期间锁定或登出。
- lease 过期、同步移除条目后旧记录失效。
- 两个存储实例并发更新时只有一个 CAS 成功。
- 密钥创建失败保留原快照、清理失败重试和幂等。
- 索引迟到回调、索引写入期间登出仍能立即撤销。
- 状态文件符号链接拒绝。
- 主密码离线解锁、错误密码、包装密文/KDF/header 篡改、锁定/登出/替换后的旧请求拒绝、旧格式兼容以及独立系统认证入口。
- 登录会话密文保存、两种主应用解锁后恢复、AutoFill 默认 lease 不带会话、令牌更新保留列表/候选、撤销后的迟到保存拒绝。

其中 Keychain 使用测试替身；真实设备上还需独立验证系统认证与签名权限。最小人工验收流程：

1. 登录专用测试账号并同步密码库，认证并更新系统候选。
2. 在 Safari 加载测试条目对应的网站后退出主应用。
3. 从系统候选选择本扩展，完成认证和填充，检查网页结果。
4. 取消一次认证，确认表单没有收到凭据。
5. 重新打开主应用，在扩展认证/列表仍打开时锁定或登出，确认旧请求无法提交。
6. 在服务端删除测试条目后重新同步，确认旧候选失效；重建索引后候选消失。
7. 重启扩展再次填充，确认无需主应用常驻；实际锁屏后应重新认证。

真实设备上的这些结果应逐项记录，不能以单元测试、签名成功或仅出现系统候选代替端到端验收。
