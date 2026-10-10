# macOS 沙盒文件访问验证（A2）

本次代码检查与无 GUI 测试不等于签名沙盒实机验证。以下入口无需 Vaultwarden 账号或网络，只使用合成文本。未在本次审计环境运行签名 GUI，也未验证真实 Send 服务器流程。

## 授权与发布约束

MyGo v0.3.7 的 `Dialog.Open` 在 `internal/darwin/dialog.go` 创建 `NSOpenPanel`；`Directory: true` 将面板设为目录选择。`Dialog.Save` 创建 `NSSavePanel`。这些面板返回本进程使用的路径；本实现不保存跨进程书签，也不声称选文件自动授权其父目录。

主应用必须带 `com.apple.security.app-sandbox` 与 `com.apple.security.files.user-selected.read-write`。读取直接打开所选文件，使用 `O_NOFOLLOW|O_NONBLOCK` 并核实普通文件和大小；不逐级打开 `/` 或未经授权的父目录。内核可以解析 `/tmp`、`/var` 等祖先别名，最终文件不能是符号链接。

安全导出调用 `send.ChooseExportPath(ctx, options)`：先用保存面板取得文件名，再用目录面板明确选择最终位置。第二个面板显示文件名；取消任一步骤均取消导出。若第二步选了不同目录，最终文件位于第二步的目录，名字来自第一步。目录权限用于创建同盘 0600 暂存文件。`fileio` 直接打开所选目录（最终目录仍 `O_NOFOLLOW`），后续暂存、发布和清理全部使用固定的目录 fd，`linkat` 原子发布且绝不覆盖已有文件。固定 fd 后目录重命名/替换不会把写入引向替代目录。调用者仍需在发布前检查会话/取消状态。

应用集成需将备份、资源备份、组织导出、恢复包和附件保存的 `mygo.Dialog.Save(opts)` 换为 `send.ChooseExportPath(ctx, opts)`，保留原来的格式后缀和 lease 检查。Send 的底层 `sendParent` 同样必须直接打开所选目录，`OpenSendSource` 必须直接打开所选文件；不能沿用从 `/` 遍历的旧实现。

## 可执行沙盒探针

从仓库根目录构建。`sandboxprobe` 标签只加入这个独立入口，默认构建不包含它。

```sh
go build -tags sandboxprobe -o "$TMPDIR/sandbox-file-access-probe" ./internal/fileio/sandboxprobe
```

探针使用真实 MyGo 原生面板、实际 `ChooseExportPath` 和 `fileio` 代码。先在一个本应用容器外的测试目录创建内容严格为 `sandbox probe fixture` 加一个换行的普通文本；只选择此合成文件，不选择真实备份。另创建一个空目录作为导出位置，推荐分别在 Documents 和 `/tmp` 下测试。

使用独立 bundle ID（例如 `local.mygo.sandbox-file-probe`）将探针包装为 `.app`：`Contents/MacOS/probe` 放上述二进制，`Contents/Info.plist` 至少有 `CFBundleIdentifier`、`CFBundleExecutable=probe`、`CFBundlePackageType=APPL`。探针 entitlement **仅**包含以下内容，不能照搬主应用的 AutoFill、应用组等受限权限：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.app-sandbox</key><true/>
  <key>com.apple.security.files.user-selected.read-write</key><true/>
</dict></plist>
```

用测试机已有的有效签名身份签名；不要安装证书或把私钥写进日志。下面的路径和身份由测试人员指定：

```sh
codesign --force --options runtime --sign "$MYGO_SIGNING_IDENTITY" --entitlements "$PROBE_ENTITLEMENTS" "$PROBE_APP"
codesign --verify --deep --strict "$PROBE_APP"
codesign -d --entitlements :- "$PROBE_APP"
"$PROBE_APP/Contents/MacOS/probe"
```

在已登录桌面会话运行，依次选择合成源文件、输出文件名、明确授权最终目录。预期终端输出 `PASS`，目标目录出现两个 0600 文件（所选文件名及 `.attachment` 后缀），内容都是合成文本，没有 `.mygo-*` 暂存残留。探针同时验证拒绝覆盖已有目标。重复运行时选同名输出应失败；取消任一面板应失败且没有新的输出。探针不会自动删除已发布文件，测试人员检查后手工清理。无签名或关闭沙盒得到的 PASS 不能作为沙盒通过证据。

## 主应用实机验收

使用项目已有签名构建流程 `bash scripts/build-macos.sh debug`，确认主应用最终签名含上述两个文件访问 entitlement。该流程需合法的团队与配置描述文件，不得以移除沙盒来解决失败。仅在用户明确授权的本地测试服务器/虚构账号执行下列操作；探针本身无需账号。

1. **备份导出与导入**：用合成保险库导出；保存面板之后必须出现目录面板。测试 Documents、`/tmp`、`/var` 下的目录；校验格式后缀、0600 权限、成功导入。拒绝已有文件、最终文件符号链接、最终目录符号链接。取消目录面板或在导出过程中锁定，确认未发布明文。
2. **附件导入/保存**：先只选择容器外的普通合成文件（不要预先选过父目录），确认可读取并上传。保存时明确选目录；同名不能覆盖，取消后无暂存文件。FIFO、目录、最终文件符号链接都应拒绝。
3. **Send 保存**：使用本地测试服务器的合成文件 Send，确认两步目标选择并验证保存内容。验证取消与过期失败。网络下载成功本身不证明本地发布成功；必须检查目标文件。Send 源文件选择同样应可直接读取容器外文件。
4. **目录替换防护**：自动测试 `TestSelectedDirectoryReplacementCannotRedirectPublication` 会在 staging 后重命名目录并在原路径建替代目录，断言发布只落在固定 fd 指向的原目录。实机可用受控调试断点重复同一操作，不能把自动测试当沙盒权限实测。

记录 macOS 版本、应用/探针提交 SHA、有效签名 entitlement、每个面板操作、结果与失败日志（不得包含真实文件内容或令牌）。任何缺失项目写为“未验证”。
