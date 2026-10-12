# 自动更新与发布

MyGo 原生更新窗口负责检查版本、展示发布说明、下载进度、安装及重新启动。用户可在“设置 › 更新”调整自动检查、自动下载，或通过应用菜单“检查更新…”主动检查。仅已配置更新 feed 与公钥的 Release 构建启用；Debug 和 `mygo dev` 永不自动更新。未配置时构建仍成功，应用会说明此构建不会自动更新。

更新先读取平台 manifest，再下载完整归档，核对大小，并使用应用内置的 Ed25519 公钥验证归档 SHA-256 摘要的签名；校验成功后解压并替换整个 `.app` bundle。更新器需要对安装目录及应用旁的临时目录有写权限，推荐安装到当前用户可写的 `~/Applications`。只读磁盘映像、不可写位置无法自更新。应用启用了 App Sandbox，沙盒默认禁止写入自身所在目录，因此 `App.entitlements` 为 `/Applications/` 与 `~/Applications/` 声明了临时例外（`com.apple.security.temporary-exception.files.*.read-write`，仅限 Developer ID 分发，不适用于 Mac App Store）。安装在其他目录的构建会提示“无法自行更新”。更新签名与 Apple 代码签名用途不同，两者都需要；发布工具不替代签名、公证或安装验收。

## 密钥与配置

本项目通过公开仓库 [vfasky/mygo-vaultwarden 的 GitHub Releases](https://github.com/vfasky/mygo-vaultwarden/releases) 发布更新，使用默认 `v` 前缀（例如 `v0.1.0`），无需单独设置 tag 前缀。

请由发布者本人使用项目固定版本的 MyGo 生成密钥：

```sh
GO=$(bash scripts/resolve-go.sh)
"$GO" tool mygo keygen -o .local/update-keys
```

将 `.local/update-keys/mygo-update.pub` 的 base64 文本填入 `publicKey`。私钥保存在已忽略的 `.local/` 或密码管理器中，绝不提交；备份并保护私钥，丢失后既有安装无法接受新密钥签发的更新。CI 通过秘密变量 `MYGO_UPDATER_PRIVATE_KEY` 传入私钥的 base64 **内容**（64 字节解码结果），不在命令行传递或打印它。

在 `mygo.json` 添加可选配置（以下公钥占位文字必须替换）：

```json
{
  "updates": {
    "publicKey": "<mygo-update.pub 的内容>",
    "github": "vfasky/mygo-vaultwarden"
  }
}
```

这是要合并到现有配置中的 `updates` 字段，保留原有 `name`、`identifier`、`version` 等字段。发布时可额外配置 `"privateKey": ".local/update-keys/mygo-update.key"`，或通过上面的 CI 秘密变量提供私钥。私钥路径相对 `mygo.json` 所在目录解析，也支持绝对路径和 `~/`。公钥必须由发布者生成后填入，仓库不预置公钥或私钥。

备选部署可用 `"url": "https://downloads.example.com/mygo-vaultwarden"` 替换 `github`。两者必须且只能提供一个；URL 为不含凭据、查询、片段、引号或空白的 HTTPS 目录基地址。公钥必须是 base64 编码的 32 字节 Ed25519 公钥。非法配置会使构建/打包失败。

构建和发布共用这些环境覆盖项：

| 环境变量 | 覆盖字段 |
|---|---|
| `MYGO_UPDATE_PUBLIC_KEY` | `updates.publicKey` |
| `MYGO_UPDATE_URL` | `updates.url` |
| `MYGO_UPDATE_GITHUB` | `updates.github` |
| `MYGO_UPDATE_TAG_PREFIX` | `updates.tagPrefix`，空值或未配置默认为 `v` |

显式设置空环境变量会清空对应配置字段。从 GitHub 切换到 URL 时，设置 URL 并清空 `MYGO_UPDATE_GITHUB`。完全不设置 `updates` 和这些覆盖项才是未配置状态；`updates: {}` 是错误配置。Debug 不读取或注入更新配置。发布时应使用与该 Release 构建一致的公钥、更新地址和 tag 前缀。

## 发布新版本

在本机执行 `scripts/release.sh`，使用 `.local/signing.env` 中的 Developer ID 证书与公证 profile，以及本机的更新签名私钥；不依赖 CI，私钥与证书不离开这台 Mac。

1. 修改版本号：`mygo.json` 的 `version`，以及 Xcode 工程中两处 `MARKETING_VERSION`（`macos/MyGoVaultwarden.xcodeproj/project.pbxproj`）。
2. 在 `CHANGELOG.md` 顶部新增 `## <版本>` 小节，它就是 release 与更新窗口里的发布说明。
3. 提交，并在 `main`、工作区干净时运行：

```sh
bash scripts/release.sh
```

脚本依次：检查三处版本一致、CHANGELOG 有该版本、tag 未指向其他提交、同版本 release 未公开；运行 `go vet` 与 `go test`；`build-macos.sh release --notarize` 构建、签名、公证并 staple；生成更新归档、manifest、首次安装用的 `MyGo-Vaultwarden-<版本>-macOS.zip` 与 `SHA256SUMS.txt`（`build/updates/<版本>/`）。随后询问确认，再创建并推送 tag `v<版本>`，创建草稿 release，先上传 zip、归档与校验文件，最后上传 manifest。

草稿不会进入应用的更新通道。在 GitHub 上检查发布说明与文件后公开：

```sh
gh release edit v<版本> --repo vfasky/mygo-vaultwarden --draft=false --latest
```

选项：

| 选项 | 作用 |
|---|---|
| `--publish` | 上传后直接公开并标为 latest（版本号含 `-` 时作为 prerelease 公开，不进入更新通道） |
| `--no-upload` | 只构建并生成发布文件，不打 tag、不上传，可用于检查产物 |
| `--skip-tests` | 跳过 vet 与测试 |
| `--yes` | 推送 tag 与上传前不再询问 |

更新签名私钥依次取自环境变量 `MYGO_UPDATER_PRIVATE_KEY`、登录钥匙串中的备份（服务名 `MyGo Vaultwarden update signing key`），最后是 `mygo keygen` 写入的 `~/Library/Application Support/mygo/update-keys/mygo-update.key`。脚本需要已登录的 GitHub CLI（`gh auth login`）。推送 tag 会把它指向的提交一起推到 GitHub。

中途失败可修复后重跑：同版本的旧发布文件会重新生成；草稿 release 中的文件会被覆盖；已公开的 release 不会被改动，需提高版本号。

## 分步构建与发布

`scripts/release.sh` 按以下步骤执行，也可以手动分步运行。先同步 `mygo.json`、Xcode `MARKETING_VERSION` 和 `CHANGELOG.md` 的版本；当前为 `0.1.0`。发布说明取 `## 0.1.0` 下直到下一个二级标题的 Markdown，支持 `## [0.1.0] - 日期`，缺失或内容为空会失败。

```sh
# 配置与密钥就绪后，构建、签名、公证并 staple
bash scripts/build-macos.sh release --notarize
# 检查已生成的 app，生成更新文件；不签名、不上传
bash scripts/release-update.sh
```

第二个脚本执行 `codesign --verify --deep --strict` 和 `xcrun stapler validate`，任一步失败都停止。随后 Go 工具读取 `Info.plist` 的 `CFBundleShortVersionString`，并使用 `debug/macho` 检测 `CFBundleExecutable`：arm64 对应 `darwin-arm64`，x86_64 对应 `darwin-amd64`，同时含这两种架构的 Fat Mach-O 对应 `darwin-universal`。Xcode 链接注入使用 `$ARCHS` 得到相同目标，不依赖构建主机架构。

可显式指定路径和版本（覆盖值须与实际应用及发布平台一致）：

```sh
bash scripts/release-update.sh \
  -app 'build/release/MyGo Vaultwarden.app' \
  -version 0.1.0 -target darwin-universal \
  -out build/updates/0.1.0
```

其他选项为 `-config`（默认 `mygo.json`）、`-changelog`（默认 `CHANGELOG.md`）。工具拒绝覆盖已存在的同名发布文件，也拒绝把输出写入输入 bundle 内。直接 `go run ./tools/release-update` 只执行归档和更新签名，不执行 Apple 验证，因此正式发布使用 shell 入口。

默认产物目录 `build/updates/0.1.0/` 包含：

- `mygo-vaultwarden-0.1.0-<target>.tar.gz`：根目录恰好一个 `.app`，保留相对符号链接和权限、归一化所有者。绝对链接、越界链接、无法解析的链接及文件/目录/符号链接以外类型会被拒绝。使用 gzip 最佳压缩；不保留扩展属性，staple 与签名应通过解压后系统验收确认。
- `update-<target>.json`：`version`、Markdown `notes`、RFC3339 UTC `date`、下载 `url`、归档字节 `size`、Ed25519 `signature`。签名的是压缩包 SHA-256 摘要，不是 JSON。本工具暂无 delta，也不下载或生成旧版本差分。

默认 feed 是 `https://github.com/vfasky/mygo-vaultwarden/releases/latest/download/update-<target>.json`，归档来自 `https://github.com/vfasky/mygo-vaultwarden/releases/download/v0.1.0/<archive>`。正式发布应标记为 latest；本项目无需配置其他 tag 前缀。GitHub 的 `releases/latest` 只指向已公开、非草稿、非 prerelease 的最新 release：草稿和 prerelease 不会进入应用的更新通道，可用来在公开前核对产物；本流程不提供单独的测试版通道。

脚本末尾按上述配置打印 `gh release create v<version> --repo vfasky/mygo-vaultwarden` 等示例，**不会执行上传**。推荐先创建草稿并上传归档，最后上传 manifest，审核全部目标产物后再公开草稿。例如：

```sh
gh release create v0.1.0 --repo vfasky/mygo-vaultwarden --draft \
  build/updates/0.1.0/mygo-vaultwarden-0.1.0-darwin-universal.tar.gz
# 归档上传完成后，最后上传 manifest
gh release upload v0.1.0 --repo vfasky/mygo-vaultwarden \
  build/updates/0.1.0/update-darwin-universal.json
# 审核发布说明与所有目标产物后再公开
gh release edit v0.1.0 --repo vfasky/mygo-vaultwarden --draft=false --latest
```

已有 release 使用脚本打印的 upload 命令，仍须先上传归档、最后上传 manifest。多架构分别构建时，汇集所有目标的归档和 manifest 后再公开草稿，避免 manifest 可见而对应归档缺失。

自定义服务器的 feed 为 `<url>/update-<target>.json`，归档 URL 为 `<url>/<archive>`。先上传归档并验证可下载，再原子发布 manifest；为 manifest 设置适当的缓存策略，保留旧版本归档以照顾缓存中的 manifest。

## 发布验收与限制

本仓库的单元测试使用假的 `.app` 检查归档解压规则、相对符号链接、执行权限、签名、manifest、URL、配置、发布说明与 Mach-O 识别，不证明真实 macOS 更新安装成功。首次发布前应在隔离安装中验证从旧版本检查、下载、替换、重启，以及 AutoFill 与本机快照仍可使用。发布前还应对解出的 bundle 再次执行代码签名与 staple 验证。

整个 bundle 更新包含 AutoFill 扩展。替换 bundle 后系统是否及时重新注册扩展尚未实测，是发布前验收项；更新后检查：

```sh
pluginkit -m -v -i yz.sh.mygo-vaultwarden.autofill
```

若系统没有重新启用，请在“系统设置 › 自动填充与密码”检查 MyGo Vaultwarden，再验证 Safari 实际填充。自动更新不代替用户的 AutoFill 授权，不能通过静态签名检查宣称系统填充已验证。
