---
name: vaultwarden-release
description: 发布 MyGo Vaultwarden 新版本：改版本号与中英双语 CHANGELOG、在本机用 Developer ID 签名公证、生成签名更新包、推送 tag 并上传 GitHub 草稿 release，按确认公开后更新介绍网站。用户提到发布、发版、升级版本、打 tag、上传 release、推送更新、release a new version 时使用。
---

# MyGo Vaultwarden 发布流程

发布全部在本机完成，入口是仓库里的 `scripts/release.sh`，不使用 CI。它使用本机的 Developer ID 证书与公证 profile（`.local/signing.env`）和本机的更新签名私钥。原理、文件格式与手动分步方式见 `docs/updates.md`。

## 必须遵守

- 版本号和更新内容由用户决定。用户没给时先问，不要自己编版本号或 CHANGELOG 内容。
- 更新说明必须中英双语，两段条目一一对应、意思一致。用户只给了一种语言时，由你翻译另一种，连同原文一起交给用户确认后再写入。
- 推送 tag、上传草稿 release 是对外操作：执行前把版本、tag、仓库和将上传的文件告诉用户，得到同意后再执行。
- 公开 release 会让所有已安装的应用收到更新：草稿上传后必须再次得到用户明确同意才公开。用户没有明确要求时不用 `--publish`。
- 绝不删除、移动或重打已推送的 tag，不 force push，不覆盖已公开的 release。发错版本时提高版本号重新发布。
- 不输出、不复制、不记录更新签名私钥、证书或 `.local/` 内容；不提交 `.local/`、`*.key`、`*.p12`、描述文件。
- 主检出目录可能有其他会话的未提交改动。不要替它们 stash、提交或还原；工作区不干净时停下来告诉用户，由用户处理。
- 只提交版本号与 CHANGELOG 相关文件（`git add` 指定路径），不要 `git add -A`。

## 步骤

### 1. 确认前提

在仓库根目录：

```sh
git branch --show-current          # 必须是 main
git status --short                 # 必须为空，否则停下询问用户
gh auth status                     # GitHub CLI 已登录
gh release list --repo vfasky/mygo-vaultwarden --limit 5   # 已有版本
plutil -extract version raw -o - mygo.json                 # 当前版本
```

新版本号必须大于已公开的最新 release（按语义化版本比较，例如 `0.1.10 > 0.1.9`）。版本号含 `-`（如 `0.2.0-beta.1`）会作为 prerelease 发布，不会推送给应用的更新通道。

### 2. 改版本号与 CHANGELOG

三处版本号必须一致，脚本会核对：

- `mygo.json` 的 `version`。
- `macos/MyGoVaultwarden.xcodeproj/project.pbxproj` 中两处 `MARKETING_VERSION = <版本>;`（Debug 与 Release 各一处）。同一行的 `CURRENT_PROJECT_VERSION`（构建号）两处都加 1。

在 `CHANGELOG.md` 中、上一个版本之前新增：

```markdown
## <版本>

### 中文

- 面向用户的改动，一条一行。

### English

- The same change in English, one per line.
```

这一节会原样成为 release 说明和应用更新窗口里显示的内容。介绍网站按 `### 中文` 与 `### English` 两个标题拆分语言，标题文字必须完全一致；缺少 English 段时，网站英文页会显示中文。

写法要求：

- 两段条目数量和顺序相同，逐条对应。
- 写用户能感知的变化，不写内部重构、测试、CI 等。
- 英文用简洁的产品说明语气，如 “Fixed …”、“Added …”，与应用界面英文术语一致（Vault、AutoFill、Account Center、Touch ID、master password）。

用户只给了大致方向时，可根据 `git log v<上一版本>..HEAD --oneline` 起草双语内容，交给用户确认后再写入。

检查后提交：

```sh
grep -n "MARKETING_VERSION\|CURRENT_PROJECT_VERSION" macos/MyGoVaultwarden.xcodeproj/project.pbxproj
git diff -- mygo.json macos/MyGoVaultwarden.xcodeproj/project.pbxproj CHANGELOG.md
git add mygo.json macos/MyGoVaultwarden.xcodeproj/project.pbxproj CHANGELOG.md
git commit -m "发布 <版本>"
```

修改 `mygo.json` 或 `macos/` 会触发用户的 `dev-debug --watch` 重新构建调试版，这是正常的。

### 3. 构建并上传草稿

用户同意推送 tag 和上传后运行。脚本在上传前会交互询问；agent 的 shell 无法回答，所以在得到用户同意后加 `--yes`：

```sh
bash scripts/release.sh --yes
```

整个过程约 8–15 分钟（两个架构各公证应用与 DMG）（测试、Xcode 归档与导出、Apple 公证、生成文件、推 tag、上传），用足够长的超时。它会：

1. 核对三处版本、CHANGELOG、tag 未指向其他提交、同版本 release 未公开。
2. `go vet` 与 `go test -tags headless`。
3. 对 arm64 与 x86_64 各执行 `scripts/build-macos.sh release --notarize --arch <架构>`：Developer ID 签名、公证、staple，输出到 `build/release-<架构>/`。
4. 生成 `build/updates/<版本>/`：每个架构一份更新归档 `mygo-vaultwarden-<版本>-darwin-arm64.tar.gz` / `-darwin-amd64.tar.gz`、manifest `update-darwin-arm64.json` / `update-darwin-amd64.json`、DMG `MyGo-Vaultwarden-<版本>-macOS-AppleSilicon.dmg` / `-macOS-Intel.dmg`，以及 `SHA256SUMS.txt`、`notes.md`。
5. 创建并推送 tag `v<版本>`，创建草稿 release；先上传 DMG、归档、校验文件，最后上传两个 manifest。

用户只想先检查产物时用 `--no-upload`（不打 tag、不上传）。其他选项：`--skip-tests`、`--publish`（见下）。

推送 tag 会把它指向的提交一起推到 GitHub；本地 `main` 领先 `origin/main` 时，这些提交会一并公开。执行前提醒用户。

### 4. 核对草稿

```sh
gh release view v<版本> --repo vfasky/mygo-vaultwarden --json isDraft,isPrerelease,assets --jq '{isDraft, isPrerelease, assets: [.assets[].name]}'
```

应为草稿，含上述七个文件（两个 DMG、两个 tar.gz、SHA256SUMS.txt、两个 manifest）。把 release 页面地址 `https://github.com/vfasky/mygo-vaultwarden/releases` 告诉用户，请用户检查说明和文件。

### 5. 公开（需用户再次明确同意）

```sh
gh release edit v<版本> --repo vfasky/mygo-vaultwarden --draft=false --latest
```

prerelease 不加 `--latest`。公开后核对应用实际读取的更新源：

```sh
for target in arm64 amd64; do
  curl -sL https://github.com/vfasky/mygo-vaultwarden/releases/latest/download/update-darwin-$target.json | plutil -extract version raw -o - -
done
```

两行输出都应为新版本号。旧版本应用会在下次自动检查（每天一次）或用户点“检查更新…”时收到更新。

### 6. 更新介绍网站

介绍网站 https://mygo-vault.vfasky.com 的下载按钮和更新日志，在部署时从 GitHub 已公开的 release 生成，公开后要重新部署才会出现新版本。部署到 Cloudflare 是对外操作，release 公开后告诉用户并在同意后执行：

```sh
cd web && bun install && bun run deploy   # 同步 GitHub release 数据，再 cf deploy
```

同步脚本对缺少 English 段的版本会输出警告，出现时告诉用户。部署后核对：

```sh
curl -s https://mygo-vault.vfasky.com/data/releases.json | grep -m1 '"version"'
```

应为新版本号。草稿和 prerelease 不会出现在网站上。

## 出错时

| 现象 | 处理 |
|---|---|
| `MARKETING_VERSION is …, mygo.json version is …` | 回到第 2 步，三处版本改成一致 |
| `CHANGELOG.md has no "## <版本>" section` | 补上该版本小节（含中文与 English 两段）并提交 |
| 网站同步提示缺少 English 段落 | 已公开的 release 可用 `gh release edit v<版本> --notes-file` 补双语说明（对外操作，先征得同意），再重新部署网站；应用内已签名的更新说明不会随之改变 |
| `Commit or stash the changes …` | 工作区有未提交改动；告诉用户，不要替别人的改动做决定 |
| `Tag v<版本> exists on another commit` | 不要移动 tag；确认是否已发布，必要时提高版本号 |
| `Release v<版本> is already published` | 已公开的版本不能改，提高版本号重新发布 |
| `No update signing key` | 私钥应在登录钥匙串（服务名 `MyGo Vaultwarden update signing key`）或 `~/Library/Application Support/mygo/update-keys/mygo-update.key`；都没有时停下告诉用户，不要重新 `mygo keygen`（新密钥会让已安装的应用拒绝更新） |
| 签名身份缺失、`Missing signing identity` | 检查 `.local/signing.env` 与钥匙串中的 Developer ID 证书，交给用户处理 |
| 公证 `status: Invalid` | 用 `xcrun notarytool log <submission id> --keychain-profile "$MYGO_NOTARY_PROFILE"`（profile 名在 `.local/signing.env`）查看原因，报告给用户 |
| 推送或上传中途失败 | 修复后直接重跑 `bash scripts/release.sh --yes`：同版本文件会重新生成，草稿中的文件会被覆盖，已存在且指向当前提交的 tag 会复用 |

## 汇报

完成后告诉用户：版本与 tag、提交、草稿或公开状态、release 地址、上传的文件、网站是否已更新；以及哪些步骤未执行或失败。没有执行公开时明确说明应用还收不到更新，网站也不会显示新版本。
