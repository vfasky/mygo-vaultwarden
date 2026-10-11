---
name: vaultwarden-release
description: 发布 MyGo Vaultwarden 新版本：改版本号与 CHANGELOG、在本机用 Developer ID 签名公证、生成签名更新包、推送 tag 并上传 GitHub 草稿 release，再按确认公开。用户提到发布、发版、升级版本、打 tag、上传 release、推送更新、release a new version 时使用。
---

# MyGo Vaultwarden 发布流程

发布全部在本机完成，入口是仓库里的 `scripts/release.sh`，不使用 CI。它使用本机的 Developer ID 证书与公证 profile（`.local/signing.env`）和本机的更新签名私钥。原理、文件格式与手动分步方式见 `docs/updates.md`。

## 必须遵守

- 版本号和更新内容由用户决定。用户没给时先问，不要自己编版本号或 CHANGELOG 内容。
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

在 `CHANGELOG.md` 的 `# 更新日志` 下、上一个版本之前新增：

```markdown
## <版本>

- 面向用户的改动，一条一行。
```

这一节就是 release 说明和应用更新窗口里显示的内容。用户只给了大致方向时，可根据 `git log v<上一版本>..HEAD --oneline` 起草，交给用户确认后再写入。

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

整个过程约 2–5 分钟（测试、Xcode 归档与导出、Apple 公证、生成文件、推 tag、上传），用足够长的超时。它会：

1. 核对三处版本、CHANGELOG、tag 未指向其他提交、同版本 release 未公开。
2. `go vet` 与 `go test -tags headless`。
3. `scripts/build-macos.sh release --notarize`：Developer ID 签名、公证、staple。
4. 生成 `build/updates/<版本>/`：`mygo-vaultwarden-<版本>-darwin-universal.tar.gz`、`update-darwin-universal.json`、`MyGo-Vaultwarden-<版本>-macOS.zip`、`SHA256SUMS.txt`、`notes.md`。
5. 创建并推送 tag `v<版本>`，创建草稿 release；先上传 zip、归档、校验文件，最后上传 manifest。

用户只想先检查产物时用 `--no-upload`（不打 tag、不上传）。其他选项：`--skip-tests`、`--publish`（见下）。

推送 tag 会把它指向的提交一起推到 GitHub；本地 `main` 领先 `origin/main` 时，这些提交会一并公开。执行前提醒用户。

### 4. 核对草稿

```sh
gh release view v<版本> --repo vfasky/mygo-vaultwarden --json isDraft,isPrerelease,assets --jq '{isDraft, isPrerelease, assets: [.assets[].name]}'
```

应为草稿，含上述四个文件（zip、tar.gz、SHA256SUMS.txt、update-darwin-universal.json）。把 release 页面地址 `https://github.com/vfasky/mygo-vaultwarden/releases` 告诉用户，请用户检查说明和文件。

### 5. 公开（需用户再次明确同意）

```sh
gh release edit v<版本> --repo vfasky/mygo-vaultwarden --draft=false --latest
```

prerelease 不加 `--latest`。公开后核对应用实际读取的更新源：

```sh
curl -sL https://github.com/vfasky/mygo-vaultwarden/releases/latest/download/update-darwin-universal.json | plutil -extract version raw -o - -
```

输出应为新版本号。旧版本应用会在下次自动检查（每天一次）或用户点“检查更新…”时收到更新。

## 出错时

| 现象 | 处理 |
|---|---|
| `MARKETING_VERSION is …, mygo.json version is …` | 回到第 2 步，三处版本改成一致 |
| `CHANGELOG.md has no "## <版本>" section` | 补上该版本小节并提交 |
| `Commit or stash the changes …` | 工作区有未提交改动；告诉用户，不要替别人的改动做决定 |
| `Tag v<版本> exists on another commit` | 不要移动 tag；确认是否已发布，必要时提高版本号 |
| `Release v<版本> is already published` | 已公开的版本不能改，提高版本号重新发布 |
| `No update signing key` | 私钥应在登录钥匙串（服务名 `MyGo Vaultwarden update signing key`）或 `~/Library/Application Support/mygo/update-keys/mygo-update.key`；都没有时停下告诉用户，不要重新 `mygo keygen`（新密钥会让已安装的应用拒绝更新） |
| 签名身份缺失、`Missing signing identity` | 检查 `.local/signing.env` 与钥匙串中的 Developer ID 证书，交给用户处理 |
| 公证 `status: Invalid` | 用 `xcrun notarytool log <submission id> --keychain-profile "$MYGO_NOTARY_PROFILE"`（profile 名在 `.local/signing.env`）查看原因，报告给用户 |
| 推送或上传中途失败 | 修复后直接重跑 `bash scripts/release.sh --yes`：同版本文件会重新生成，草稿中的文件会被覆盖，已存在且指向当前提交的 tag 会复用 |

## 汇报

完成后告诉用户：版本与 tag、提交、草稿或公开状态、release 地址、上传的文件；以及哪些步骤未执行或失败。没有执行公开时明确说明应用还收不到更新。
