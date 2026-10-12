---
name: mygo-upgrade
description: 升级 MyGo 框架（github.com/egoist/mygo）及相关 Go 依赖：检查最新版本、更新 go.mod/go.sum、tidy、构建验证。用户提到 mygo 发了新版本、更新依赖、升级 mygo、go get -u 时使用。
---

# MyGo 依赖升级流程

## 必须遵守

- 开始前先 `git status --short`，记录 `go.mod`/`go.sum` 是否已有未提交改动（可能已经手动升过），不要覆盖或回退。
- 默认只升级 mygo；`golang.org/x/*` 等其他依赖是否一并升级，用户没说时先问或在结果中说明可以退回。
- 不自动提交、不推送；升级完成后汇报改动，由用户决定。

## 步骤

1. 查看当前与最新版本：
   ```
   grep mygo go.mod
   go list -m -versions github.com/egoist/mygo | tr ' ' '\n' | tail -5
   ```
2. 只升级 mygo：
   ```
   go get github.com/egoist/mygo@latest
   ```
   用户要求全部依赖更新时，改用 `go get -u ./...`。
3. 整理依赖：`go mod tidy`（会把 `golang.org/x/image` 等在直接/间接依赖间调整）。
4. 验证构建：`go build ./...`，必要时 `go test ./...`。`go.mod` 里的 `tool github.com/egoist/mygo/cmd/mygo` 随模块版本一起更新，无需单独处理。
5. 查看 `git diff --stat`，确认改动仅限 `go.mod` 和 `go.sum`，向用户汇报：mygo 新旧版本、其他被升级的依赖、构建/测试是否通过。

## 注意

- 若 mygo 新版本带来 API 变化导致构建失败，先读其 release notes 再改代码，不要降级绕过。
- 升级 mygo 后如需打包验证，用 `mygo.json` 对应的构建命令；发版走 `vaultwarden-release` skill。
