# 介绍网站

纯静态页面（HTML/CSS/少量 JS），中英双语，部署在 Cloudflare Workers 静态资源上，域名 `mygo-vault.vfasky.com`。

- `public/`：站点文件。`public/data/releases.json` 由脚本生成，不要手改。
- `scripts/sync-releases.mjs`：读取 GitHub Releases，生成下载链接与更新日志数据。release 说明按 `### 中文` / `### English` 拆分语言，内容来自仓库根目录的 `CHANGELOG.md`；`MIN_VERSION` 之前的版本不展示。

## 发布流程

新版本在 GitHub 公开 release 后：

```sh
cd web && bun run deploy        # 等价于 sync + cf deploy
```

本地预览：`bun run dev`，打开 http://localhost:8787。仅预览前先 `bun run sync`。
