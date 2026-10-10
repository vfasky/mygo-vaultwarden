# 应用图标

图标以用户提供的 Vaultwarden 标识为参考，保留 V 字、齿轮圆环和顶部菱形；去除横排文字，采用石墨黑金属标记与浅银色底面。

## 文件与构建

- `resources/branding/vaultwarden-master.png`：生成服务返回的 1254×1254 完整方形原稿，保留未裁切底面。
- `resources/icon.png`：1024×1024 PNG，供 `mygo.json` 的 `icon` 字段使用。
- `macos/App/AppIcon.icns`：包含 16、32、64、128、256、512、1024 像素表示的 macOS 图标；Xcode 主应用 Resources 阶段复制它，Info.plist 的 `CFBundleIconFile` 引用它。

本项目最低支持 macOS 14，当前 MyGo v0.3.7 使用传统 PNG → ICNS 流程，不会自动添加图标圆角。运行时 PNG 因此采用与 MyGo 默认图标一致的 100px 外边距、824px 底板和 185px 圆角半径，外部透明，底板不透明，并带轻微阴影。这些数值来自 MyGo 默认图标实现，不是 Apple 规定的通用数值。

Apple 当前 Icon Composer 分层流程要求未预先裁切的完整底面；保留的方形原稿可用于以后重新制作该版本。本次交付是兼容当前工程的传统 macOS 图标，不是分层 Liquid Glass `.icon` 工程，也不是 iOS App Store 上传资源。

## 重新生成

macOS 上需要 Xcode 命令行工具和提供 `Bun.Image` 的 WorkTony Bun 运行时：

```sh
"${WAKU_BUN_EXECUTABLE:-bun}" scripts/generate-icons.ts
```

脚本使用 Bun.Image 归一化和缩放、AppKit 裁切与合成透明边距、系统 `iconutil` 打包完整的 1×/2× ICNS。原稿保持不变，临时 iconset 自动清理；生成的 PNG 和 ICNS 一起提交即可，正常构建不依赖 Bun。

## 规范依据

- [Apple App icons](https://developer.apple.com/design/human-interface-guidelines/app-icons)
- [MyGo distribution](https://github.com/egoist/mygo/blob/v0.3.7/docs/distribution.md)
- 本机 MyGo v0.3.7 的 `cmd/mygo/init.go`（默认图标）、`cmd/mygo/icon.go`（ICNS 打包）。

图像生成请求使用 `gpt-image-2.5`；服务端未报告实际图片模型版本。
