# 更新日志

每个版本分“中文”和“English”两段，内容一一对应。这一节会写入 GitHub release 说明和应用的更新窗口，介绍网站也从 release 读取两种语言。

## 0.1.6

### 中文

- 修复后台同步下载期间无法读取保险库秘密的问题，同步进行时仍可正常查看和使用凭据。

### English

- Fixed an issue where Vault secrets could not be read while a background sync was downloading; items can now be viewed and used during a sync.

## 0.1.5

### 中文

- 两步登录验证界面改版：先选择验证方式，再输入验证码；可随时返回切换其他方式，恢复码入口单独列出。
- 编辑或保存条目后不再重复同步整个密码库，同步更快。
- 同步完成时界面不再短暂卡顿。

### English

- Redesigned two-step login: choose a method first, then enter its code. You can go back to other methods at any time, and the recovery code option is listed separately.
- Saving or editing an item no longer syncs the whole vault twice, so syncing is faster.
- The app no longer briefly freezes when a sync finishes.

## 0.1.4

### 中文

- 通过系统自动填充填入账号密码后，可自动把该条目的当前验证码（TOTP）复制到剪贴板；可在“设置 → 本机存储与自动填充”关闭。
- 只有一个匹配凭据时，自动填充弹窗出现后直接发起系统认证，少点一步。
- 升级 MyGo 框架。

### English

- After AutoFill fills a login, the item's current verification code (TOTP) can be copied to the clipboard automatically. Turn this off in Settings → Storage & AutoFill.
- When only one credential matches, AutoFill starts system authentication as soon as the sheet appears, saving a click.
- Updated the MyGo framework.

## 0.1.3

### 中文

- 分别提供 Apple 芯片与 Intel 版本，安装包体积约减半。
- 修复应用内更新后应用无法打开的问题。
- 0.1.2 及更早版本需手动下载 DMG 安装一次，之后可在应用内更新。

### English

- Separate builds for Apple silicon and Intel; installers are roughly half the size.
- Fixed an issue where the app would not open after an in-app update.
- Versions 0.1.2 and earlier need one manual DMG install; after that, updates happen in the app.

## 0.1.2

### 中文

- 安装包改为 DMG，打开后可直接把应用拖进“应用程序”。
- 设置中的语言选择改为单选卡片，并缩短侧栏英文标签避免换行。
- 修复切换语言后，底部同步状态仍显示旧语言的问题。

### English

- The installer is now a DMG: open it and drag the app straight into Applications.
- The language picker in Settings is now single-select cards, and sidebar English labels are shortened to avoid wrapping.
- Fixed the bottom sync status still showing the old language after switching languages.

## 0.1.1

### 中文

- 重新设计系统自动填充弹窗，加入应用图标与统一的按钮布局。
- 修复已安装版本提示“无法在当前安装位置自行更新”、无法检查更新的问题。

### English

- Redesigned the system AutoFill dialog with the app icon and a consistent button layout.
- Fixed installed builds reporting “cannot update in the current location”, which blocked update checks.

## 0.1.0

### 中文

- 支持个人密码库的登录、解锁、同步、搜索、编辑及附件管理。
- 支持主密码、Touch ID 解锁和 macOS 系统自动填充。
- 提供文件夹、收藏、归档、回收站、批量管理及 Bitwarden 兼容 JSON 导入导出。
- 优化三栏布局、编辑抽屉、删除确认和按钮交互，支持网站图标缓存。
- 提供独立设置与账号中心窗口，支持简体中文、英文及签名自动更新。

### English

- Personal vault: sign in, unlock, sync, search, edit and manage attachments.
- Master password, Touch ID unlock and macOS system AutoFill.
- Folders, favorites, archive, trash, bulk management, and Bitwarden-compatible JSON import/export.
- Refined three-pane layout, edit drawer, delete confirmation and buttons; website icon cache.
- Standalone Settings and Account Center windows, Simplified Chinese and English, and signed automatic updates.
