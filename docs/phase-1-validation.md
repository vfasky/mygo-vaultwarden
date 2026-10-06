# 第一阶段验证记录

日期：2026-10-06。

目标：建立 MyGo Native UI 主应用，嵌入 Swift/AppKit Credential Provider Extension，使用公开测试凭据验证 macOS 系统自动填充入口。

## 当前结论

工程、构建、Developer ID 分发签名、profile、安装和系统扩展配置已实现并实测通过。Safari 测试页已打开，系统候选注册成功。

Safari 最后一次“选择凭据 → 扩展返回 → 表单值检查”仍待人工点选，不能把当前状态写成整个端到端自动填充验收完成。

## 环境

- macOS 27.0.1，Apple Silicon。
- Xcode 27.0，macOS SDK 27.0。
- Go 1.27.1，MyGo v0.2.15。
- Deployment target：macOS 14.0。尚未在 macOS 14/15 或 Intel 实机验证。
- 主应用和扩展均导出为 arm64 + x86_64 Universal Binary。
- Developer ID 签名配置保存在本机被 Git 忽略的 `.local/` 目录。

## 检查结果

| 检查 | 结果 | 证据 |
|---|---|---|
| Go 主应用构建 | 通过 | Xcode shell phase 生成实际 Go Mach-O |
| Swift/AppKit 扩展构建 | 通过 | Xcode 编译并嵌入 `Contents/PlugIns/AutoFill.appex` |
| Xcode archive/export | 通过 | `ARCHIVE SUCCEEDED`、`EXPORT SUCCEEDED`，构建脚本退出码 0 |
| Developer ID 签名 | 通过 | 主应用/扩展的 `codesign --verify --deep --strict` 通过 |
| 受限权限授权 | 通过 | 两个 bundle 含匹配的 `embedded.provisionprofile`，签名含 AutoFill entitlement、团队和 application identifier |
| 已安装主应用启动 | 通过 | `~/Applications/MyGo Vaultwarden.app` 启动并保持运行，窗口可通过辅助功能树读取 |
| 系统设置中的 provider | 通过 | “自动填充与密码”页面显示“MyGo Vaultwarden / 密码”，成功打开扩展配置窗口 |
| 系统候选注册 | 通过 | 点击“启用演示凭据”后扩展日志为 `Demo identity registration completed` |
| 已安装扩展状态 | 通过 | `pluginkit -m -v -i yz.sh.mygo-vaultwarden.autofill` 返回 `+` 和正确安装路径 |
| Safari 本机页面 | 通过 | HTTP 200；Safari 辅助功能树显示用户名、密码和检查按钮 |
| Safari 系统自动填充入口 | 通过 | 用户名字段出现“自动填充密码”按钮并可触发 |
| Safari 最终凭据回填 | 待人工验证 | 系统凭据选择面板拒绝当前自动化进程的辅助访问，未取得回填完成证据 |
| Go 测试和 vet | 通过 | `go test ./...`、`go vet ./...` |
| Swift 匹配测试 | 通过 | 4 tests / 0 failures |
| 配置与脚本 | 通过 | plist、Xcode project lint；shell 语法检查；`git diff --check` |
| 第三方许可证收集 | 通过 | Go、MyGo、purego、typesetting/harfbuzz、x/image 及项目 GPL 文本已收集 |
| 公证 | 未执行 | 仅提供可选 `release --notarize` 流程 |

## 解决的实际问题

### 证书签名不等于受限权限授权

第一次直接使用 Developer ID 对两个 bundle 签名后，静态 codesign 校验通过，但主应用启动被 AMFI 拒绝：

```text
No matching profile found
AppleMobileFileIntegrityError Code=-413
Disallowing yz.sh.mygo-vaultwarden because no eligible provisioning profiles found
```

最终改用 Xcode 自动配置的 archive + Developer ID export。Xcode 创建/配置了本项目主应用和扩展的 App ID、能力及 profile；导出后应用可正常启动。没有复用 Waku 的 bundle ID 或 profile。

### PlugInKit 登记不等于设置页面立即可见

开发目录中的 bundle 可以出现在 PlugInKit 列表里，但最初系统设置列表未出现它。安装到 `~/Applications` 并重新打开系统设置后，provider 可见。安装脚本固定采用这个路径，并登记 Launch Services 和 PlugInKit。

### Xcode Swift debug dylib

扩展关闭了 `ENABLE_DEBUG_DYLIB`，避免调试版另外生成预览/调试动态库，使嵌套代码与发布签名结构更简单。

### 最后一个验收限制

自动化通过已授权的 System Events 操作主应用、系统设置和 Safari 测试页。在读取 `AuthenticationServicesAgent` 的凭据选择面板时，系统返回：

```text
“osascript”不允许辅助访问。(-1728)
```

该限制定位到 AuthenticationServicesAgent；Safari 的测试页面本身可读取。未尝试绕过该系统权限。下一步由用户在 Safari 密码入口选择本应用的演示账号，在扩展中确认填充，再点击网页“检查填充结果”。

## 可复现产物

- 构建产物：`build/debug/MyGo Vaultwarden.app`
- 安装产物：`~/Applications/MyGo Vaultwarden.app`
- 主应用 bundle ID：`yz.sh.mygo-vaultwarden`
- 扩展 bundle ID：`yz.sh.mygo-vaultwarden.autofill`
- 本机测试 URL：`http://localhost:18472/`，在主应用点击“打开 Safari 测试页”后启动。
- 演示账号：`demo@mygo.invalid`。密码来自仓库中的公开 fixture。

构建产物、证书相关 profile、Xcode 缓存均被 Git 忽略。没有提交、推送或发布版本。
