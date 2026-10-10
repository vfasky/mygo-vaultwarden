# 第三方来源与许可证

本项目 Copyright © 2026 vfasky，采用 GNU General Public License v3.0 only（`GPL-3.0-only`），完整条款见 [LICENSE](LICENSE)。

## MyGo

- 项目：https://github.com/egoist/mygo
- 固定依赖版本：v0.2.15
- 许可证：MIT
- 本项目使用官方 Native UI 模板作为 Go 主应用的起点，界面使用 MyGo 的 `ui` 包。
- MyGo 及其依赖的原始许可证随对应 Go module 保留；打包时 `scripts/collect-licenses.sh` 将相关声明写入应用 Resources/ThirdPartyLicenses。

## KeePassium

- 项目：https://github.com/keepassium/KeePassium
- 参考提交：`e651df4f89b0b8550371566ca9aa55a964d2904e`
- 版权：KeePassium Labs；相关参考文件头部标注 Copyright © 2018–2025 KeePassium Labs。
- 许可证：GNU GPL v3。
- 参考文件：
  - `KeePassium AutoFill/CredentialProviderViewController.swift`
  - `KeePassium AutoFill/AutoFillCoordinator+quickMode.swift`
  - `KeePassiumLib/KeePassiumLib/util/autofill/QuickTypeAutoFillStorage.swift`
  - `KeePassium AutoFill/KeePassium_AutoFill-macOS.entitlements`
- 借鉴内容：将系统回调与凭据选择分离；无交互请求返回 `userInteractionRequired` 进入交互流程；使用稳定 record ID 注册系统候选；独立配置扩展权限。
- 当前扩展 UI 为针对 macOS AppKit 编写的实现，未整体移植 KeePassium 的 UIKit/Mac Catalyst 界面或 KDBX 密码库代码。后续移植源码时，应保留原文件的版权和许可声明，并标注修改。

## Bitwarden 加密协议与测试向量

- 项目：https://github.com/bitwarden/sdk-internal
- 参考目录：`crates/bitwarden-crypto/src/keys/{kdf,master_key,utils}.rs`。
- 固定测试向量来源：上述文件中的 KDF、登录哈希与 HKDF 单元测试（GPLv3 部分）。未引入 `bitwarden_license` 目录或商业 SDK 包。
- Go 协议适配使用标准库和 `golang.org/x/crypto` 实现基础算法，并与官方固定向量及官方 CLI 核对。测试向量引用保留其来源；项目整体为 GPLv3。
- URI 规范化使用 `golang.org/x/net/idna` 与 `publicsuffix`；这些依赖的许可证随应用的第三方声明一起收集。
- Bitwarden CLI 仅用于隔离环境中的兼容性核对，不随产品发行。

## 固定官方主密码评分

以下登记 `internal/passwordstrength` 新增的固定算法资源与 Go 运行时依赖。发布包含本评分功能的制品时，应一并保留本声明和链接的许可证全文；`scripts/collect-licenses.sh` 同时收集这些源码树内的许可证。

| 组件 | 固定版本 / 来源 | 许可证全文 |
|---|---|---|
| Dropbox zxcvbn | npm 4.4.2，未经修改的完整 dist 与词典；版权 2012–2016 Dropbox, Inc. | [MIT](third_party/zxcvbn/LICENSE.txt) |
| dop251/goja | v0.0.0-20261007120015-921e62952efd | [MIT](third_party/licenses/goja.txt) |
| dlclark/regexp2/v2 | v2.8.1 | [MIT](third_party/licenses/regexp2.txt) |
| go-sourcemap/sourcemap | v2.1.3+incompatible | [BSD-2-Clause](third_party/licenses/sourcemap.txt) |
| google/pprof | v0.0.0-20230207041349-798e818bf904 | [Apache-2.0](third_party/licenses/pprof.txt) |

版本、完整性校验、官方客户端来源和输入/Unicode/资源边界见[评分模块说明](internal/passwordstrength/README.md)。Go module 依赖由 go.mod/go.sum 固定；未把额外第三方源码复制进项目，除上述许可证与 zxcvbn 原始发布文件。
