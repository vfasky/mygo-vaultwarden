# 个人文件格式与互操作

此功能为整卡的一个模块，完整 API 仍未完成。入口为顶栏「导入导出」。文件包含明文秘密，需要用户明确确认。导出默认勾选当前列表，可逐项调整，也可选择归档和回收站；同时导出全部个人文件夹，包括空文件夹。读取及发布都绑定当前 server/account、本地 snapshot revision 和 UI epoch。打开系统对话框期间不保留导出明文缓冲；返回后重新核对并解密。取消/锁定或陈旧回调不发布文件。

## 文件格式

导入导出只提供 Bitwarden 兼容 JSON，应用不对用户定义自己的文件格式。下表第二行的 MyGo 结构只在应用内部使用（带附件项目创建副本时中转元数据），界面不再提供以此格式导入或导出文件。

| 格式 | 内容与边界 |
|---|---|
| Bitwarden 兼容 JSON `.json` | `encrypted:false, folders:[{id,name}], items:[...]`，逐字段映射官方 camelCase export schema。固定 clients `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 的 `libs/common/src/models/export/cipher.export.ts` 的 `toView`/`build` 分支仅支持1–7类，没有Passport。`libs/importer/src/importers/bitwarden/bitwarden-json-importer.ts` 将历史截断为5条，`BaseImporter.cleanupCipher` 会改写空白名称/备注。故兼容导出对所选范围内Passport、回收站、超过5条历史、无法保留的登录附加设置、空白名称/备注、亚毫秒history时间等整体拒绝，提示改用MyGo备份。兼容子集不受库中其他未选择Passport影响。标准URI校验值须可重建，legacy alias须与首个URI一致，才允许转成官方canonical URIs。 |
| MyGo 内部结构（不对用户开放） | `format:"mygo-vaultwarden-personal-backup", version:1, encrypted:false, folders, items`，明确不是官方JSON；官方格式解析器拒绝此标识。保留1–8类标准字段、多URI与checksum/legacy alias、登录设置/密码修订时间、四类custom、全部history、必要日期与folder引用。尚不支持附件、非空FIDO2、未知扩展或旧key依赖；整文件拒绝，不能称支持任意数据的完整备份。未来schema版本拒绝。 |

导出文件不包含用户key、item key、令牌、服务器/账号凭据。组织项目不导出。reprompt项目在再次验证能力完成前拒绝导出。原样保留密码历史内容；导入创建独立随机64字节item key，以当前user key包装，并以type2加密所有已知秘密。导入重新创建文件夹并映射ID，不按重名合并。归档日期可原样提交，回收站项目先创建再软删；新项目的创建/修订/删除日期由服务器生成，源日期不冒充服务器revision。

文件整体限制32 MiB，最多10,000项目/文件夹，拒绝重复JSON键、非法UTF-8、深层嵌套、混合格式、无效folder引用、未知字段和无法安全转换的数据。在第一次创建文件夹前，对全部项目完成校验及加密。任何写入失败立即停止，显示已创建标识、失败/未知项与同步核对状态；不自动重试整个文件或单项。取消已发出的导入不撤销服务器已完成项目，界面明确要求同步核对。

## 文件安全

macOS/Linux逐级使用目录描述符与 `O_NOFOLLOW` 拒绝符号链接，读取只允许有界普通文件。导出在选择目录生成随机名0600临时文件，写入并fsync；发布使用`linkat`原子不覆盖目标。已有文件、符号链接或并发创建的目标均拒绝，必须另选新文件名。失败/取消/迟到结果删除本次临时文件，不改动已有目标。没有实现覆盖旧导出文件的路径。Go/系统运行时无法保证清零所有字符串历史副本，也不承诺系统崩溃后自动清理遗留临时文件。

## 验证与可重复运行

- `backup_test.go`：八类完整字段往返、不同item key、官方1–7选择、Passport/附件/FIDO2/未知扩展/权限/reprompt/不可重建checksum拒绝、未知版本/混合/畸形/重复键预检零请求、folder映射、历史/归档、部分失败与checkpoint阻断。
- `backup_safety_test.go`：scope混淆零请求、Close中断写入且结果未知、不继续后续项目、超过5条history在MyGo格式保留、非法field/URI/date拒绝。
- `backup_file_test.go`：0600、目标不覆盖、符号链接/父目录链接、并发创建、取消清理、锁定/陈旧revision迟到导出不发布、headless预览/确认/取消。
- `backup_integration_test.go`：隔离1.37.4八类备份真实导入/导出/回收站/归档/历史；独立官方CLI导入1–7类、读取并验证各秘密字段、多网址、四类custom与history，官方CLI导出再由MyGo解析并写回。CLI列表分别查询活动与归档。日期按实际时间比较，custom缺省与null按语义比较。测试只清理自身随机账号中相对此用例起点新建的项目和文件夹。

官方源来自固定commit的raw URL；CLI独立发行版通过 npm `@bitwarden/cli@2026.5.0` 安装于scratch（没有改项目依赖）。tarball SHA1 `3a5a65abd2fa36c0da17ef6a0b751b8bed2cdcbd`，SRI `sha512-lp4P3PJ9/8KGW6SrBGPRof5XHLXYKg+gW9hHJf3WxzuF/uI0HLrvaqPnXixmfazRBuQQhNXJS4bhHPUS998kQg==`。npm未提供gitHead，因此不宣称发行包等同上述commit构建；源码依据与CLI验证版本分别记录。该CLI强制HTTPS，测试通过自有 `httptest.NewTLSServer` 代理至回环容器，以 `NODE_EXTRA_CA_CERTS` 只在子进程信任临时测试证书；没有禁用TLS验证或修改官方CLI。账号为随机 `example.invalid`，公开测试密码，不读取用户凭据。

```sh
GO_BIN="$(bash scripts/resolve-go.sh)"
MYGO_VW_TEST_URL=http://127.0.0.1:<自有容器端口> \
MYGO_BW_CLI=<scratch>/bw-cli/node_modules/.bin/bw \
"$GO_BIN" test ./internal/vaultwarden -run TestLiveVaultwarden -count=1 -v
```

未设置 `MYGO_BW_CLI` 时跳过官方CLI部分并明确记录，不能声称该次已验证官方互操作。没有运行实际原生窗口/Open/Save交互、安装、Keychain、Touch ID或AutoFill验证。组织、附件、Send、加密官方导出/ZIP、其他第三方格式仍待整卡继续实现。
