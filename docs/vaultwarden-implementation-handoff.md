# 同卡续作交接：groups 已落地，下一步 policies

**INCOMPLETE — 整卡未完成，禁止 Review / merge。** 协调者本轮通过 `contact_supervisor(need_decision)` 批准：在剩余上下文不足以安全迁移跨模块策略授权时，保存groups成果、准确清理、干净提交后续启同卡；完整原范围不缩减。以本文之后 `git log/status` 的最新HEAD为准，不回退或重新导入。

## 基线与本轮结果

- 开始HEAD `5710bf295cf5b1ddfcdc4b186a7d4299b6c75e96`；全部既有提交及用户成果baseline保留，未读真实凭据、未接生产、未改主目录或用户进程。
- 代码：`internal/vaultwarden/group_management.go`；原生：`group_management_ui.go`、`organization_management_ui.go`；单元/真实/headless测试均以 `group_management` 命名。README、coverage和[群组专题](organization-groups.md)同步。
- 群组新增/列表/完整详情/成员和集合访问配置/编辑/删除已接业务表单，群组名明文、集合名解密。owner/admin与UseGroups门控、ID与目录分页严格核验、未知字段大整数保留，取消/锁定/迟到响应沿现有epoch。
- 固定1.37.4所有group GET **没有accessAll**，PUT无条件覆盖且缺省false：`src/db/models/group.rs:75–109`、`src/api/core/organizations.rs:2454/2467`。协调者批准：不得猜原值或声称无副作用更名。每次保存必须从未选择状态明确选全部集合（含未来新增）/仅指定集合（空集明确无授权），并显式确认。
- `GroupConsent` 私有整草稿绑定org/group/scope/revision、原可读文档、member/collection映射及目标值；有效保存尝试消耗确认，目标改变/重载使其失效；写前重新读取全部可读源状态。隐藏accessAll并发不可检测，GET→PUT无CAS。
- 所有已有group修改/删除通过真实生产`quarantineOrganization`回调先持久隔离目标组织；个人及其它组织保留，普通sync不恢复，须侧栏明确重新核验。保存非事务可能部分执行，异常成功身份/5xx/取消是未知结果不重试。Group GET plural-details、plain单组别名与批量delete尚未调用/实现。

## 实际验证与资源

使用 `GO=$(bash scripts/resolve-go.sh)` 后执行：

- `"$GO" test ./...`、`"$GO" build ./...`、`"$GO" vet ./...`、`"$GO" test -race ./...` 全部通过（末次结果以最终报告为准）。
- `MYGO_VW_GROUP_TEST=1 "$GO" test ./internal/vaultwarden -run '^TestLiveGroupManagement$' -count=1 -v` 通过。测试自建独有1.37.4 Docker实例，唯一`mygo-groups-UUID`名称/`mygo.fixture`标签、回环随机端口，example.invalid账号，无SMTP、不外发。
- 真实角色覆盖：owner创建/读取/编辑/删除；admin创建/读取/删除；普通member及manager拒绝群组管理；owner设置true→false空集合→true→false，通过普通member sync集合投影确认撤回/恢复。GET仍保持范围unknown。**真实服务里的isolate是计数替身，仅证明回调顺序，不声称Keychain/AutoFill实际运行**；生产接现有持久隔离桥。
- 单元：范围必须显式、旧确认/重放、关联及opaque、目录分页/跨org/源变化、隔离与checkpoint失败、旧revision、成功响应错误身份、503不重试、取消/Close期间写入未知结果。headless：权限入口、功能关闭、业务字段、两阶段确认、取消保稿、锁定清表单。
- 开发中曾有一条checkpoint测试误期待ErrCheckpoint而真实回调错误原样返回，已改为检查实际sentinel与零写；Close测试的HTTP handler未读body导致server.Close等待，已补独立release通道保证测试资源退出，之后检查通过。不是未修复产品失败。
- 未改Swift/桥协议，**本轮未跑Swift/bridge**；历史52 Swift等证据见既有提交，不算新验证。未启动真实窗口/安装/访问用户剪贴板。
- 每个容器cleanup均先用完整ID校验唯一label，再`docker rm -fv ID`；末次 `docker ps -a --filter 'name=mygo-groups-' --format '{{.ID}} {{.Names}}'` 无输出。只清理自有资源。临时公开源码在本轮`$TMPDIR=/tmp/pi/01a115a5-eed5-7199-9842-8e06cc7f0330`，无测试账号邮件或密钥导出。

## 下一进程直接 policies：已批准的接口方向，尚未实现

不要再做SMTP/成员基线调查，也不要把这里的设计当产品完成。下一优先为完整策略业务表单 + 实际客户端策略执行，随后legacy无item-key共享，再原完整其它模块。

固定1.37.4 `organizations.rs:1923–2160`：GET list/单type、PUT包裹`{"policy":{"enabled":bool,"data":...}}`；启用2FA和SingleOrg可撤销成员且先产生副作用，非事务。`src/db/models/org_policy.rs`仅支持 **0/1/2/3/5/6/7/8/14/15/16/20**；SSO type4、timeout9等没有实现，不能伪造。先对照实际helper及客户端适用范围，不能简单给所有角色一律加约束。

协调者已批准新增私有Session策略状态（可用`BindVaultPolicies(vault, revision)`或更合适认证上下文）及统一写前guard。完整约束：

1. 只能由本session已核验server/account/profile/wrapped key的完整sync，或认证解锁返回的VaultData绑定当前获授权snapshot revision。调用方随便传入伪造/缺policy文档不能当无政策。旧revision/scope、closed、新sync、隔离均使旧策略授权失效。
2. 与`BindSnapshotRevision`明确更新顺序，避免先换revision仍用旧policy；refresh checkpoint成功后再次核验，不能意外授予陈旧policy。在线写必须取得最新可获得的权威政策；读取错误、无法解析/确定适用权限要失败关闭，不能当作无政策。
3. `Session.mu`内不能递归调用公共Sync/加锁方法；采用内部guard避免死锁。bulk/import可绑定一次明确核验上下文并逐步检查取消/epoch/撤销，不按每个字段重复全sync。policy读取不能复活被隔离组织或引入自动重试。
4. 迁移全部生产personal create/update/copy/import/bulk/metadata、组织share/write以及后续Send/账号路径；按政策真实作用区分，不能一律封禁已有条目合法读取/编辑。fixture也绑定可信上下文，**禁止为旧测试加生产绕过开关**。断网只读可依认证快照，真实写不能用陈旧快照绕政策。
5. 管理页逐type业务控件、影响确认、原值/未知data无损、owner/admin/feature权限、启停依赖；危险策略准确告知收回访问与持久隔离；尚未有依赖产品功能明确后续接入，不能声称已执行却忽略。
6. 主密码minComplexity不能用字符种类冒充zxcvbn。协调者批准后续定向核对固定clients/SDK输入/词典/用户相关输入/Unicode评分，选许可证兼容等价实现及固定独立向量；当前账号密码更改产品未落地，该依赖仍待实现，政策页不能虚称支持。

现有接口/调用点：

- `internal/vaultwarden/client.go:276` Session；`:342` `SyncWithCheckpoint`在锁内GET `/api/sync`核验profile id/email/key，构造完整VaultData；当前没有策略状态。
- `internal/vaultwarden/item_authorization.go:35` `BindSnapshotRevision`；`session_state.go:45/61` checkpoint/`RestoreSession`；`authenticated.go:115` guard在refresh/checkpoint后、dispatch前执行。
- `session_storage.go:46`生产checkpoint revision更新；`cipher_editor.go:134/186`授权绑定与`:549–563`写入口；`cipher_comparison.go`、`personal_secret.go`也绑定revision。
- `cipher_create.go:9` `CreatePersonalCipher(ctx,scope,fields,persist)`没有VaultData；`ciphers_api.go` update、`cipher_copy.go`、`backup_import.go`、`cipher_bulk.go`、`organization_write.go`应统一迁移。不要只加UI拦截。

固定clients `5983f56ce0cf924eea56c7d8f066f7885825a7ce` 对应路径：`apps/web/src/app/admin-console/organizations/policies/policy-edit-definitions/{master-password,password-generator,restricted-item-types,uri-match-default,reset-password}.component.ts` 本轮原站读取成功，临时`policy-*.ts`文件仅参考；send-options单个fetch socket失败未伪称拿到（服务器org_policy.rs已有disableHideEmail字段定义）。主密码控件含minComplexity/minLength/requireUpper/Lower/Numbers/Special/enforceOnLogin；策略14/15/16/20等仍须定向读实际消费方，不能根据名字猜。

固定VW缓存 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/` commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`；clients/sdk tree同目录，SDK固定`39dbb510f5eae82f5cbfd527b0f70a01d5626ec1`。GitHub原站失败才读既定mirror fallback skill。

## 完整剩余范围仍保留

policies/events/Public API/API keys/完整管理员recovery及已accepted登记、legacy完整共享、组织import/export/复制/批量/冲突、附件/Send、注册账号轮换/MFA/SSO/platform/device/emergency/通知、4MiB桥大库、安全离线迁移/AutoFill、个人双改数组逐行选择及reprompt批量/导出、含附件/FIDO2无损备份复制等均继续原验收，不以暂拒绝冒充服务器限制。矩阵及专题保留实际边界。未完成前不要创建Review/merge；主目录dirty的最终合并协调仍由父进程处理。
