# 群组管理（Vaultwarden 1.37.4）

整卡 **INCOMPLETE**。此增量实现群组原生管理，不代表 policies、events、完整 recovery 或其它 API 已完成。

## 固定协议与产品入口

固定服务器 commit `7c188967e7a467b19b2757bc3326f9cf3ccae327`：`src/api/core/organizations.rs:2386–2740`、`src/db/models/group.rs:75–109`。

组织管理 → 群组管理提供列表、新建、名称、成员姓名/邮箱选择、集合解密名称及只读/隐藏密码/管理权限、删除、影响确认和取消。仅 owner/admin；组功能关闭明确提示。群组名称为明文，集合名称端到端加密。集合级或全组织经理均没有群组管理权限。

| method/path（均以 `/api/organizations/{orgId}` 为前缀） | 产品调用与边界 |
| --- | --- |
| GET `/groups` | `OrganizationGroups`；拒绝缺失数组、重复/跨组织ID、未处理分页与错误；不将失败当空目录 |
| POST `/groups` | `GroupDetails(..., "")` → `SaveGroup`；明确范围与全草稿确认；保留users/collections/externalId/opaque |
| GET `/groups/{groupId}/details` + GET `/groups/{groupId}/users` | `GroupDetails`；还读取完整 `/users` 与 `/collections`，验证成员ID≠全局账号ID、当前身份、组织ID、全部关联 |
| PUT `/groups/{groupId}` | `SaveGroup`；重新读取全部可读原状态，比对后仅一次提交；必须指定访问范围并使用绑定全草稿的私有确认 |
| DELETE `/groups/{groupId}` | `DeleteGroup`；原生独立删除确认，保留条目本身，只解除群组关联 |
| GET `/groups/details`、GET `/groups/{groupId}`、DELETE `/groups` | 尚未调用/批量删除尚未实现；不得算作全量路由完成 |

## accessAll 的不可见原值

固定版所有群组 GET 都不返回 `accessAll`，但 `GroupRequest.access_all` 缺省 false，PUT 无条件覆盖它（`organizations.rs:2454,2467`）。不能从有效权限或集合数组推断原值，也不能声称更名无副作用。

- `GroupScopeUnset` 与 false 分开；新建、重载已有群组均不预选范围。
- 保存必须明确选择「全部集合（含未来新增集合）」或「仅选定集合」。空选定集合明确表示不经此群组授予集合访问；其他直接授权仍按服务器规则执行。
- 即使仅更名，也必须确认本次保存应用所选访问范围。UI确认阶段冻结字段；取消保留草稿且不写入。
- `GroupConsent` 私有副本绑定组织/群组/账号服务器scope/revision、全部可读文档、成员/集合目录和目标字段。目标变化不接受旧确认；重新加载清除确认；有效提交尝试消耗该确认。保存前重新核对源状态。未公开accessAll并发变化不能检测，GET→PUT也没有CAS。
- 更名与单项修改保留其余成员/集合关联、外部ID与未知JSON字段（包括大整数），不把集合投影当完整直接分配。群组全访问及直接集合优先级继续使用服务器结果，不在客户端简单OR。

## 安全与故障

所有已有群组编辑或删除可能改变当前访问，故请求前通过现有 `quarantineOrganization` 生产存储回调持久隔离目标组织；个人与其它组织保留，随后须从侧栏明确联网重新核验恢复。隔离失败零写；错误不能假回滚或通过普通sync自动取消隔离。

认证刷新沿现有checkpoint先持久化；旧scope/revision、取消/Close拒绝；写后取消、非预期状态、5xx、成功响应身份不符按未知结果处理。成功响应核验groupID/orgID/name。UI未知结果禁重复保存，提示同步核对。服务器写群组及成员/集合映射非事务：失败可能已有部分结果，不自动重试。

## 本轮证据

- `group_management_test.go`：仅更名未选范围零写、true/false请求、空集合、完整成员与opaque保留、跨组织身份、目录分页、源状态变化、目标变化确认失效、确认不可重放、隔离失败、checkpoint失败、旧revision、写后响应身份错误、503未知结果、请求前取消与PUT/POST期间Close无重试。
- `group_management_ui_test.go`：普通成员无入口、feature关闭提示、原生业务字段、未选范围不能确认、两阶段确认/取消保稿、锁定擦除表单。使用 headless MyGo tester，未查看真实窗口。
- `MYGO_VW_GROUP_TEST=1 go test ./internal/vaultwarden -run '^TestLiveGroupManagement$' -count=1 -v`：测试自行create/start唯一标记、唯一回环端口的1.37.4容器，example.invalid账号，无SMTP。owner新建/读/改/删除；admin新建/读/删除；普通成员及manager管理拒绝。true→false（空集合）→true→false后通过普通成员sync集合投影确认权限撤回/恢复，GET仍不推断accessAll。真实测试隔离callback为计数替身，不能声称真实Keychain/安装/AutoFill通过；生产复用已验证持久隔离桥。cleanup按完整容器ID及唯一label核对后删除，不触碰其它容器。
- Go全仓test/build/vet/race通过。Swift/bridge未改，本轮没有重复运行，历史证据不可算新执行。

本轮没有实现groups批量路由；没有实现policies管理或策略会话上下文。后续策略执行方向与既有完整剩余范围见最新handoff。
