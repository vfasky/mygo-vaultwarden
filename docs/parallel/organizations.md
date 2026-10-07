# Board #8 组织条目、传输和审计模块交接

状态：**INCOMPLETE，不能据此宣称整卡或完整组织客户端完成。** 本次提交包含可独立检查的客户端模块及测试；主应用集成由协调者/#5负责。本模块尚缺下述产品表单、官方明文格式互操作、真实服务器多角色回环与部分结果重读核对。独立 Review 应按完整卡片要求核对这些缺口，不能把单测通过当作整卡通过。

## 基线和范围

工作树初始分支 `waku/board-8-new-worktree`，HEAD `9fee5bd420a76d0cf6ab678cb4a13f5de0221e51`，status干净。按卡片明确授权，在原分支执行 `git reset --hard 14bbaf0ec2f176c598560883cc895f4dcd24405d`。仅新增 `internal/vaultwarden/org_*.go`、根 `org_*.go` 和本文；未修改现有组织/成员/集合/群组/策略/密码文档/附件/存储/网络/主界面、Swift、go.mod。未启动子代理，未访问生产账号或修改主工作树。

协议核对来自卡片指定缓存 `/tmp/pi/01a11459-aaf7-7501-aa57-d5854f080e4b/vw/src/api/core/` 的 ciphers.rs、organizations.rs、events.rs、public.rs；本轮未独立验证该缓存构建镜像的版本/摘要，因此“固定1.37.4”是卡片提供的来源标识，并非本轮实测证明。

## 已实现接口

| 接口 | 实际协议/行为 | 接线责任 |
|---|---|---|
| `Session.ChangeOrganizationCiphers` | 单ID或同组织批量：PUT `/api/ciphers/delete`、`restore`、`archive`、`unarchive`；DELETE `/api/ciphers`。重复/无效ID、跨组织、缺edit/viewPassword、未授权reprompt、未删除直接永久删均拒绝。派发前认证sync核对memberID/globalUserID/role、cipher revision/type/权限及策略。 | 传入当前认证VaultData和每条ItemAuthorization；checkpoint由现有存储适配器处理。返回 `OrganizationOperationResult`。任何不确定结果先sync核对，禁止自动重试。 |
| `AssignOrganizationCipherCollections` | PUT `/api/ciphers/{id}/collections`；调整用户可见关联，服务器可保留该用户不可见的旧关联。差异集合必须本地明确可写。可能撤回自身访问，所以在**任何HTTP前**调用isolate；失败零HTTP。随后live sync核对条目与原关联、政策。空列表编码为 `[]`。 | isolate复用现有原子quarantineOrganization回调；保留pending policies，不能在成功/失败后自动撤隔离。成功回执采用既有adoptOrganizationIsolation；显式重新核验才能恢复。当前只有单条集合分配接口，批量bulk-collections未实现。 |
| `CopyOrganizationCipher` | 真实 POST `/api/ciphers/create`；从认证源组织文档读取，目标组织/集合明确。标准八类型、custom fields、history、legacy URI/checksum重加密到新随机item key，再用目标org key包装。源不改，新建清除ID/创建修订时间/删除归档状态及个人folder。两端策略及当前源权限检查。 | 显示复制语义并明确确认；组织复制专用UI未实现。附件/FIDO2/未知扩展/encryptedByKeyId在HTTP前拒绝，绝不静默剔除。只读源当前保守拒绝。 |
| `WithOrganizationBackup` | GET `/api/organizations/{orgID}/export`，仅owner/admin。结合认证sync与绑定快照核对完整导出项目的权限、策略、revision和reprompt；解密集合名及八类型标准字段。整份预检，任何未知/附件/FIDO2/不支持字段失败，不产生假成功的部分备份。 | 明确 `confirmed`，借用明文给save回调，用毕清buffer；save不可重入Session。根 `exportOrgBackupFile` 复用既有安全文件实现：父目录descriptor/no-follow、0600暂存、原子no-replace发布，不覆盖已有文件。主应用需持有认证snapshot lease并传递锁定取消。 |
| `ParseOrganizationImport` / `OrganizationImportPlan` | 解析严格versioned `mygo-organization-backup` v1。私有计划、只读预览、集合映射，unknown不丢弃而拒绝。此格式保留官方明文导入器可能规范化的legacy URI/checksum等字段。 | **不是官方Bitwarden CLI明文JSON/CSV导入支持，也不是加密备份。** 不得在UI标成官方兼容文件。Close/取消后Clear；有进行中worker时由worker完成后Clear，不并发Clear。Go字符串不能保证历史副本归零。 |
| `ImportOrganizationBackup` | POST `/api/ciphers/import-organization?organizationId=...`。每个源集合必须明确映射既有集合，或空字符串选择新建；目标权限/建集合权限、类型政策预检；重新生成item key；collectionRelationships为条目/集合索引。 | 新建ID及创建/修订日期为服务器生成；有回收/归档或folder元数据的对象暂拒绝，不能无声恢复成普通条目。`IDs`是源预览ID，不是新服务器ID。`Applied`始终false、`ReconcileRequired`始终true（派发后），即使200也只代表请求返回。 |
| `OrganizationEvents` | 组织 GET `/api/organizations/{id}/events`；成员 GET `/api/organizations/{id}/users/{membershipID}/events`；条目 GET `/api/ciphers/{id}/events`。start/end/continuationToken正确编码，显式一次一页，时间窗口/token/跨组织返回检查；未知事件类型数字保留。 | 仅owner/admin入口；成员ID不是global userID。空日志也可能是服务器未启用审计，不得显示“确定没有活动”。不自动无限翻页。 |
| `CollectOrganizationEvents` | POST **`/events/collect`**，不是 `/api/events/collect`。支持组织客户端导出1602及服务器接受的cipher客户端事件1107–1114、1117、1119–1132。校验本组织/cipher关系，拒绝伪造服务端管理事件。 | 只在对应真实客户端动作发生后调用；不能把collect成功当作证明日志已存储（服务器可关闭审计）。banner事件和个人导出1007未实现，不属于本接口支持。 |
| `WithOrganizationAPIKey` | owner + 主密码派生proof + 显式确认；POST `/api/organizations/{id}/api-key` 或 `rotate-api-key`。返回secret仅借给回调，用后clear byte slice，clientID=`organization.{id}`。 | 读取也可能首次创建key；轮换撤销旧key。回调不得重入Session，UI不得写日志或持久保存key。当前未实现原生API key展示/轮换表单。 |
| `ImportOrganizationDirectory` | 仅既有Public目录路由：先组织client credentials获取 `api.organization` token，POST `/api/public/organization/import`，不伪造Public GET/users/groups等路由，不传user token。校验email/externalId重复及group引用；owner/UseGroups门控。 | 显式确认overwriteExisting语义；先isolate，失败零HTTP（含token请求）。借用API secret，不持久化。请求/组/成员全部待核对，返回外部ID用于表格；没有凭空生成逐项成功。当前原生目录表单及认证成员/群组重读差异报告未实现。 |

## 非事务和权限的重要限制

缓存上游 `post_org_import` 对每个 `update_cipher_from_data(...).await.ok()` 忽略结果，因此HTTP200**也可能缺少条目**；不能仅通过状态码产生逐项成功记录。目录import也可能因策略跳过恢复、缺失外部成员引用或服务器关闭群组而没有完成期望状态。本模块只报告请求级acceptance和待核对行，不声明已验证全部成功。尚缺完整产品reconciliation UI，不得把底层结果包装成全绿。

普通组织状态批量遇到非2xx或不确定传输结果，不推断全部失败或回滚。集合调整中途错误保留隔离，不能自动重试。隔离刻意撤销旧offline authority与外部grant；集合操作只在Session锁内保留隔离前已验证grant的短期限给本次操作，并在新epoch检查，不更新/复活外部grant。政策读取不借隔离绕过pending政策。

当前授权由最后认证快照+提交前sync+服务器最终检查组成，不是服务端CAS。sync到写入之间仍有权限/内容并发变化窗口。旧snapshot、错误scope和refresh checkpoint均继续使用基线既有机制，但本卡**未新增覆盖全部旧receipt/refresh失败组合的专属测试**。

## 原生组件与集成

- `newOrgOperationsPanel`：输入已认证组织entry列表、绑定Session/snapshot的execute、UI线程dispatcher。业务列表选择、权限禁用、操作选择、二次确认、取消、进行中和待核对结果；失败/成功后均冻结，不自动重试。需要reprompt的条目不在此多选面板授权，调用方需提供单条授权入口。`Close()`必须在锁定/sync/scope变化时调用，清条目并丢弃迟到回调。
- `newOrgEventsPanel`：输入组织/成员/条目业务筛选所得query、fetch、UI dispatcher。时间表单、事件列表、未知类型数字、分页、取消与迟到结果清理。筛选对象应来自现有业务目录，不能让用户猜原始ID。
- 根 `exportOrgBackupFile`、`readOrgImportPlan`：安全文件绑定，复用既有文件工具而不修改存储核心。
- 未创建全局app映射，未改main或既有组织管理UI。上面两个View需要#5挂载。复制/集合分配/导入预览映射/导出确认/API key/目录的完整原生产品表单仍需实现，不能拿方法存在等同用户入口完成。

## 跨卡精确依赖

1. #3附件与完整跨key复制：需要接受已授权完整source CipherDocument、源/目标owner key及附件迁移能力的转换接口；返回完整新document和明确逐附件结果/不支持原因。未知/FIDO2不能当作明文普通字段或者直接丢弃。当前安全标准对象已实现独立跨key复制，附件/FIDO2/unknown继续失败关闭。
2. #5集成：提供当前Session/VaultData/snapshot lease、checkpoint持久保存回调、持久quarantine及adopt回执、UI线程dispatcher、锁定/sync统一Close；不能用no-op隔离回调接产品。
3. 导入结果：官方接口没有新ID映射/逐项receipt，需一次新sync后按预览/新增集合/条目差异展示，重复内容无法唯一匹配时保留unknown并要求人工核对。不能自动重发整份文件。
4. 目录结果：需隔离状态下由既有管理读取接口核对成员及群组关系，但不能普通sync自动撤隔离或pending policy。MemberID、globalUserID、orgID及externalID均独立展示/传递。

## 本轮验证

已执行并通过：

- `go test ./internal/vaultwarden -run 'TestOrgOperations' -count=1`
- `go test -tags headless ./... -run 'TestOrg(Operation|Event)' -count=1`
- `go test -tags headless ./... -run 'TestOrg(Operation|Event|Collection|APIKey|Copy|Directory)' -count=1`
- `go test ./internal/vaultwarden -run 'TestOrgBackup' -count=1`
- `go test -tags headless ./...`
- `go vet -tags headless ./...`
- `go test -race -tags headless ./... -run 'TestOrg(Operation|Event|Collection|APIKey|Copy|Directory|Backup)' -count=1`（最终审计panel和live-test文件加入后再次通过；live test因未设置隔离fixture URL而skip，未运行HTTP回环）

覆盖：真实路由/请求体、批量非事务HTTP400、只读/隐藏/reprompt拒绝、live权限撤回/版本变化/跨组织、非法ID与取消零请求、集合隔离失败零HTTP、API key owner/确认/secret借用归零、组织Public token路径和隔离、目录重复externalID/缺失组成员拒绝、八类型跨key复制及unknown/附件/FIDO2拒绝、官方export→自有文件→官方import协议加密回环、200不冒充逐项成功、借用导出buffer归零、集合预览不可变、独立UI控制器确认/取消/迟到/分页。

中间集合测试曾失败：隔离会推进authorizationEpoch，最初复用了隔离前epoch，导致操作总是Expired。已修正为隔离成功后只更新本次操作期望epoch，外部grant仍失效；隔离前验证并借用短期限，不延长授权。定向测试及全量通过。未执行的检查没有标记通过。

**未验证**：实际自有1.37.4容器owner/admin/member多角色回环、官方CLI文件互操作、真实窗口/视觉/Keychain/系统AutoFill、原生导入导出和目录/API key全流程、持久隔离接线（只测试借用回调协议，真实存储归基线）、完整checkpoint/旧receipt组合。本次没有外发邮件。

### 回环基础设施失败证据

新增 `TestLiveOrgModule` 可用 `MYGO_ORG_MODULE_TEST_URL` 指向专属loopback服务器，涵盖owner的状态/复制/export-import/collect-events/APIkey/Public目录/集合分配与永久删。普通全量测试默认skip，不算实测。该fixture只有owner，不能替代多角色证明；isolate为一次性服务器fixture的no-op，不能用于产品。

本轮执行 `docker version --format '{{.Server.Version}}'` 得到 `29.4.0`，`docker image ls`确认本地有 `vaultwarden/server:1.37.4`。执行：

```
docker run --rm -d --name mygo-board8-module-01a11726 -p 127.0.0.1::80 -e SIGNUPS_ALLOWED=true -e ORG_EVENTS_ENABLED=true -e WEBSOCKET_ENABLED=false vaultwarden/server:1.37.4
```

返回容器ID `bd3e93ea05926c4923e8b2036949ee260f152e326c31a11c501a81d133f8bd6f`。随后 `docker port mygo-board8-module-01a11726 80/tcp` 失败：`Error response from daemon: No such container: mygo-board8-module-01a11726`。容器已退出且被 `--rm` 删除，未拿到监听地址，因此未执行live test，也没有可读的保留日志；退出原因未验证。按卡片指令没有重试、更换镜像/CLI/运行模式。测试账号注册尚未开始，没有残留该命名容器或生产用户改动。
