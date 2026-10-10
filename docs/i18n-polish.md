# i18n key 整理记录

基线：`bf8a097`。仅整理 key、引用、目录顺序和英文大小写；中文、程序行为、协议值和状态值未改。

## 合并与数量

原有 **1447** 个 key，整理后 **1384** 个，减少 **63** 个。原有 68 组中英文完全相同的文案中合并 **59** 组，保留 **9** 组。另有 **45** 项独立改名。共享角色和 URI 词汇归入 `common.go` 的 `role`、`urimatch` area。

| 最终 key | 被替换的旧 key |
|---|---|
| `vault.field.bank.account_number` | `account.emergency.account_number` |
| `vault.field.bank.account_type` | `account.emergency.account_type` |
| `vault.field.bank.phone` | `account.emergency.bank_phone` |
| `vault.field.date_of_birth` | `account.emergency.birth_date` |
| `vault.field.passport.birth_place` | `account.emergency.birth_place` |
| `vault.field.card.number` | `account.emergency.card_number` |
| `vault.field.card.holder` | `account.emergency.cardholder_name` |
| `vault.field.identity.city` | `account.emergency.city` |
| `vault.field.identity.company` | `account.emergency.company` |
| `vault.field.identity.country` | `account.emergency.country` |
| `vault.field.expiration_date` | `account.emergency.expiration_date` |
| `vault.field.card.expiration_month` | `account.emergency.expiration_month` |
| `vault.field.card.expiration_year` | `account.emergency.expiration_year` |
| `vault.field.first_name` | `account.emergency.first_name` |
| `vault.field.issue_date` | `account.emergency.issue_date` |
| `vault.field.issuing_authority` | `account.emergency.issuing_authority` |
| `vault.field.issuing_country` | `account.emergency.issuing_country` |
| `vault.field.ssh.fingerprint` | `account.emergency.key_fingerprint` |
| `vault.field.last_name` | `account.emergency.last_name` |
| `vault.field.middle_name` | `account.emergency.middle_name` |
| `vault.field.identity.title` | `account.emergency.name_title` |
| `vault.field.passport.nationality` | `account.emergency.nationality` |
| `vault.field.identity.phone` | `account.emergency.phone` |
| `vault.field.identity.postal_code` | `account.emergency.postal_code` |
| `vault.field.ssh.private_key` | `account.emergency.private_key` |
| `vault.field.ssh.public_key` | `account.emergency.public_key` |
| `vault.field.bank.routing_number` | `account.emergency.routing_number` |
| `vault.field.card.security_code` | `account.emergency.security_code` |
| `vault.field.passport.sex` | `account.emergency.sex` |
| `vault.field.identity.social_security_number` | `account.emergency.ssn` |
| `vault.field.login.totp` | `account.emergency.totp_key` |
| `vault.field.website` | `app.detail.website` |
| `common.current_master_password` | `account.form.current_password`、`org.apikey.current_password` |
| `common.verification_code` | `account.mfa.verification_code`、`login.mfa.code` |
| `common.server_url` | `account.device_login.server_url`、`login.server_url` |
| `login.cancel` | `account.mfa.cancel_login` |
| `account.form.title` | `app.settings.account_security` |
| `account.device.title` | `app.settings.devices` |
| `account.emergency.title` | `app.settings.emergency_access` |
| `account.device_login.title` | `login.device.use_another` |
| `account.emergency.show_granted_access` | `org.services.emergency_grants` |
| `account.emergency.show_trusted_contacts` | `org.services.emergency_contacts` |
| `account.emergency.view_contact` | `org.services.view_contact` |
| `vault.folder.manage_title` | `app.sidebar.manage_folder` |
| `vault.folder.add_title` | `app.sidebar.new_folder` |
| `vault.bulk.title` | `app.toolbar.bulk_actions` |
| `policy.value.passphrase` | `org.policy.passphrase` |
| `vault.field.uri` | `account.emergency.uri`、`server.rebase.uri` |
| `role.owner` | `policy.role.owner`、`org.member.role_owner` |
| `role.admin` | `policy.role.admin`、`org.member.role_admin` |
| `urimatch.base_domain` | `policy.uri_match.base_domain`、`org.policy.uri_base_domain` |
| `urimatch.exact` | `policy.uri_match.exact`、`org.policy.uri_exact`、`vault.uri.exact` |
| `urimatch.host` | `policy.uri_match.host`、`org.policy.uri_host`、`vault.uri.host` |
| `urimatch.never` | `policy.uri_match.never`、`org.policy.uri_never` |
| `urimatch.regular_expression` | `policy.uri_match.regex`、`org.policy.uri_regex`、`vault.uri.regular_expression` |
| `urimatch.starts_with` | `policy.uri_match.starts_with`、`org.policy.uri_starts_with` |
| `common.default` | `policy.value.default`、`org.policy.default_value`、`vault.uri.default` |
| `common.yes` | `policy.value.yes`、`org.policy.yes` |
| `common.no` | `policy.value.no`、`org.policy.no` |

## 有意保留的重复组

| key（基线名称） | 理由 |
|---|---|
| `account.form.confirm_execute`、`org.services.confirm_execute` | 账号安全变更确认与组织服务请求确认是不同操作；分别明确命名为 `confirm_security_change`、`confirm_submit_request`，保持各流程可独立调整。 |
| `account.emergency.card`、`policy.restricted_item_types.card` | 紧急查看的银行卡分组标题与策略中的受限条目类型选项，属于不同呈现用途；不能替换为中文为“支付卡”的 `itemtype.card`。 |
| `account.emergency.resend_invitation`、`org.member.invite_resend` | 紧急联系人邀请与组织成员邀请的收件人、授权和后续流程不同。 |
| `account.emergency.status_confirmed`、`org.member.status_confirmed` | 紧急访问授权确认与组织成员资格确认，属于不同状态机。 |
| `account.emergency.status_unknown`、`org.member.status_unknown` | 分别表示紧急访问状态未知、组织成员状态未知，保持各自状态说明。 |
| `app.settings.withdraw_account_replacement`、`crossaccount.recovery.revoke_replace` | 普通账号替换与跨账号恢复中的目标替换，撤回的同意范围不同。 |
| `backup.resource.source_status`、`org.resource.file_source_status` | 个人资源恢复与组织资源恢复的逐文件结果行，权限与恢复上下文不同，保留领域内格式。 |
| `send.editor.cancel_delete`、`vault.folder.cancel_delete` | Send 删除与文件夹删除是不同流程，取消按钮可独立翻译。 |
| `common.folder`、`state.import.kind_folder` | 通用文件夹名称与导入结果类型不同，结果类型应与其他 `state.import.kind_*` 保持一致。 |

中文不同的同义词继续保留，如 URI 的“基础域名 / 基本域名”“从不匹配 / 从不填充”“以此开头 / 起始部分”，以及银行字段的“户名 / 账户姓名”“支行号码 / 分行号码”。这保证中文界面不发生变化。

## 独立改名清单

统一确认操作、动词短语、标签后缀和显示状态前缀；`state.share.*` 的名词标签不强行改成状态。

| 旧 key | 新 key |
|---|---|
| `account.form.confirm_execute` | `account.form.confirm_security_change` |
| `org.services.confirm_execute` | `org.services.confirm_submit_request` |
| `account.mfa.enabled_status` | `account.mfa.status_enabled` |
| `common.processing` | `common.status_processing` |
| `login.account_switch.confirm` | `login.account_switch.confirm_replace_account` |
| `vault.bulk.cancel_confirm` | `vault.bulk.cancel_confirmation` |
| `org.member.invite_send` | `org.member.send_invitation` |
| `org.member.invite_resend` | `org.member.resend_invitation` |
| `org.member.invite_verify_policy` | `org.member.verify_invitation_policy` |
| `org.member.invite_accept_recovery` | `org.member.accept_invitation_with_recovery` |
| `org.services.back_edit` | `org.services.back_to_edit` |
| `org.services.review_continue` | `org.services.review_and_continue` |
| `org.services.verify_continue` | `org.services.verify_and_continue` |
| `org.ops.back_select` | `org.ops.back_to_selection` |
| `org.transfer.copy_open` | `org.transfer.open_copy` |
| `org.transfer.export_open` | `org.transfer.open_export` |
| `org.member.label_member` | `org.member.member_label` |
| `org.collection.label_collection` | `org.collection.collection_label` |
| `org.group.label_group` | `org.group.group_label` |
| `org.collection.delete_hint` | `org.collection.confirm_delete_hint` |
| `org.settings.delete_hint` | `org.settings.confirm_delete_hint` |
| `org.settings.leave_hint` | `org.settings.confirm_leave_hint` |
| `org.recovery.initialize_hint` | `org.recovery.confirm_initialize_hint` |
| `backup.import.confirm_hint` | `backup.import.confirm_create_hint` |
| `policy.role.manager` | `role.manager` |
| `policy.role.member` | `role.member` |
| `org.member.role_user` | `role.user` |
| `org.member.role_collection_manager` | `role.collection_manager` |
| `org.member.role_unknown` | `role.unknown` |
| `vault.compare.both_changed` | `vault.compare.status_both_changed` |
| `vault.compare.local_changed` | `vault.compare.status_local_changed` |
| `vault.compare.remote_changed` | `vault.compare.status_remote_changed` |
| `vault.compare.no_changes` | `vault.compare.status_no_changes` |
| `vault.bulk.item_matched` | `vault.bulk.status_item_matched` |
| `vault.bulk.item_unmatched` | `vault.bulk.status_item_unmatched` |
| `vault.bulk.item_unverified` | `vault.bulk.status_item_unverified` |
| `state.resource.not_started` | `state.resource.status_not_started` |
| `state.resource.pending_verify` | `state.resource.status_pending_verify` |
| `state.resource.verified` | `state.resource.status_verified` |
| `state.resource.pending_sync` | `state.resource.status_pending_sync` |
| `state.import.created` | `state.import.status_created` |
| `state.import.created_pending_sync` | `state.import.status_created_pending_sync` |
| `state.import.stopped` | `state.import.status_stopped` |
| `state.import.unknown` | `state.import.status_unknown` |
| `state.import.metadata_copied` | `state.import.status_metadata_copied` |

## 英文大小写清单

**65** 个 key（64 种不同文案）仅变更大小写。保留 Send、MyGo、Bitwarden、JSON、Trash 等专名；说明中引用的按钮名也同步大小写。

| 最终 key | 原英文 | 新英文 |
|---|---|---|
| `send.file.choose_title` | Choose Send File | Choose Send file |
| `send.file.save_title` | Save Send File | Save Send file |
| `send.file.default_name` | Send File | Send file |
| `send.panel.offline_list` | Offline List | Offline list |
| `send.editor.new_text` | New Text | New text |
| `send.editor.new_file` | New File | New file |
| `send.editor.confirm_delete` | Confirm Delete Send | Confirm delete Send |
| `send.receive.show_text` | Show Send Text | Show Send text |
| `role.collection_manager` | Collection Manager | Collection manager |
| `org.member.title` | Organization Members | Organization members |
| `org.member.send_invitation` | Send Invite | Send invite |
| `org.member.change_role` | Change Role | Change role |
| `org.member.restore_member` | Restore Member | Restore member |
| `org.member.revoke_access` | Revoke Access | Revoke access |
| `org.member.remove_member` | Remove Member | Remove member |
| `org.collection.title` | Collection Management | Collection management |
| `org.collection.create_collection` | New Collection | New collection |
| `org.collection.access_title` | Collection Access | Collection access |
| `org.collection.save_collection` | Save Collection | Save collection |
| `org.collection.delete_collection` | Delete Collection | Delete collection |
| `org.settings.title` | Manage Organization | Manage organization |
| `org.settings.create_title` | Create Organization | Create organization |
| `org.settings.save_organization` | Save Organization | Save organization |
| `org.settings.leave_organization` | Leave Organization | Leave organization |
| `org.settings.delete_organization` | Delete Organization | Delete organization |
| `org.policy.title` | Organization Policies | Organization policies |
| `org.policy.enable_policy` | Enable Policy | Enable policy |
| `org.policy.save_policy` | Save Policy | Save policy |
| `org.group.title` | Group Management | Group management |
| `org.group.load_groups` | Load Groups | Load groups |
| `org.group.create_group` | New Group | New group |
| `org.group.save_group` | Save Group | Save group |
| `org.group.delete_group` | Delete Group | Delete group |
| `org.recovery.cancel_initialize` | Cancel Initialization | Cancel initialization |
| `org.share.cancel_share` | Cancel Sharing | Cancel sharing |
| `org.share.copy_password` | Copy Password | Copy password |
| `org.services.back_to_edit` | Back to Edit | Back to edit |
| `org.services.cancel_review` | Cancel and Review | Cancel and review |
| `org.services.review_and_continue` | Review and Continue | Review and continue |
| `org.services.verify_and_continue` | Verify and Continue | Verify and continue |
| `org.directory.add_member_preview` | Add to Preview | Add to preview |
| `org.directory.remove_group` | Remove Group | Remove group |
| `org.directory.remove_member_row` | Remove Row | Remove row |
| `org.events.cancel_load` | Cancel Loading | Cancel loading |
| `org.events.load` | Load Events | Load events |
| `org.ops.back_to_selection` | Back to Selection | Back to selection |
| `org.ops.open` | Bulk Status | Bulk status |
| `org.resource.archive_state` | Archive State | Archive state |
| `org.resource.confirm_restore_state` | Confirm Restore: %s | Confirm restore: %s |
| `org.resource.folder_mapping` | Folder Mapping | Folder mapping |
| `org.resource.trash_state` | Trash State | Trash state |
| `org.transfer.assign_collections` | Assign Collections | Assign collections |
| `org.transfer.open_export` | Export Organization | Export organization |
| `org.transfer.format_official` | Official Bitwarden Plaintext JSON | Official Bitwarden plaintext JSON |
| `org.transfer.format_resources_export` | MyGo Full Organization Resource Backup (Attachments and Passkeys, Unofficial Format) | MyGo full organization resource backup (attachments and passkeys, unofficial format) |
| `org.apikey.clear` | Clear Key | Clear key |
| `account.mfa.verification_response` | Verification response / Recovery code | Verification response / recovery code |
| `account.emergency.state` | State / Province | State / province |
| `account.emergency.view_title` | Emergency access · Read-only view | Emergency access · read-only view |
| `login.register_password_hint` | Sign up / Password hint | Sign up / password hint |
| `org.directory.status_unknown` | Unknown / Needs review | Unknown / needs review |
| `vault.field.identity.state` | State / Province | State / province |
| `org.collection.status_changes_submitted` | Collection changes submitted. Syncing to verify. If the sidebar shows “Verify Again”, complete verification to restore organization access. | Collection changes submitted. Syncing to verify. If the sidebar shows “Verify again”, complete verification to restore organization access. |
| `app.toolbar.empty_trash` | Empty trash | Empty Trash |
| `org.transfer.err_import_state_unsupported` | This item is archived or in the trash. The official organization import endpoint cannot preserve this state, so submission is blocked. | This item is archived or in the Trash. The official organization import endpoint cannot preserve this state, so submission is blocked. |

测试期望仅一处英文调整：`internal/ui/send/panel_i18n_test.go` 的默认文件名从 `Send File` 改为 `Send file`。`internal/app/organization_i18n_test.go` 只把角色 key 期望改为 `role.owner`，其 `Owner` 文案期望未变。所有中文测试期望未改。

## 中文和代码核对

运行 `bun scripts/verify-i18n-polish.ts bf8a097`（实际使用 WorkTony 内置 Bun）：读取基线 git 对象与当前目录，按 Go token 位置比较每个 key 引用对应的中文；同时核对直接 T/Tf、switch/map 中的 key、测试 key 和其余非文案 token。

- 比较 425 个非目录 Go 文件、1618 个 key 引用，其中直接 T/Tf 调用 1499 个；137 个引用改用新 key。
- 中文差异 **0**，非 i18n token 差异 **0**；英文变更仅为大小写，唯一英文测试期望变更按目录值核验。
- 123 个被替换旧 key 在全部 Go 文件中均无残留。
- 9 个目录文件按 area、完整 key 排序。
- `internal/i18n/i18n.go`、`internal/i18n/catalog_test.go`、`go.mod`、`go.sum` 与基线完全相同。

## 验证结果

使用 `export GO_BIN=$(bash scripts/resolve-go.sh); export PATH=$(dirname "$GO_BIN"):$PATH`，并设置 `GOPROXY=off GOSUMDB=off`，未联网。

| 命令 | 结果 |
|---|---|
| `gofmt -l internal` | 通过，无输出 |
| `go build ./...` | 通过 |
| `go vet ./...` | 通过 |
| `go vet -tags headless ./...` | 通过 |
| `GOOS=linux CGO_ENABLED=0 go vet ./internal/...` | 通过 |
| `go tool mygo vet .` | 通过 |
| `go test -tags headless ./... -count=1` | 通过 |
| `go test ./... -count=1` | 通过 |
| `go test ./internal/i18n -count=1` | 通过 |
| `bun scripts/verify-i18n-polish.ts bf8a097` | 通过 |
| `git diff --check` | 通过 |

首次两套完整测试仅因旧的 `Send File` 英文期望失败；同步期望后，Send 包的 headless/native 测试及两套完整测试均重新通过。未修改测试规则。

本次没有增加 Go 测试；保留可复现的中文与非文案 token 核对脚本。无已知未解决问题；独立审查由上层执行。提交信息：`i18n：合并重复 key、统一命名与英文大小写`，不推送。
