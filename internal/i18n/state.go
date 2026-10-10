// SPDX-License-Identifier: GPL-3.0-only

package i18n

func init() { register("state", state) }

var state = map[string]text{
	"state.resource.not_started":              {"未执行", "Not started"},
	"state.resource.pending_verify":           {"待核对", "Needs review"},
	"state.resource.verified":                 {"已核验", "Verified"},
	"state.resource.pending_sync":             {"待同步核对", "Awaiting sync verification"},
	"state.import.kind_folder":                {"文件夹", "Folder"},
	"state.import.kind_item":                  {"项目", "Item"},
	"state.import.kind_item_trash_unverified": {"项目（已创建，回收站状态待核对）", "Item (created; Trash status needs verification)"},
	"state.import.created":                    {"已创建", "Created"},
	"state.import.created_pending_sync":       {"已创建，待同步核对", "Created; sync to verify"},
	"state.import.stopped":                    {"已停止，请同步核对", "Stopped; sync to verify"},
	"state.import.unknown":                    {"结果未知，请同步核对；禁止重试", "Result unknown; sync to verify. Do not retry"},
	"state.import.metadata_copied":            {"副本元数据已创建，附件待恢复核验", "Copy metadata created; attachments still need restoration and verification"},
	"state.share.missing":                     {"缺失", "Missing"},
	"state.share.external_change":             {"外部修改", "Changed externally"},
	"state.share.old_personal":                {"旧个人", "Original personal item"},
	"state.share.new_organization":            {"新组织", "New organization item"},
	"state.share.old_wrapping":                {"旧包装", "Original key wrapping"},
	"state.share.new_wrapping":                {"新包装", "New key wrapping"},
	"state.share.remote_added":                {"远端新增", "Added on server"},
}
