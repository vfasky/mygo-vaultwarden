// SPDX-License-Identifier: GPL-3.0-only

package i18n

// Words shared by every area. Add a key here only when several areas use
// the same text with the same meaning; otherwise keep it in its own area.

func init() {
	register("common", common)
	register("itemtype", itemTypes)
}

var common = map[string]text{
	"common.save":               {"保存", "Save"},
	"common.cancel":             {"取消", "Cancel"},
	"common.confirm":            {"确认", "Confirm"},
	"common.close":              {"关闭", "Close"},
	"common.delete_permanently": {"永久删除", "Delete permanently"},
	"common.continue":           {"继续", "Continue"},
	"common.restore":            {"恢复", "Restore"},
	"common.archive":            {"归档", "Archive"},
	"common.unarchive":          {"取消归档", "Unarchive"},
	"common.sync":               {"同步", "Sync"},
	"common.lock":               {"锁定", "Lock"},
	"common.hide":               {"隐藏", "Hide"},
	"common.processing":         {"处理中…", "Processing…"},
	"common.username":           {"用户名", "Username"},
	"common.password":           {"密码", "Password"},
	"common.email":              {"邮箱", "Email"},
	"common.notes":              {"备注", "Notes"},
	"common.name":               {"名称", "Name"},
	"common.folder":             {"文件夹", "Folder"},
	"common.no_folder":          {"无文件夹", "No folder"},
	"common.my_vault":           {"我的密码库", "My vault"},
}

// itemTypes are the display names of the eight item types, indexed by
// their protocol number in the item type tables.
var itemTypes = map[string]text{
	"itemtype.login":    {"登录", "Login"},
	"itemtype.note":     {"安全笔记", "Secure note"},
	"itemtype.card":     {"支付卡", "Card"},
	"itemtype.identity": {"身份", "Identity"},
	"itemtype.ssh_key":  {"SSH 密钥", "SSH key"},
	"itemtype.bank":     {"银行账户", "Bank account"},
	"itemtype.license":  {"驾驶证", "Driver's license"},
	"itemtype.passport": {"护照", "Passport"},
}
