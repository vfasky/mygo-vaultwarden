// SPDX-License-Identifier: GPL-3.0-only

package i18n

// Shared vocabulary, item types, member roles, and URI match rules.

func init() {
	register("common", common)
	register("itemtype", itemTypes)
	register("role", roles)
	register("urimatch", uriMatches)
}

var common = map[string]text{
	"common.archive":                 {"归档", "Archive"},
	"common.cancel":                  {"取消", "Cancel"},
	"common.close":                   {"关闭", "Close"},
	"common.confirm":                 {"确认", "Confirm"},
	"common.continue":                {"继续", "Continue"},
	"common.current_master_password": {"当前主密码", "Current master password"},
	"common.default":                 {"默认", "Default"},
	"common.delete_permanently":      {"永久删除", "Delete permanently"},
	"common.email":                   {"邮箱", "Email"},
	"common.folder":                  {"文件夹", "Folder"},
	"common.hide":                    {"隐藏", "Hide"},
	"common.lock":                    {"锁定", "Lock"},
	"common.my_vault":                {"我的密码库", "My vault"},
	"common.name":                    {"名称", "Name"},
	"common.no":                      {"否", "No"},
	"common.no_folder":               {"无文件夹", "No folder"},
	"common.notes":                   {"备注", "Notes"},
	"common.password":                {"密码", "Password"},
	"common.restore":                 {"恢复", "Restore"},
	"common.save":                    {"保存", "Save"},
	"common.server_url":              {"服务器地址", "Server URL"},
	"common.status_processing":       {"处理中…", "Processing…"},
	"common.sync":                    {"同步", "Sync"},
	"common.unarchive":               {"取消归档", "Unarchive"},
	"common.username":                {"用户名", "Username"},
	"common.verification_code":       {"验证码", "Verification code"},
	"common.yes":                     {"是", "Yes"},
}

var itemTypes = map[string]text{
	"itemtype.bank":     {"银行账户", "Bank account"},
	"itemtype.card":     {"支付卡", "Card"},
	"itemtype.identity": {"身份", "Identity"},
	"itemtype.license":  {"驾驶证", "Driver's license"},
	"itemtype.login":    {"登录", "Login"},
	"itemtype.note":     {"安全笔记", "Secure note"},
	"itemtype.passport": {"护照", "Passport"},
	"itemtype.ssh_key":  {"SSH 密钥", "SSH key"},
}

var roles = map[string]text{
	"role.admin":              {"管理员", "Admin"},
	"role.collection_manager": {"集合经理", "Collection manager"},
	"role.manager":            {"经理", "Manager"},
	"role.member":             {"成员", "Member"},
	"role.owner":              {"所有者", "Owner"},
	"role.unknown":            {"未知角色", "Unknown role"},
	"role.user":               {"普通成员", "User"},
}

var uriMatches = map[string]text{
	"urimatch.base_domain":        {"基础域名", "Base domain"},
	"urimatch.exact":              {"完全匹配", "Exact"},
	"urimatch.host":               {"主机", "Host"},
	"urimatch.never":              {"从不匹配", "Never"},
	"urimatch.regular_expression": {"正则表达式", "Regular expression"},
	"urimatch.starts_with":        {"以此开头", "Starts with"},
}
