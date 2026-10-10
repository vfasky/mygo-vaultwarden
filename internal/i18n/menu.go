// SPDX-License-Identifier: GPL-3.0-only
package i18n

func init() { register("menu", menu) }

var menu = map[string]text{
	"menu.about":           {"关于 MyGo Vaultwarden", "About MyGo Vaultwarden"},
	"menu.account":         {"账号", "Account"},
	"menu.account_center":  {"账号中心", "Account center"},
	"menu.bring_all_front": {"前置全部窗口", "Bring all to front"},
	"menu.copy":            {"复制", "Copy"},
	"menu.cut":             {"剪切", "Cut"},
	"menu.devices":         {"设备与登录审批", "Devices and login approval"},
	"menu.edit":            {"编辑", "Edit"},
	"menu.emergency":       {"紧急访问", "Emergency access"},
	"menu.hide":            {"隐藏 MyGo Vaultwarden", "Hide MyGo Vaultwarden"},
	"menu.hide_others":     {"隐藏其他", "Hide others"},
	"menu.import_export":   {"导入导出", "Import & export"},
	"menu.lock":            {"锁定", "Lock"},
	"menu.main_window":     {"主窗口", "Main window"},
	"menu.mfa":             {"两步验证设置", "Two-step login settings"},
	"menu.minimize":        {"最小化", "Minimize"},
	"menu.new_item":        {"新建项目", "New item"},
	"menu.paste":           {"粘贴", "Paste"},
	"menu.quit":            {"退出 MyGo Vaultwarden", "Quit MyGo Vaultwarden"},
	"menu.redo":            {"重做", "Redo"},
	"menu.security":        {"账号与安全", "Account and security"},
	"menu.select_all":      {"全选", "Select all"},
	"menu.send":            {"Send", "Send"},
	"menu.services":        {"服务", "Services"},
	"menu.settings":        {"设置…", "Settings…"},
	"menu.show_all":        {"全部显示", "Show all"},
	"menu.sync":            {"同步", "Sync"},
	"menu.undo":            {"撤销", "Undo"},
	"menu.vault":           {"密码库", "Vault"},
	"menu.window":          {"窗口", "Window"},
	"menu.zoom":            {"缩放", "Zoom"},
}
