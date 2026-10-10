// SPDX-License-Identifier: GPL-3.0-only
package i18n

func init() { register("accountcenter", accountcenter) }

var accountcenter = map[string]text{
	"accountcenter.finish_editing_hint": {"请先在主窗口完成或取消正在编辑的内容", "Finish or cancel your edits in the main window first"},
	"accountcenter.go_to_main":          {"前往主窗口", "Go to main window"},
	"accountcenter.open_page_hint":      {"打开此页面以连接账号服务。操作结束或密码库状态变化后，请重新打开。", "Open this page to connect to account services. Reopen it after an operation ends or the vault state changes."},
	"accountcenter.send_title":          {"Send", "Send"},
	"accountcenter.unlock_in_main":      {"前往主窗口解锁", "Unlock in main window"},
}
