// SPDX-License-Identifier: GPL-3.0-only
package i18n

func init() { register("settings", settings) }

var settings = map[string]text{
	"settings.about.license":               {"本应用采用 GPL-3.0-only 许可证。", "This app is licensed under GPL-3.0-only."},
	"settings.about.third_party":           {"MyGo、goja、zxcvbn 等第三方组件保留各自许可证。应用包随附第三方组件声明与许可证。", "Third-party components, including MyGo, goja and zxcvbn, retain their own licenses. Third-party notices and licenses are included in the app bundle."},
	"settings.account.description":         {"管理当前连接与账号服务。", "Manage your connection and account services."},
	"settings.account.editor_hint":         {"请先在主窗口完成或关闭编辑器，再打开账号服务。", "Finish or close the editor in the main window before opening account services."},
	"settings.account.send":                {"Send", "Send"},
	"settings.account.server":              {"服务器", "Server"},
	"settings.account.wait_hint":           {"请等待密码库操作完成后再打开账号服务。", "Wait for the vault operation to finish before opening account services."},
	"settings.app_name":                    {"MyGo Vaultwarden", "MyGo Vaultwarden"},
	"settings.locked_hint":                 {"解锁密码库后查看账号与本机存储设置。", "Unlock your vault to view account and local storage settings."},
	"settings.show_main_window":            {"前往主窗口", "Go to main window"},
	"settings.storage.description":         {"管理本机快照与系统自动填充。", "Manage your local snapshot and system AutoFill."},
	"settings.storage.snapshot_title":      {"本机快照与自动填充", "Local snapshot and AutoFill"},
	"settings.tab.about":                   {"关于", "About"},
	"settings.tab.account":                 {"账号", "Account"},
	"settings.tab.general":                 {"通用", "General"},
	"settings.tab.updates":                 {"更新", "Updates"},
	"settings.updates.automatic_checks":    {"自动检查更新", "Automatically check for updates"},
	"settings.updates.automatic_downloads": {"自动下载并安装更新", "Automatically download and install updates"},
	"settings.updates.available_hint":      {"此构建支持自动更新。", "This build supports automatic updates."},
	"settings.updates.check_now":           {"检查更新…", "Check for updates…"},
	"settings.updates.description":         {"查看版本信息并设置自动更新。", "View version details and configure automatic updates."},
	"settings.updates.last_check":          {"上次检查", "Last checked"},
	"settings.updates.never_checked":       {"从未检查", "Never checked"},
	"settings.updates.preferences_title":   {"自动更新", "Automatic updates"},
	"settings.updates.status_title":        {"更新状态", "Update status"},
	"settings.updates.unavailable_hint":    {"此构建无法自动更新。开发构建或未配置更新源的构建不会自动更新；已配置的发行构建也需要安装在可写位置。", "Automatic updates are unavailable for this build. Development builds and builds without an update feed do not update automatically; configured release builds also require a writable install location."},
	"settings.version":                     {"版本：%s", "Version: %s"},
	"settings.version_label":               {"版本", "Version"},
}
