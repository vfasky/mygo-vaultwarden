// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

// accountWindowOptions are the account center's native options;
// selectAccountTab adds its StateKey and Content.
func accountWindowOptions() mygo.WindowOptions {
	return mygo.WindowOptions{Title: i18n.T("app.window.account_center_title"), Width: 1080, Height: 720, MinWidth: 900, MinHeight: 600,
		TitleBarStyle: mygo.TitleBarHiddenInset, TrafficLightPosition: &mygo.Point{X: 18, Y: 18}}
}

// openAccountPage is the entry from menus, Settings and the sidebar. Selecting
// a page revokes the previous panel even when the new panel cannot open.
func (a *app) openAccountPage(tab accountTab) {
	switch tab {
	case accountTabSend, accountTabDevices, accountTabSecurity:
	default:
		tab = accountTabSend
	}
	a.selectAccountTab(tab)
	a.reconcileAccountPanels()
	if !a.unlocked() || a.showLogin || a.pending != 0 || a.mainEditorOpen() || a.accountPanelOpen() {
		return
	}
	switch tab {
	case accountTabDevices:
		a.openDevices()
	case accountTabSecurity:
		a.openAccount()
	case accountTabMFA:
		a.openAuthenticationManagement()
	case accountTabEmergency:
		a.openEmergencyServices()
	default:
		a.openSend()
	}
}

func (a *app) accountPanelOpen() bool {
	switch a.windows.accountTab {
	case accountTabDevices:
		return a.devicePanel != nil
	case accountTabSecurity:
		return a.accountForm != nil && !a.accountForm.SignedOut()
	case accountTabMFA:
		return a.authManagement != nil
	case accountTabEmergency:
		return a.orgServices != nil
	default:
		return a.sendPanel != nil
	}
}

var accountPages = []struct {
	tab                 accountTab
	title, symbol, open string
}{
	{accountTabSend, "accountcenter.send_title", "external", "app.settings.open_send"},
	{accountTabDevices, "account.device.title", "shield", "app.settings.open_devices"},
	{accountTabSecurity, "account.form.title", "user", "app.settings.open_account_security"},
}

func (a *app) accountWindowView(c *ui.Context) {
	a.framePrelude(c)
	c.SetTheme(kit.Theme)
	c.Root().Background(ui.Transparent)
	bar := c.TitleBar()
	row, below := titleBarRow(bar)
	if !a.unlocked() || a.showLogin {
		ui.Column(c).Fill().TextColor(kit.Ink).Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
			ui.Box(c).Height(row + below).Shrink(0).DragWindow()
			ui.Column(c).Grow(1).Padding(32).Justify(ui.Center).AlignItems(ui.Center).Gap(16).Children(func() {
				kit.EmptyState(c, "lock", i18n.T("app.list.status_locked"), i18n.T("accountcenter.locked_hint")).Grow(0)
				if kit.Action(c, i18n.T("accountcenter.unlock_in_main"), "external", true, false).Clicked() {
					a.showMainWindow()
				}
			})
		})
		return
	}
	ui.Row(c).Fill().TextColor(kit.Ink).AlignItems(ui.Stretch).Children(func() {
		width := max(float32(236), bar.Left+20)
		ui.Column(c).Width(width).Shrink(0).Background(kit.SidebarBackground).Children(func() {
			ui.Box(c).Height(row + below).Shrink(0).DragWindow()
			ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
				ui.Column(c).Padding(8, 12).Gap(4).Children(func() {
					ui.Text(c, i18n.T("app.window.account_center_title")).Padding(4, 10, 12, 10).FontSize(11).FontWeight(600).TextColor(kit.SidebarFaint)
					for _, page := range accountPages {
						if kit.SidebarItem(c, i18n.T(page.title), page.symbol, "", a.windows.accountTab == page.tab, false, false).Key("account-nav-" + string(page.tab)).Clicked() {
							a.openAccountPage(page.tab)
						}
					}
				})
			})
		})
		ui.Box(c).Width(1).Background(kit.Line)
		ui.Column(c).Grow(1).MinWidth(0).Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
			ui.Box(c).Height(row + below).Shrink(0).DragWindow()
			ui.Column(c).Grow(1).MinHeight(0).Padding(0, 20, 18, 20).Gap(16).Children(func() {
				for _, page := range accountPages {
					if page.tab == a.windows.accountTab {
						kit.PageHeader(c, i18n.T(page.title), i18n.T("accountcenter.description"), nil)
					}
				}
				a.accountPage(c)
				if a.pending != 0 {
					ui.Row(c).Height(32).Shrink(0).Children(func() {
						ui.Text(c, i18n.T("common.status_processing")).FontSize(12).TextColor(kit.Purple)
					})
				}
			})
		})
	})
}

func (a *app) accountPage(c *ui.Context) {
	if !a.accountPanelOpen() {
		ui.Column(c).Grow(1).MinHeight(0).Justify(ui.Center).AlignItems(ui.Center).Gap(12).Children(func() {
			switch {
			case a.pending != 0:
				kit.EmptyState(c, "sync", i18n.T("common.status_processing"), i18n.T("accountcenter.processing_hint")).Grow(0)
			case a.mainEditorOpen():
				kit.EmptyState(c, "note", i18n.T("accountcenter.editing_title"), i18n.T("accountcenter.finish_editing_hint")).Grow(0)
				if kit.Action(c, i18n.T("accountcenter.go_to_main"), "external", true, false).Clicked() {
					a.showMainWindow()
				}
			default:
				kit.EmptyState(c, "shield", i18n.T("accountcenter.open_title"), i18n.T("accountcenter.open_page_hint")).Grow(0)
				for _, page := range accountPages {
					if page.tab == a.windows.accountTab && kit.Action(c, i18n.T(page.open), page.symbol, true, false).Clicked() {
						a.openAccountPage(page.tab)
					}
				}
			}
		})
		return
	}
	ui.Scroll(c.Key(string(a.windows.accountTab))).Grow(1).MinHeight(0).Children(func() {
		switch a.windows.accountTab {
		case accountTabEmergency:
			a.orgServices.View(c)
		case accountTabMFA:
			account.AuthManagementView(c, a.authManagement)
		case accountTabSecurity:
			account.FormView(c, a.accountForm)
		case accountTabDevices:
			a.devicePanel.View(c)
		default:
			a.sendPanel.View(c)
		}
	})
}
