// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

// accountWindowView is the account center window: Send, devices, account
// security, two-step login and emergency access, one page at a time. The
// pages share one controller lease, so showing another page closes the
// panel of the last one (reconcileAccountPanels).
//
// SKELETON: the pages the main window used to show in place of the vault,
// moved as is. The account center lane replaces it with the final layout.
// accountWindowOptions are the account center's native options;
// selectAccountTab adds its StateKey and Content.
func accountWindowOptions() mygo.WindowOptions {
	return mygo.WindowOptions{Title: i18n.T("app.window.account_center_title"), Width: 1080, Height: 720, MinWidth: 900, MinHeight: 600}
}

// openAccountPage is the one entry to an account center page, from menus,
// Settings and the account center's own navigation: it shows the page and
// opens its panel when the vault allows it.
//
// SKELETON: opens the panel whenever the open* controller does; the account
// center lane adds the conditions and their explanations.
func (a *app) openAccountPage(tab accountTab) {
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
		tab = accountTabSend
		a.openSend()
	}
	a.selectAccountTab(tab)
}

func (a *app) accountWindowView(c *ui.Context) {
	a.framePrelude(c)
	c.SetTheme(kit.Theme)
	ui.Column(c).Fill().TextColor(kit.Ink).Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
		ui.Box(c).Height(max(c.TitleBar().Height, 28)).Shrink(0).DragWindow()
		ui.Column(c).Grow(1).MinHeight(0).Padding(0, 20, 18, 20).Children(func() {
			if !a.unlocked() || a.showLogin {
				ui.Text(c, i18n.T("app.list.status_locked")).FontSize(15).FontWeight(550)
				return
			}
			a.accountPage(c)
		})
	})
}

func (a *app) accountPage(c *ui.Context) {
	ui.Scroll(c.Key(string(a.windows.accountTab))).Grow(1).Children(func() {
		switch a.windows.accountTab {
		case accountTabEmergency:
			if a.orgServices != nil {
				a.orgServices.View(c)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, i18n.T("app.settings.open_emergency_access")).Disabled(a.pending != 0).Clicked() {
					a.openEmergencyServices()
				}
			}
		case accountTabMFA:
			if a.authManagement != nil {
				account.AuthManagementView(c, a.authManagement)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, i18n.T("app.settings.open_mfa")).Disabled(a.pending != 0).Clicked() {
					a.openAuthenticationManagement()
				}
			}
		case accountTabSecurity:
			if a.accountForm != nil {
				account.FormView(c, a.accountForm)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, i18n.T("app.settings.open_account_security")).Disabled(a.pending != 0).Clicked() {
					a.openAccount()
				}
			}
		case accountTabDevices:
			if a.devicePanel != nil {
				a.devicePanel.View(c)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, i18n.T("app.settings.open_devices")).Disabled(a.pending != 0).Clicked() {
					a.openDevices()
				}
			}
		default:
			if a.sendPanel != nil {
				a.sendPanel.View(c)
			} else {
				ui.Text(c, a.status)
				if ui.Button(c, i18n.T("app.settings.open_send")).Disabled(a.pending != 0).Clicked() {
					a.openSend()
				}
			}
		}
	})
}
