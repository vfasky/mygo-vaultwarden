// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// The app has three windows of its own, all drawn from the one app state on
// the main thread:
//
//   - the main window (view): authentication while locked, otherwise the vault
//     browser and its editors;
//   - Settings (settingsWindowView, window_settings.go): account, storage &
//     AutoFill, updates and about;
//   - the account center (accountWindowView, window_account.go): Send,
//     devices, account security, two-step login and emergency access.
//
// The update window belongs to the updater plugin (updates.go).
//
// Which windows are open is app state (windowSet); the native windows are its
// projection, created only after Run sets native. Headless tests drive the
// state and render the views with ui.NewTester.

type settingsTab string

const (
	settingsTabAccount settingsTab = "account"
	settingsTabStorage settingsTab = "storage"
	settingsTabUpdates settingsTab = "updates"
	settingsTabAbout   settingsTab = "about"
)

type accountTab string

const (
	accountTabSend      accountTab = "send"
	accountTabDevices   accountTab = "devices"
	accountTabSecurity  accountTab = "security"
	accountTabMFA       accountTab = "mfa"
	accountTabEmergency accountTab = "emergency"
)

type windowSet struct {
	// native is set by Run: open windows get native windows. Tests leave it off.
	native bool
	// quitting is set while the app quits, so closing the main window no longer hides it.
	quitting bool

	settingsOpen bool
	settingsTab  settingsTab
	settings     *mygo.Window

	accountOpen bool
	accountTab  accountTab
	account     *mygo.Window

	// signature is the shared state the windows last drew (see frame).
	signature uiSignature
}

// postUI runs f on the main thread, then redraws every window. Workers and
// native callbacks deliver results through it (dispatchUI uses it).
func (a *app) postUI(f func()) {
	main := a.mainWindow
	main.Update(func() {
		f()
		a.invalidateWindows(main)
	})
}

// invalidateWindows redraws the app's windows other than except. Main thread only.
func (a *app) invalidateWindows(except *mygo.Window) {
	for _, w := range []*mygo.Window{a.mainWindow, a.windows.settings, a.windows.account} {
		if w != nil && w != except && !w.IsDestroyed() {
			w.Invalidate()
		}
	}
}

// uiSignature is the state that more than one window shows. A frame that
// changed it redraws the other windows, so a lock in the main window hides
// the account center, and a logout in Settings shows the login page.
type uiSignature struct {
	epoch                     uint64
	pending                   int
	status                    string
	unlocked, showLogin, live bool
	snapshot, diskSnapshot    *localstore.SnapshotStatus
	itemsRevision             string
	vault                     *vaultwarden.VaultData
	runtime                   *runtimeVault
	runtimeReplaceConfirmed   bool
	secretInputVersion        uint64
	editing                   bool
	targetRecovery            *targetRecoveryController
	send                      *send.Panel
	devices                   *account.DevicePanel
	accountForm               *account.Form
	authManagement            *account.AuthManagementForm
	orgServices               *orgServicesController
	settingsOpen, accountOpen bool
	settingsTab               settingsTab
	accountTab                accountTab
}

func (a *app) signature() uiSignature {
	return uiSignature{
		epoch: a.epoch, pending: a.pending, status: a.status,
		unlocked: a.unlocked(), showLogin: a.showLogin, live: a.session != nil,
		snapshot: a.snapshot, diskSnapshot: a.diskSnapshot, itemsRevision: a.itemsRevision,
		vault: a.vault, runtime: a.runtimeVault, runtimeReplaceConfirmed: a.runtimeReplaceConfirmed,
		secretInputVersion: a.secretInputVersion, editing: a.mainEditorOpen(), targetRecovery: a.targetRecovery,
		send: a.sendPanel, devices: a.devicePanel, accountForm: a.accountForm, authManagement: a.authManagement,
		orgServices: a.orgServices, settingsOpen: a.windows.settingsOpen, accountOpen: a.windows.accountOpen,
		settingsTab: a.windows.settingsTab, accountTab: a.windows.accountTab,
	}
}

// frame wraps the Content of a native window: after its view, a change of
// the shared state redraws the other windows.
func (a *app) frame(self func() *mygo.Window, view func(c *ui.Context)) func(c *ui.Context) {
	return func(c *ui.Context) {
		view(c)
		if sig := a.signature(); sig != a.windows.signature {
			a.windows.signature = sig
			a.invalidateWindows(self())
		}
	}
}

// framePrelude runs at the top of every window's view: it checks the
// temporary online vault's source and closes connected panels whose account
// center page is no longer shown, as leaving the page always did.
func (a *app) framePrelude(c *ui.Context) {
	if runtime := a.runtimeVault; runtime != nil {
		if err := runtime.sourceCheck(runtime.source, *a.liveScope); err != nil {
			a.stopNetwork()
			a.status = i18n.T("app.sync.err_runtime_source_changed")
		} else {
			c.After(time.Second)
		}
	}
	a.reconcileAccountPanels()
}

// reconcileAccountPanels keeps at most the panel of the shown account center
// page. The panels share one controller lease, so closing one revokes all.
// While the vault is locked or the login page is up, the account center shows
// no page, so no panel survives to reappear afterwards.
func (a *app) reconcileAccountPanels() {
	shown := accountTab("")
	if a.windows.accountOpen && a.unlocked() && !a.showLogin {
		shown = a.windows.accountTab
	}
	switch {
	case a.orgServices != nil && shown != accountTabEmergency,
		a.authManagement != nil && shown != accountTabMFA,
		a.accountForm != nil && a.accountForm.Mode != "register" && shown != accountTabSecurity,
		a.devicePanel != nil && shown != accountTabDevices,
		a.sendPanel != nil && shown != accountTabSend:
		a.advanceEpoch()
	}
}

// mainEditorOpen reports whether the main window edits something. Account
// center pages do not open over it, as Settings could not before.
func (a *app) mainEditorOpen() bool {
	return a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil || a.organizationEditor != nil
}

// openMainWindow creates the main window. Run calls it once.
func (a *app) openMainWindow() {
	// Pinning the traffic lights where hiddenInset puts them makes the
	// title bar exactly as tall as their row, centered on them, so the
	// sidebar toggle and toolbar can center on c.TitleBar().Height.
	var win *mygo.Window
	win = mygo.NewWindow(mygo.WindowOptions{Title: "MyGo Vaultwarden", Width: 1280, Height: 820, MinWidth: 1060, MinHeight: 700,
		StateKey: "main", TitleBarStyle: mygo.TitleBarHiddenInset, TrafficLightPosition: &mygo.Point{X: 18, Y: 18},
		Content: ui.View(a.frame(func() *mygo.Window { return win }, a.view))})
	a.mainWindow = win
	win.OnClose(func(e *mygo.CloseEvent) {
		if a.hideMainWindowOnClose() {
			e.PreventDefault()
			win.Hide()
		}
	})
}

func (a *app) hideMainWindowOnClose() bool {
	return !a.windows.quitting
}

// showMainWindow brings the main window forward, as after a Dock click or
// from Settings to log in or unlock.
func (a *app) showMainWindow() {
	if w := a.mainWindow; w != nil && a.windows.native && !w.IsDestroyed() {
		if w.IsMinimized() {
			w.Restore()
		}
		w.Show()
		w.Focus()
	}
}

// showSettingsWindow opens Settings, on tab unless tab is empty.
func (a *app) showSettingsWindow(tab settingsTab) {
	a.windows.settingsOpen = true
	if tab != "" {
		a.windows.settingsTab = tab
	}
	if a.windows.settingsTab == "" {
		a.windows.settingsTab = settingsTabAccount
	}
	if !a.windows.native {
		return
	}
	if a.windows.settings == nil || a.windows.settings.IsDestroyed() {
		var win *mygo.Window
		options := settingsWindowOptions()
		options.StateKey = "settings"
		options.Content = ui.View(a.frame(func() *mygo.Window { return win }, a.settingsWindowView))
		win = mygo.NewWindow(options)
		win.OnClosed(func() {
			if a.windows.settings == win {
				a.windows.settings, a.windows.settingsOpen = nil, false
				a.invalidateWindows(win)
			}
		})
		a.windows.settings = win
	}
	a.windows.settings.Show()
	a.windows.settings.Focus()
}

// selectAccountTab shows the account center on tab without opening its
// panel. The open* controllers call it once their panel exists; menus and
// buttons use openAccountPage (window_account.go) instead.
func (a *app) selectAccountTab(tab accountTab) {
	a.windows.accountOpen, a.windows.accountTab = true, tab
	if !a.windows.native {
		return
	}
	if a.windows.account == nil || a.windows.account.IsDestroyed() {
		var win *mygo.Window
		options := accountWindowOptions()
		options.StateKey = "account-center"
		options.Content = ui.View(a.frame(func() *mygo.Window { return win }, a.accountWindowView))
		win = mygo.NewWindow(options)
		win.OnClosed(func() {
			if a.windows.account == win {
				a.windows.account, a.windows.accountOpen = nil, false
				// Closing the window leaves its page: its panel stops now, not at the next frame.
				a.reconcileAccountPanels()
				a.invalidateWindows(win)
			}
		})
		a.windows.account = win
	}
	a.windows.account.Show()
	a.windows.account.Focus()
}

// closeAccountCenter closes the account center and its panel.
func (a *app) closeAccountCenter() {
	if w := a.windows.account; w != nil && !w.IsDestroyed() {
		w.Close()
		return
	}
	a.windows.accountOpen = false
	a.reconcileAccountPanels()
}

// accountParent is the window that account center dialogs and system
// authentication attach to: the account center while it is open.
func (a *app) accountParent() *mygo.Window {
	if w := a.windows.account; w != nil && !w.IsDestroyed() {
		return w
	}
	return a.mainWindow
}
