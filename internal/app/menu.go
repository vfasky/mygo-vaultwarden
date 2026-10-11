// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
)

type menuCommand string

const (
	menuSettings  menuCommand = "settings"
	menuMain      menuCommand = "main"
	menuNew       menuCommand = "new"
	menuSync      menuCommand = "sync"
	menuLock      menuCommand = "lock"
	menuBackup    menuCommand = "backup"
	menuAccount   menuCommand = "account"
	menuSend      menuCommand = "send"
	menuDevices   menuCommand = "devices"
	menuSecurity  menuCommand = "security"
	menuMFA       menuCommand = "mfa"
	menuEmergency menuCommand = "emergency"
)

// runMenuCommand is also used by the main window. Native menu clicks run on
// the main thread; conditions are checked here against the current state.
func (a *app) runMenuCommand(command menuCommand) {
	defer a.invalidateWindows(nil)
	switch command {
	case menuSettings:
		a.showSettingsWindow("")
	case menuMain:
		a.showMainWindow()
	case menuAccount, menuSend, menuDevices, menuSecurity, menuMFA, menuEmergency:
		// The account center always opens: while the vault is locked, busy or
		// being edited, openAccountPage opens no panel and the page says why.
		tab := a.windows.accountTab
		switch command {
		case menuSend:
			tab = accountTabSend
		case menuDevices:
			tab = accountTabDevices
		case menuSecurity:
			tab = accountTabSecurity
		case menuMFA:
			tab = accountTabMFA
		case menuEmergency:
			tab = accountTabEmergency
		}
		if tab == "" {
			tab = accountTabSend
		}
		a.openAccountPage(tab)
	case menuNew, menuSync, menuLock, menuBackup:
		if command == menuBackup && a.backupEditor != nil {
			a.showBackupWindow()
			return
		}
		if command == menuLock {
			a.showMainWindow()
			a.runStorage(localstore.OperationLock)
			return
		}
		if !a.unlocked() || a.showLogin || a.pending != 0 {
			return
		}
		if command == menuSync {
			a.showMainWindow()
			a.syncVault(false)
			return
		}
		if a.vault == nil || a.mainEditorOpen() {
			return
		}
		if command == menuBackup {
			a.openBackupEditor()
		} else {
			a.showMainWindow()
			kind := categoryKinds[a.category]
			if kind == 0 {
				kind = 1
			}
			a.openCipherEditor("", kind)
		}
	}
}

func (a *app) menu() *mygo.Menu {
	action := func(label, accelerator string, command menuCommand) *mygo.MenuItem {
		return &mygo.MenuItem{Label: label, Accelerator: accelerator, Click: func(*mygo.MenuItem, *mygo.Window) { a.runMenuCommand(command) }}
	}
	application := []*mygo.MenuItem{{Label: i18n.T("menu.about"), Role: mygo.RoleAbout}}
	if item := checkForUpdatesMenuItem(); item != nil {
		application = append(application, item)
	}
	application = append(application,
		mygo.Separator(), action(i18n.T("menu.settings"), "CmdOrCtrl+,", menuSettings),
		mygo.Separator(), &mygo.MenuItem{Label: i18n.T("menu.services"), Role: mygo.RoleServices},
		mygo.Separator(), &mygo.MenuItem{Label: i18n.T("menu.hide"), Role: mygo.RoleHide},
		&mygo.MenuItem{Label: i18n.T("menu.hide_others"), Role: mygo.RoleHideOthers},
		&mygo.MenuItem{Label: i18n.T("menu.show_all"), Role: mygo.RoleUnhide},
		mygo.Separator(), &mygo.MenuItem{Label: i18n.T("menu.quit"), Role: mygo.RoleQuit})
	return mygo.NewMenu([]*mygo.MenuItem{
		{Label: "MyGo Vaultwarden", Role: mygo.RoleAppMenu, Submenu: application},
		{Label: i18n.T("menu.edit"), Role: mygo.RoleEditMenu, Submenu: []*mygo.MenuItem{
			{Label: i18n.T("menu.undo"), Role: mygo.RoleUndo},
			{Label: i18n.T("menu.redo"), Role: mygo.RoleRedo}, mygo.Separator(),
			{Label: i18n.T("menu.cut"), Role: mygo.RoleCut},
			{Label: i18n.T("menu.copy"), Role: mygo.RoleCopy},
			{Label: i18n.T("menu.paste"), Role: mygo.RolePaste},
			{Label: i18n.T("menu.select_all"), Role: mygo.RoleSelectAll},
		}},
		{Label: i18n.T("menu.vault"), Submenu: []*mygo.MenuItem{
			action(i18n.T("menu.new_item"), "CmdOrCtrl+N", menuNew),
			action(i18n.T("menu.sync"), "CmdOrCtrl+R", menuSync),
			action(i18n.T("menu.lock"), "CmdOrCtrl+L", menuLock),
			action(i18n.T("menu.import_export"), "", menuBackup),
		}},
		{Label: i18n.T("menu.account"), Submenu: []*mygo.MenuItem{
			action(i18n.T("menu.account_center"), "CmdOrCtrl+Shift+A", menuAccount), mygo.Separator(),
			action(i18n.T("menu.send"), "", menuSend),
			action(i18n.T("menu.devices"), "", menuDevices),
			action(i18n.T("menu.security"), "", menuSecurity),
			action(i18n.T("menu.mfa"), "", menuMFA),
			action(i18n.T("menu.emergency"), "", menuEmergency),
		}},
		{Label: i18n.T("menu.window"), Role: mygo.RoleWindowMenu, Submenu: []*mygo.MenuItem{
			{Label: i18n.T("menu.minimize"), Role: mygo.RoleMinimize},
			{Label: i18n.T("menu.zoom"), Role: mygo.RoleZoom}, mygo.Separator(),
			action(i18n.T("menu.main_window"), "CmdOrCtrl+0", menuMain), mygo.Separator(),
			{Label: i18n.T("menu.bring_all_front"), Role: mygo.RoleFront},
		}},
	})
}
