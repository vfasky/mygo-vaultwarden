// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
)

func TestMenuWindowCommands(t *testing.T) {
	a := previewApp()
	a.category = "favorites"
	a.runMenuCommand(menuSettings)
	if !a.windows.settingsOpen || a.windows.settingsTab != settingsTabAccount || a.category != "favorites" {
		t.Fatal("settings changed vault filter or did not open")
	}
	a.runMenuCommand(menuAccount)
	if !a.windows.accountOpen || a.windows.accountTab != accountTabSend {
		t.Fatal("account center did not default to Send")
	}
	for command, tab := range map[menuCommand]accountTab{menuDevices: accountTabDevices, menuSecurity: accountTabSecurity, menuSend: accountTabSend} {
		a.runMenuCommand(command)
		if a.windows.accountTab != tab {
			t.Fatalf("%s selected %s", command, a.windows.accountTab)
		}
	}
	a.windows.accountTab = accountTabDevices
	a.runMenuCommand(menuAccount)
	if a.windows.accountTab != accountTabDevices {
		t.Fatal("account center forgot last page")
	}
}

func TestMenuRejectsUnavailableCommands(t *testing.T) {
	for _, state := range []string{"locked", "login", "pending", "editor", "folder", "bulk", "backup", "organization"} {
		t.Run(state, func(t *testing.T) {
			a := writableUIFixture(t)
			defer a.stopNetwork()
			switch state {
			case "locked":
				a.itemsRevision = ""
			case "login":
				a.showLogin = true
			case "pending":
				a.pending = 1
			case "editor":
				a.editor = &cipherEditor{}
			case "folder":
				a.folderEditor = &folderEditor{}
			case "bulk":
				a.bulkEditor = &bulkEditor{}
			case "backup":
				a.backupEditor = &backupEditor{}
			case "organization":
				a.organizationEditor = &organizationEditor{}
			}
			editor, backup, epoch := a.editor, a.backupEditor, a.epoch
			for _, command := range []menuCommand{menuNew, menuBackup, menuAccount, menuDevices} {
				a.runMenuCommand(command)
			}
			if a.editor != editor || a.backupEditor != backup || a.epoch != epoch {
				t.Fatal("unavailable command changed state")
			}
			// The account center opens to say why, without a panel or a new lease.
			if !a.windows.accountOpen || a.sendPanel != nil || a.devicePanel != nil || a.componentLease != nil {
				t.Fatal("unavailable account page opened a panel or no window")
			}
			if state == "pending" {
				a.runMenuCommand(menuSync)
				if a.pending != 1 || a.epoch != epoch {
					t.Fatal("sync ran while pending")
				}
			}
		})
	}
}

func TestMenuNewItemAndLock(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.category = "note"
	a.runMenuCommand(menuNew)
	if a.editor == nil {
		t.Fatal("new item did not open")
	}
	queue := make(chan func(), 1)
	a.uiDispatcher = func(f func()) { queue <- f }
	a.storageBackend = func(request localstore.Request) localstore.Reply {
		if request.Operation != "lock" {
			return localstore.Reply{}
		}
		return localstore.Reply{OK: true}
	}
	a.masterPassword = "fixture secret"
	a.runMenuCommand(menuLock)
	if a.unlocked() || a.editor != nil || a.masterPassword != "" {
		t.Fatal("lock retained sensitive state")
	}
	select {
	case complete := <-queue:
		complete()
	case <-time.After(5 * time.Second):
		t.Fatal("lock completion missing")
	}
}

func TestSidebarWindowEntrances(t *testing.T) {
	for _, collapsed := range []bool{false, true} {
		a := previewApp()
		a.sidebarCollapsed = collapsed
		tt := ui.NewTester(func(c *ui.Context) { a.sidebar(c) }, 237, 820)
		if collapsed {
			if len(tt.Texts()) != 0 {
				t.Fatal("hidden sidebar retained window entrances")
			}
			continue
		}
		uitest.Click(t, tt, "账号中心")
		if !a.windows.accountOpen {
			t.Fatal("account center entrance missing")
		}
		if _, found := tt.Find("设置"); found {
			t.Fatal("sidebar retained redundant settings entrance")
		}
		a.windows.accountOpen = false
		a.itemsRevision = ""
		tt.Frame()
		uitest.Click(t, tt, "账号中心")
		if a.windows.accountOpen {
			t.Fatal("locked sidebar opened account center")
		}
	}
}
