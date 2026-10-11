// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func accountCenterFixture(t *testing.T) *app {
	t.Helper()
	a := writableUIFixture(t)
	t.Cleanup(a.stopNetwork)
	a.snapshot.SnapshotID = "fixture-snapshot"
	a.deviceID = "fixture-device-identifier"
	var wire map[string]any
	if err := json.Unmarshal(a.vault.Sync, &wire); err != nil {
		t.Fatal(err)
	}
	wire["sends"] = []any{}
	a.vault.Sync, _ = json.Marshal(wire)
	if err := a.session.(*vaultwarden.Session).AcceptAuthenticatedSnapshot(a.vault, a.sessionRevision); err != nil {
		t.Fatal(err)
	}
	state := *a.snapshot
	a.storageBackend = func(localstore.Request) localstore.Reply { return localstore.Reply{OK: true, State: &state} }
	a.openSendWith(func(f func()) { f() }, a.storageBackend, false)
	if a.sendPanel == nil {
		t.Fatal("Send did not open")
	}
	return a
}

func TestAccountCenterPlaceholderStates(t *testing.T) {
	for _, state := range []string{"open", "processing", "editing"} {
		t.Run(state, func(t *testing.T) {
			a := previewApp()
			a.windows.accountTab = accountTabSend
			a.status = "Fixture status"
			want := i18n.T("accountcenter.open_page_hint")
			switch state {
			case "processing":
				a.pending = 1
				want = i18n.T("accountcenter.processing_hint")
			case "editing":
				a.editor = &cipherEditor{}
				want = i18n.T("accountcenter.finish_editing_hint")
			}
			tt := ui.NewTester(a.accountWindowView, 900, 600)
			if !tt.HasText(want) {
				t.Fatalf("missing placeholder: %s", want)
			}
			for _, text := range tt.Texts() {
				if text == a.status {
					t.Fatal("account center must not show status")
				}
			}
			if state != "open" && tt.HasText(i18n.T("app.settings.open_send")) {
				t.Fatal("blocked placeholder offered to open a panel")
			}
		})
	}
}

func TestAccountCenterNavigationRevokesLease(t *testing.T) {
	for _, tab := range []accountTab{accountTabDevices, accountTabSecurity} {
		t.Run(string(tab), func(t *testing.T) {
			a := accountCenterFixture(t)
			panel, lease := a.sendPanel, a.componentLease
			// Switching still closes the old page while opening is blocked.
			a.pending = 1
			a.openAccountPage(tab)
			if !a.windows.accountOpen || a.windows.accountTab != tab || a.sendPanel != nil || !panel.Closed || a.accountPanelOpen() {
				t.Fatal("page switch retained or opened a panel")
			}
			if err := lease.check(a.storageBackend); !errors.Is(err, vaultwarden.ErrCancelled) {
				t.Fatal("previous lease remains valid", err)
			}
		})
	}
}

func TestAccountCenterCloseRevokesLease(t *testing.T) {
	a := accountCenterFixture(t)
	panel, lease := a.sendPanel, a.componentLease
	panel.New(0)
	panel.Fields.Text = "private send"
	a.closeAccountCenter()
	if a.windows.accountOpen || a.sendPanel != nil || !panel.Closed || panel.Fields.Text != "" {
		t.Fatal("closing account center retained panel secrets")
	}
	if err := lease.check(a.storageBackend); !errors.Is(err, vaultwarden.ErrCancelled) {
		t.Fatal("closed window lease remains valid", err)
	}
}

// Logging in from Settings hides the account center's page, so its panel and
// lease end then, and returning to the vault does not bring the draft back.
func TestAccountCenterLoginFromSettingsRevokesPanel(t *testing.T) {
	a := accountCenterFixture(t)
	panel, lease := a.sendPanel, a.componentLease
	panel.New(0)
	panel.Fields.Text = "private send"
	main := ui.NewTester(a.view, 1280, 820)
	settings := ui.NewTester(a.settingsWindowView, 720, 560)
	uitest.Click(t, settings, "登录服务器")
	main.Frame()
	if !a.showLogin || a.sendPanel != nil || !panel.Closed || panel.Fields.Text != "" {
		t.Fatal("login page retained the account center panel")
	}
	if err := lease.check(a.storageBackend); !errors.Is(err, vaultwarden.ErrCancelled) {
		t.Fatal("login page left the lease valid", err)
	}
	uitest.Click(t, main, "返回密码库")
	account := ui.NewTester(a.accountWindowView, 1080, 720)
	if a.showLogin || !a.unlocked() || a.sendPanel != nil || account.HasText("private send") || !account.HasText(i18n.T("accountcenter.open_page_hint")) {
		t.Fatal("returning to the vault revived the account center panel")
	}
}

func TestAccountCenterLockedView(t *testing.T) {
	for _, login := range []bool{false, true} {
		t.Run(map[bool]string{false: "locked", true: "login"}[login], func(t *testing.T) {
			a := accountCenterFixture(t)
			a.status = "private account status"
			if login {
				a.showLogin = true
			} else {
				a.itemsRevision = ""
			}
			tt := ui.NewTester(a.accountWindowView, 1080, 720)
			if !tt.HasText(i18n.T("accountcenter.unlock_in_main")) || tt.HasText(a.status) || tt.HasText(i18n.T("account.device.title")) || tt.HasText(i18n.T("send.editor.new_text")) {
				t.Fatal("locked account center revealed panel/navigation/status")
			}
		})
	}
}

func TestAccountCenterOpenGuards(t *testing.T) {
	for _, guard := range []string{"pending", "editor", "folder", "bulk", "backup", "organization", "locked", "login"} {
		t.Run(guard, func(t *testing.T) {
			a := accountCenterFixture(t)
			a.advanceEpoch()
			switch guard {
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
			case "locked":
				a.itemsRevision = ""
			case "login":
				a.showLogin = true
			}
			for _, page := range accountPages {
				a.openAccountPage(page.tab)
				if a.windows.accountTab != page.tab || !a.windows.accountOpen || a.accountPanelOpen() {
					t.Fatal("open guard failed", page.tab)
				}
			}
		})
	}
}

func TestAccountCenterSidebarOpensPageAndPreservesCurrentPanel(t *testing.T) {
	a := accountCenterFixture(t)
	panel, epoch := a.sendPanel, a.epoch
	a.openAccountPage(accountTabSend)
	if a.sendPanel != panel || a.epoch != epoch {
		t.Fatal("selecting the current page replaced its panel")
	}
	tt := ui.NewTester(a.accountWindowView, 1080, 720)
	if err := tt.Click(i18n.T("account.form.title")); err != nil {
		t.Fatal(err)
	}
	if a.windows.accountTab != accountTabSecurity || a.accountForm == nil || a.sendPanel != nil || !panel.Closed {
		t.Fatal("sidebar did not open the selected page through its controller")
	}
	a.advanceEpoch()
	tt.Frame()
	tt.Frame()
	if a.accountForm != nil || !tt.HasText(i18n.T("app.settings.open_account_security")) {
		t.Fatal("rendering reopened a revoked panel")
	}
	if err := tt.Click(i18n.T("app.settings.open_account_security")); err != nil {
		t.Fatal(err)
	}
	if a.accountForm == nil {
		t.Fatal("explicit reopen failed")
	}
}
