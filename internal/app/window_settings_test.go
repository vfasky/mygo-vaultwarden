// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
)

func TestSettingsWindowTabs(t *testing.T) {
	a := previewApp()
	tt := ui.NewTester(a.settingsWindowView, 720, 560)
	if !tt.HasText(i18n.T("app.settings.connect_vault")) || tt.HasText(i18n.T("app.settings.refresh_status")) {
		t.Fatal("default tab must show only account settings")
	}
	for _, pane := range []struct {
		tab            settingsTab
		label, content string
	}{
		{settingsTabStorage, i18n.T("app.settings.local_storage_autofill"), i18n.T("app.settings.refresh_status")},
		{settingsTabUpdates, i18n.T("settings.tab.updates"), i18n.T("settings.updates.automatic_checks")},
		{settingsTabAbout, i18n.T("settings.tab.about"), i18n.T("settings.about.license")},
		{settingsTabAccount, i18n.T("settings.tab.account"), i18n.T("app.settings.connect_vault")},
	} {
		uitest.Click(t, tt, pane.label)
		if a.windows.settingsTab != pane.tab || !tt.HasText(pane.content) {
			t.Fatalf("tab %s did not render its content", pane.tab)
		}
	}
}

func TestSettingsWindowHidesAccountWhileLockedOrLoggingIn(t *testing.T) {
	for _, loggingIn := range []bool{false, true} {
		for _, tab := range []settingsTab{settingsTabAccount, settingsTabStorage} {
			a := passwordLockedApp()
			if loggingIn {
				a = writableUIFixture(t)
				a.showLogin = true
			}
			a.serverURL, a.email, a.masterPassword = "https://private.example.invalid", "private@example.invalid", "private-input"
			a.windows.settingsTab = tab
			tt := ui.NewTester(a.settingsWindowView, 720, 560)
			if !tt.HasText(i18n.T("settings.show_main_window")) || !tt.HasText(i18n.T("app.list.status_locked")) {
				t.Fatal("locked settings must offer the main window")
			}
			text := strings.Join(tt.Texts(), "\n")
			for _, secret := range []string{a.serverURL, a.email, a.masterPassword, a.snapshot.Scope.Server, a.snapshot.Scope.Account, a.snapshot.PasswordUnlock.Email, "Fixture card"} {
				if strings.Contains(text, secret) {
					t.Fatalf("locked tab %s exposed %q", tab, secret)
				}
			}
			for _, label := range []string{i18n.T("app.settings.connect_vault"), i18n.T("app.settings.refresh_status"), i18n.T("app.settings.bind_master_password_label")} {
				if tt.HasText(label) {
					t.Fatalf("locked tab exposed control %q", label)
				}
			}
		}
	}
}

func TestSettingsWindowUpdatesWithoutPlugin(t *testing.T) {
	if updaterUsed.Load() {
		t.Fatal("headless tests must not install the updater")
	}
	a := passwordLockedApp()
	a.windows.settingsTab = settingsTabUpdates
	tt := ui.NewTester(a.settingsWindowView, 720, 560)
	for _, text := range []string{i18n.T("settings.updates.unavailable_hint"), i18n.Tf("settings.updates.last_check", i18n.T("settings.updates.never_checked")), i18n.Tf("settings.version", "—")} {
		if !tt.HasText(text) {
			t.Fatalf("missing update state: %s", text)
		}
	}
	uitest.Click(t, tt, i18n.T("settings.updates.automatic_checks"))
	uitest.Click(t, tt, i18n.T("settings.updates.automatic_downloads"))
	uitest.Click(t, tt, i18n.T("settings.updates.check_now"))
	if state := currentUpdateState(); state.Enabled || state.AutomaticChecks || state.AutomaticDownloads {
		t.Fatal("unavailable updater controls changed state")
	}
}

func TestSettingsWindowAccountServicesDisabled(t *testing.T) {
	for _, editing := range []bool{false, true} {
		a := writableUIFixture(t)
		reason := i18n.T("settings.account.wait_hint")
		if editing {
			a.openCipherEditor("card-1", 3)
			reason = i18n.T("settings.account.editor_hint")
		} else {
			a.pending = 1
		}
		tt := ui.NewTester(a.settingsWindowView, 720, 560)
		if !tt.HasText(reason) {
			t.Fatal("disabled account services need an explanation")
		}
		epoch := a.epoch
		for _, label := range []string{i18n.T("settings.account.send"), i18n.T("account.device.title"), i18n.T("account.form.title"), i18n.T("app.settings.mfa"), i18n.T("account.emergency.title")} {
			uitest.Click(t, tt, label)
			if a.windows.accountOpen || a.epoch != epoch || a.sendPanel != nil || a.devicePanel != nil || a.accountForm != nil || a.authManagement != nil || a.orgServices != nil {
				t.Fatalf("disabled account service %q opened a panel", label)
			}
		}
	}
}

func TestSettingsWindowLoginServer(t *testing.T) {
	a := previewApp()
	a.status = "previous status"
	a.masterPassword = "previous secret"
	tt := ui.NewTester(a.settingsWindowView, 720, 560)
	uitest.Click(t, tt, i18n.T("login.title"))
	if !a.showLogin || a.status != "" || a.masterPassword != "" {
		t.Fatal("server login did not reset the form and open login")
	}
	if !tt.HasText(i18n.T("settings.show_main_window")) || tt.HasText(i18n.T("app.settings.connect_vault")) {
		t.Fatal("settings retained account details after opening login")
	}
}
