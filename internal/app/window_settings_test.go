// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
)

func TestWindowsVisualPreviews(t *testing.T) {
	dir := os.Getenv("MYGO_UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MYGO_UI_PREVIEW_DIR to export window previews")
	}
	language := i18n.Current()
	defer i18n.Set(language)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	export := func(name string, view func(*ui.Context), width, height int) {
		t.Helper()
		tt := ui.NewTester(view, width, height)
		if strings.HasSuffix(name, "-bottom") {
			tt.Scroll(float32(width-40), float32(height/2), 0, 1000)
		}
		f, err := os.Create(filepath.Join(dir, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		err = png.Encode(f, tt.Image())
		closeErr := f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	for _, tab := range []settingsTab{settingsTabGeneral, settingsTabAccount, settingsTabStorage, settingsTabUpdates, settingsTabAbout} {
		a := previewApp()
		a.windows.settingsTab = tab
		export("settings-"+string(tab), a.settingsWindowView, 720, 560)
		if tab == settingsTabAccount {
			export("settings-account-full", a.settingsWindowView, 720, 1000)
			export("settings-account-bottom", a.settingsWindowView, 720, 560)
		}
	}
	for _, tab := range []settingsTab{settingsTabAccount, settingsTabUpdates} {
		i18n.Set(i18n.English)
		a := previewApp()
		a.windows.settingsTab = tab
		export("settings-"+string(tab)+"-en-min", a.settingsWindowView, 620, 460)
		export("settings-"+string(tab)+"-en-min-bottom", a.settingsWindowView, 620, 460)
		i18n.Set(language)
	}
	a := previewApp()
	a.windows.settingsTab = settingsTabStorage
	a.snapshot.IndexPending, a.snapshot.CleanupPending = true, true
	export("settings-storage-pending", a.settingsWindowView, 720, 560)
	a = passwordLockedApp()
	a.windows.settingsTab = settingsTabAccount
	export("settings-account-locked", a.settingsWindowView, 720, 560)
	for _, page := range accountPages {
		a := previewApp()
		a.windows.accountTab = page.tab
		export("account-open-"+string(page.tab), a.accountWindowView, 1080, 720)
	}
	for _, state := range []string{"processing", "editing", "locked"} {
		a := previewApp()
		a.windows.accountTab = accountTabSend
		switch state {
		case "processing":
			a.pending = 1
		case "editing":
			a.editor = &cipherEditor{}
		case "locked":
			a = passwordLockedApp()
		}
		export("account-"+state, a.accountWindowView, 1080, 720)
	}
}

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
	for _, text := range []string{i18n.T("settings.updates.unavailable_hint"), i18n.T("settings.updates.last_check"), i18n.T("settings.updates.never_checked"), i18n.T("settings.version_label"), "—"} {
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
		for _, label := range []string{i18n.T("settings.account.send"), i18n.T("account.device.title"), i18n.T("account.form.title")} {
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

// General works while locked, and a language chosen there applies at once,
// to the menu bar and window titles too (frame).
func TestSettingsWindowGeneralLanguage(t *testing.T) {
	defer i18n.SetPreference("")
	a := passwordLockedApp()
	a.windows.language = i18n.Current()
	tt := ui.NewTester(a.frame(func() *mygo.Window { return nil }, a.settingsWindowView), 720, 560)
	uitest.Click(t, tt, "通用")
	if a.windows.settingsTab != settingsTabGeneral || !tt.HasText("简体中文") {
		t.Fatalf("general tab missing while locked: %q", tt.Texts())
	}
	// The card is titled 语言 too; the picker shows the current language.
	uitest.Click(t, tt, "简体中文")
	if err := tt.ChooseMenuItem("English"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if i18n.Current() != i18n.English || !tt.HasText("General") || !tt.HasText("Account") || a.windows.language != i18n.English {
		t.Fatalf("language did not apply to the window and its titles: %q", tt.Texts())
	}
}
