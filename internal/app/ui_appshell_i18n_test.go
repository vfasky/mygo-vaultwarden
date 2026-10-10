// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
)

func TestAppShellEnglishLogin(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	a := &app{snapshot: &localstore.SnapshotStatus{Revision: "empty"}, deviceID: "fixture",
		serverURL: "https://vault.example.com", email: "invalid"}
	tt := ui.NewTester(a.view, 1060, 700)
	for _, text := range []string{"Log in to server", "Server URL", "Email", "Master password", "Log in and sync"} {
		if !tt.HasText(text) {
			t.Errorf("English login page missing %q", text)
		}
	}
	uitest.Click(t, tt, "Log in and sync")
	if a.status != "Enter your login email." || a.pending != 0 {
		t.Fatalf("English validation = %q, pending = %d", a.status, a.pending)
	}
	if !tt.HasText("Enter your login email.") {
		t.Fatal("English validation is not displayed")
	}
}
