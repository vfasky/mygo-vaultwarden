// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
)

func TestUnlockLanguageMenuSwitchesAtOnce(t *testing.T) {
	defer i18n.SetPreference("")
	a := passwordLockedApp()
	tt := ui.NewTester(a.view, 1060, 700)
	if !tt.HasText("解锁密码库") || !tt.HasText("简体中文") {
		t.Fatalf("unlock page should start in Chinese: %q", tt.Texts())
	}
	uitest.Click(t, tt, "语言")
	if err := tt.ChooseMenuItem("English"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if i18n.Preference() != i18n.English || !tt.HasText("Unlock vault") || !tt.HasText("English") || tt.HasText("解锁密码库") {
		t.Fatalf("English was not applied at once: %q", tt.Texts())
	}
	uitest.Click(t, tt, "Language")
	if err := tt.ChooseMenuItem("Follow system"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if i18n.Preference() != "" || !tt.HasText("解锁密码库") {
		t.Fatalf("following the system again should restore Chinese in tests: %q", tt.Texts())
	}
}
