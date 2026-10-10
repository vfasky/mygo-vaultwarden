// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestAccountEnglishAPIKeyConfirmationPreservesProtocol(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	var request FormRequest
	calls := 0
	f := NewForm(vaultwarden.Scope{}, 1, func(r FormRequest) { request = r; calls++ })
	defer f.Close()
	defer request.Close()
	f.Mode = "api-key"
	tt := ui.NewTester(func(c *ui.Context) { FormView(c, f) }, 1200, 2400)
	if err := tt.Click("Rotate API key"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if calls != 0 || !f.confirming || !tt.HasText("Your personal API key is a sensitive credential. Rotating it invalidates the old key. Confirm before continuing.") {
		t.Fatal("English API key action bypassed confirmation or omitted warning")
	}
	if err := tt.Click("Confirm and run"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || request.Operation != "rotate-api-key" || request.Confirmation != "rotate-api-key" {
		t.Fatal("translated action changed the protocol or confirmation value")
	}
}
