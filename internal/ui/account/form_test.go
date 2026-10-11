// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestAccountNativeAPIKeyTwoStepsAndLateResults(t *testing.T) {
	calls := 0
	var request FormRequest
	f := NewForm(vaultwarden.Scope{Server: "https://test.invalid", Account: "a"}, 8, func(r FormRequest) { calls++; request = r })
	f.Mode = "api-key"
	f.password = "secret-password"
	tt := ui.NewTester(func(c *ui.Context) { FormView(c, f) }, 1200, 2400)
	if err := tt.Click("轮换 API key"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if calls != 0 || !f.confirming || !tt.HasText("确认执行") {
		t.Fatal("missing first confirmation")
	}
	if err := tt.Click("取消"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if calls != 0 || f.password != "" || f.confirming {
		t.Fatal("cancel dispatched API rotation")
	}
	f.password = "another-secret"
	tt.Frame()
	if err := tt.Click("查看 API key"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if err := tt.Click("确认执行"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || request.Confirmation != "api-key" {
		t.Fatal("confirm not dispatched")
	}
	request.Close()
	epoch, seq := f.epoch, f.sequence
	scope := f.scope
	f.Close()
	if f.Completed(scope, epoch, seq, vaultwarden.AccountChangeResult{Confirmed: true}, nil) || f.Registration(scope, epoch, seq, vaultwarden.AccountRegistrationVerification{Token: "late"}, nil) {
		t.Fatal("closed form revived")
	}
	if f.token != "" || f.password != "" {
		t.Fatal("late secret retained")
	}
}
func TestAccountNativeScopeEpochAndUnknown(t *testing.T) {
	scope := vaultwarden.Scope{Server: "https://test.invalid", Account: "a"}
	f := NewForm(scope, 11, func(FormRequest) {})
	if f.Completed(vaultwarden.Scope{Server: scope.Server, Account: "other"}, 11, 0, vaultwarden.AccountChangeResult{}, nil) || f.Completed(scope, 10, 0, vaultwarden.AccountChangeResult{}, nil) {
		t.Fatal("cross scope/epoch adopted")
	}
	f.password = "secret"
	if !f.Completed(scope, 11, 0, vaultwarden.AccountChangeResult{Scope: scope, Dispatched: true, Unknown: true, RequireLogin: true}, nil) || !f.uncertain || f.password != "" {
		t.Fatal("unknown state missing")
	}
	calls := 0
	f.Submit = func(FormRequest) { calls++ }
	f.dispatch("prepare-purge")
	if calls != 0 {
		t.Fatal("unknown operation retried")
	}
}

// The operation menu switches the form, clearing the secrets of the last
// operation, and does nothing while the form is busy or uncertain.
func TestAccountFormOperationSelector(t *testing.T) {
	f := NewForm(vaultwarden.Scope{Server: "https://test.invalid", Account: "a"}, 3, func(FormRequest) {})
	f.Mode = "profile"
	// The section title shows the mode too, so the menu is opened from the
	// keyboard: it is the first control of the form.
	open := func() *ui.Tester {
		tt := ui.NewTester(func(c *ui.Context) { FormView(c, f) }, 1200, 2400)
		tt.Key(0, ui.KeyTab)
		tt.Key(0, ui.KeySpace)
		return tt
	}
	choose := func(from, to string) {
		t.Helper()
		tt := open()
		if err := tt.Click(accountModeLabel(to)); err != nil {
			t.Fatal(err)
		}
		tt.Frame()
	}
	for _, step := range [][2]string{{"profile", "password"}, {"password", "api-key"}, {"api-key", "rotate-user-key"}} {
		f.password = "secret-password"
		choose(step[0], step[1])
		if f.Mode != step[1] || f.password != "" {
			t.Fatalf("choosing %s: mode=%s password cleared=%v", step[1], f.Mode, f.password == "")
		}
	}
	if !open().HasText(accountModeLabel("rotate-user-key")) {
		t.Fatal("rotation form not shown")
	}
	for _, state := range []string{"busy", "uncertain"} {
		f.busy, f.uncertain = state == "busy", state == "uncertain"
		tt := open()
		_ = tt.Click(accountModeLabel("profile"))
		tt.Frame()
		if f.Mode != "rotate-user-key" {
			t.Fatalf("%s form switched to %s", state, f.Mode)
		}
	}
}
