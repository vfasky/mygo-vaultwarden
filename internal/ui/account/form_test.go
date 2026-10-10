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
