// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestAccountNativeFormSensitiveClearAndRegistration(t *testing.T) {
	var request accountFormRequest
	calls := 0
	f := newAccountForm(vaultwarden.Scope{Server: "https://test.invalid", Account: "a"}, 4, func(r accountFormRequest) { request = r; calls++ })
	f.mode = "register"
	f.newPassword = "Secret-Registration-492!"
	f.repeatPassword = f.newPassword
	f.password = "Old-secret"
	f.token = "verification-token"
	tt := ui.NewTester(func(c *ui.Context) { accountFormView(c, f) }, 1200, 2400)
	if !tt.HasText("账号与安全") || !tt.HasText("完成注册") || !tt.HasText("评估密码强度") {
		t.Fatal("native account controls absent")
	}
	if tt.HasText(f.newPassword) || tt.HasText(f.password) || tt.HasText(f.token) {
		t.Fatal("unmasked secret")
	}
	f.dispatch("register-finish")
	if calls != 1 || request.Operation != "register-finish" || request.Token != "verification-token" || f.newPassword != "" || f.token != "" {
		t.Fatal("dispatch/clear contract")
	}
	request.Close()
	if !f.registration(f.scope, f.epoch, f.sequence, vaultwarden.AccountRegistrationVerification{EmailSent: true}, nil) || f.status != "验证邮件已请求发送，请输入邮件中的注册令牌" {
		t.Fatal("SMTP status missing")
	}
	if !f.registration(f.scope, f.epoch, f.sequence, vaultwarden.AccountRegistrationVerification{Token: "returned-token"}, nil) || f.token != "returned-token" {
		t.Fatal("direct registration token lost")
	}
	f.cancel()
	if f.token != "" || f.password != "" || f.newPassword != "" || f.confirming {
		t.Fatal("cancel retained secrets")
	}
}
func TestAccountNativeAPIKeyTwoStepsAndLateResults(t *testing.T) {
	calls := 0
	var request accountFormRequest
	f := newAccountForm(vaultwarden.Scope{Server: "https://test.invalid", Account: "a"}, 8, func(r accountFormRequest) { calls++; request = r })
	f.mode = "api-key"
	f.password = "secret-password"
	tt := ui.NewTester(func(c *ui.Context) { accountFormView(c, f) }, 1200, 2400)
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
	if f.completed(scope, epoch, seq, vaultwarden.AccountChangeResult{Confirmed: true}, nil) || f.registration(scope, epoch, seq, vaultwarden.AccountRegistrationVerification{Token: "late"}, nil) {
		t.Fatal("closed form revived")
	}
	if f.token != "" || f.password != "" {
		t.Fatal("late secret retained")
	}
}
func TestAccountNativeScopeEpochAndUnknown(t *testing.T) {
	scope := vaultwarden.Scope{Server: "https://test.invalid", Account: "a"}
	f := newAccountForm(scope, 11, func(accountFormRequest) {})
	if f.completed(vaultwarden.Scope{Server: scope.Server, Account: "other"}, 11, 0, vaultwarden.AccountChangeResult{}, nil) || f.completed(scope, 10, 0, vaultwarden.AccountChangeResult{}, nil) {
		t.Fatal("cross scope/epoch adopted")
	}
	f.password = "secret"
	if !f.completed(scope, 11, 0, vaultwarden.AccountChangeResult{Scope: scope, Dispatched: true, Unknown: true, RequireLogin: true}, nil) || !f.uncertain || f.password != "" {
		t.Fatal("unknown state missing")
	}
	calls := 0
	f.submit = func(accountFormRequest) { calls++ }
	f.dispatch("prepare-purge")
	if calls != 0 {
		t.Fatal("unknown operation retried")
	}
}
