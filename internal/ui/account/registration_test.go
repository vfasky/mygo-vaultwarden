// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

const testMasterPassword = "Correct-horse-battery-42"

func registrationForm(submit func(FormRequest)) *Form {
	f := NewForm(vaultwarden.Scope{Server: "https://vault.example.com"}, 4, submit)
	f.Mode, f.Modes = "register", []string{"register"}
	return f
}

func TestRegistrationStepsAndSecrets(t *testing.T) {
	var request FormRequest
	calls := 0
	f := registrationForm(func(r FormRequest) { request = r; calls++ })
	tt := ui.NewTester(func(c *ui.Context) { SignedOutView(c, f) }, 400, 1400)
	if title, subtitle := f.Heading(); title != "创建账号" || subtitle != "在 vault.example.com 上创建 Vaultwarden 账号" {
		t.Fatalf("heading %q / %q", title, subtitle)
	}
	for _, text := range []string{"邮箱", "名称（可选）", "我们会向该邮箱发送验证邮件。"} {
		if !tt.HasText(text) {
			t.Errorf("details step missing %q", text)
		}
	}
	f.Email = "new@example.com"
	tt.Frame()
	uitest.Click(t, tt, "继续")
	if calls != 1 || request.Operation != "register-send" || request.Email != "new@example.com" {
		t.Fatalf("register-send not dispatched: %d %+v", calls, request.Operation)
	}
	request.Close()

	// The server emailed a token: ask for it on its own page.
	if !f.Registration(f.scope, f.epoch, f.sequence, vaultwarden.AccountRegistrationVerification{EmailSent: true}, nil) || f.step != registerVerify || f.Status != "" {
		t.Fatal("email verification step missing")
	}
	tt.Frame()
	if title, _ := f.Heading(); title != "查收验证邮件" || !tt.HasText("注册令牌") || !tt.HasText("重新发送邮件") {
		t.Fatalf("verify step: %q", tt.Texts())
	}
	f.token = "verification-token"
	tt.Frame()
	uitest.Click(t, tt, "继续")
	tt.Frame()
	if f.step != registerPassword || calls != 1 {
		t.Fatal("token step did not advance locally")
	}

	// Password step: confirmation and the 12-character minimum gate the button.
	f.newPassword, f.repeatPassword = "short", "short"
	tt.Frame()
	uitest.Click(t, tt, "创建账号")
	if calls != 1 {
		t.Fatal("a short master password was submitted")
	}
	f.newPassword, f.repeatPassword = testMasterPassword, "Correct-horse-battery-43"
	tt.Frame()
	if !tt.HasText("两次主密码不一致") {
		t.Fatal("mismatch not shown inline")
	}
	if tt.HasText(testMasterPassword) || tt.HasText(f.token) {
		t.Fatal("unmasked secret")
	}
	f.repeatPassword = testMasterPassword
	f.hint = "horse"
	tt.Frame()
	uitest.Click(t, tt, "创建账号")
	if calls != 2 || request.Operation != "register-finish" || request.Token != "verification-token" || string(request.NewPassword) != testMasterPassword || request.Hint != "horse" || request.KDF.Iterations != 600000 {
		t.Fatalf("register-finish request: %+v", request.Operation)
	}
	if f.newPassword != "" || f.repeatPassword != "" || f.token != "" {
		t.Fatal("secrets kept after submission")
	}
	request.Close()

	// A failed finish needs the token again, which was cleared on submit.
	f.Completed(f.scope, f.epoch, f.sequence, vaultwarden.AccountChangeResult{}, vaultwarden.ErrValidation)
	if f.step != registerVerify {
		t.Fatal("failed registration should ask for the token again")
	}
	f.restartRegistration()
	if f.step != registerDetails || f.token != "" {
		t.Fatal("restart kept state")
	}
}

func TestRegistrationTokenFromServerSkipsEmail(t *testing.T) {
	f := registrationForm(func(FormRequest) {})
	f.Registration(f.scope, f.epoch, f.sequence, vaultwarden.AccountRegistrationVerification{Token: "returned-token"}, nil)
	if f.step != registerPassword || f.token != "returned-token" || !f.tokenFromServer {
		t.Fatal("direct registration token lost")
	}
	f.Registration(f.scope, f.epoch, f.sequence, vaultwarden.AccountRegistrationVerification{}, vaultwarden.ErrNetwork)
	if f.Status != "请求失败或结果未知，请检查邮箱后再继续" {
		t.Fatalf("error status %q", f.Status)
	}
}

func TestRegistrationKDFAdvanced(t *testing.T) {
	f := registrationForm(func(FormRequest) {})
	f.step, f.kdfOpen = registerPassword, true
	tt := ui.NewTester(func(c *ui.Context) { SignedOutView(c, f) }, 400, 1600)
	uitest.Click(t, tt, "Argon2id")
	tt.Frame()
	if f.kdfType != "1" || f.iterations != "3" || !tt.HasText("内存 MiB（16–1024）") {
		t.Fatalf("Argon2id defaults: %s %s", f.kdfType, f.iterations)
	}
}

func TestPasswordHintPage(t *testing.T) {
	var request FormRequest
	f := registrationForm(func(r FormRequest) { request = r })
	f.Mode, f.Modes = "hint", []string{"hint"}
	f.Email = "me@example.com"
	tt := ui.NewTester(func(c *ui.Context) { SignedOutView(c, f) }, 400, 800)
	if title, _ := f.Heading(); title != "获取主密码提示" || tt.HasText("创建账号") {
		t.Fatal("hint page shows registration")
	}
	uitest.Click(t, tt, "发送提示")
	if request.Operation != "password-hint" || request.Email != "me@example.com" {
		t.Fatalf("hint request %q", request.Operation)
	}
}

func TestRegistrationEnglish(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	f := registrationForm(func(FormRequest) {})
	f.step = registerPassword
	f.newPassword = testMasterPassword
	f.scorePassword()
	tt := ui.NewTester(func(c *ui.Context) { SignedOutView(c, f) }, 400, 1400)
	for _, text := range []string{"Master password", "At least 12 characters", "Confirm master password", "Master password hint (optional)", "Advanced: key derivation", "Create account"} {
		if !tt.HasText(text) {
			t.Errorf("English registration missing %q", text)
		}
	}
	if title, _ := f.Heading(); title != "Set your master password" {
		t.Fatal(title)
	}
}
