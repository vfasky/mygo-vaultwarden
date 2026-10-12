// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestAuthFormViewMethodsAndRecoveryDetour(t *testing.T) {
	var sent []AuthRequest
	f := NewAuthForm(vaultwarden.Scope{Server: "https://vault.example.com"}, 1, func(r AuthRequest) { sent = append(sent, r) })
	f.DisableRemember = true
	providers := map[int]string{0: i18n.T("account.mfa.authenticator_code"), 1: i18n.T("account.mfa.email_code")}
	platform, emails := 0, 0
	opts := AuthOptions{
		Platform:   map[int]string{7: i18n.T("account.mfa.system_security_key")},
		OnPlatform: func(p int) { platform = p },
		SendEmail:  func() { emails++ },
	}
	tt := ui.NewTester(func(c *ui.Context) { AuthFormView(c, f, providers, opts) }, 360, 700)

	// One method is shown at a time; the email method offers to send a code.
	if !tt.HasText("其他验证方式") || tt.HasText("发送邮件验证码") || tt.HasText(i18n.T("account.mfa.confirm_recovery_code_impact")) {
		t.Fatalf("authenticator view: %q", tt.Texts())
	}
	uitest.Click(t, tt, "邮件验证码")
	tt.Frame()
	if f.Provider != 1 || !tt.HasText("发送邮件验证码") {
		t.Fatalf("email method not selected: %d %q", f.Provider, tt.Texts())
	}
	uitest.Click(t, tt, "发送邮件验证码")
	uitest.Click(t, tt, "系统安全密钥")
	if emails != 1 || platform != 7 {
		t.Fatalf("emails %d platform %d", emails, platform)
	}

	// Recovery is a detour that warns before anything is sent.
	uitest.Click(t, tt, "无法使用以上方式？使用恢复码")
	tt.Frame()
	if f.Provider != 8 || !tt.HasText("返回其他验证方式") || !tt.HasText(i18n.T("account.mfa.confirm_recovery_code_impact")) {
		t.Fatalf("recovery view: %q", tt.Texts())
	}
	f.Token = "recovery"
	tt.Frame()
	uitest.Click(t, tt, "继续验证")
	tt.Frame()
	if !f.Confirming || len(sent) != 0 {
		t.Fatal("recovery code sent without confirmation")
	}
	uitest.Click(t, tt, "取消")
	tt.Frame()
	uitest.Click(t, tt, "返回其他验证方式")
	tt.Frame()
	if f.Provider != 0 || f.Token != "" || f.Confirming {
		t.Fatalf("back to methods: provider %d", f.Provider)
	}
}
