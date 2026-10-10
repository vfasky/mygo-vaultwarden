// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"net/url"
	"unicode/utf8"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

// Registration takes three steps, one decision each: who the account is
// for, proof of the email address, then the master password.
const (
	registerDetails = iota
	registerVerify
	registerPassword
)

// minMasterPassword is the shortest master password Bitwarden clients accept.
const minMasterPassword = 12

// SignedOut reports a form for a visitor who is not logged in: creating an
// account or asking for the master password hint.
func (f *Form) SignedOut() bool { return f.Mode == "register" || f.Mode == "hint" }

// Heading returns the authentication page title and subtitle for the form.
func (f *Form) Heading() (title, subtitle string) {
	server := f.scope.Server
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		server = u.Host
	}
	if f.Mode == "hint" {
		return i18n.T("account.hint.title"), server
	}
	switch f.step {
	case registerVerify:
		return i18n.T("account.register.verify_title"), f.Email
	case registerPassword:
		return i18n.T("account.register.password_title"), f.Email
	}
	return i18n.T("account.register.title"), i18n.Tf("account.register.subtitle", server)
}

// SignedOutView shows the registration or password hint form in the style
// of the login page.
func SignedOutView(c *ui.Context, f *Form) {
	if f == nil || f.closed {
		return
	}
	ui.Column(c.Key(f.Mode + "-" + string(rune('0'+f.step)))).Gap(16).Children(func() {
		if f.Mode == "hint" {
			passwordHintView(c, f)
		} else {
			switch f.step {
			case registerVerify:
				registerVerifyView(c, f)
			case registerPassword:
				registerPasswordView(c, f)
			default:
				registerDetailsView(c, f)
			}
		}
		if f.Status != "" {
			ui.Text(c, f.Status).FontSize(12).LineHeight(1.5).TextColor(kit.Muted).TextAlign(ui.Center).Role(ui.RoleStatus)
		}
	})
}

func formHint(c *ui.Context, text string) {
	ui.Text(c, text).FontSize(12).LineHeight(1.5).TextColor(kit.Muted)
}

func registerDetailsView(c *ui.Context, f *Form) {
	disabled := f.busy || f.uncertain
	submitted := false
	ui.Field(c, i18n.T("common.email"), func() {
		field := kit.FormInput(ui.TextInput(c, &f.Email).Placeholder("you@example.com").Disabled(disabled))
		if f.Email == "" {
			field.AutoFocus()
		}
		submitted = field.Submitted()
	}).Description(i18n.T("account.register.email_hint"))
	ui.Field(c, i18n.T("account.register.name"), func() {
		field := kit.FormInput(ui.TextInput(c, &f.name).Placeholder(i18n.T("account.register.name_placeholder")).Disabled(disabled))
		if f.Email != "" {
			field.AutoFocus()
		}
		submitted = submitted || field.Submitted()
	})
	label := i18n.T("common.continue")
	if f.busy {
		label = i18n.T("common.status_processing")
	}
	ready := !disabled && f.Email != ""
	if kit.WidePrimary(c, label, !ready).Clicked() || (ready && submitted) {
		f.Status = ""
		f.dispatch("register-send")
	}
}

func registerVerifyView(c *ui.Context, f *Form) {
	disabled := f.busy || f.uncertain
	formHint(c, i18n.Tf("account.register.verify_description", f.Email))
	submitted := false
	ui.Field(c, i18n.T("account.register.token"), func() {
		field := kit.FormInput(ui.TextInput(c, &f.token).Password().Placeholder(i18n.T("account.register.token_placeholder")).
			Disabled(disabled)).AutoFocus()
		submitted = field.Submitted()
	})
	ready := !disabled && f.token != ""
	if kit.WidePrimary(c, i18n.T("common.continue"), !ready).Clicked() || (ready && submitted) {
		f.Status = ""
		f.step = registerPassword
	}
	ui.Row(c).Justify(ui.Center).Wrap().Children(func() {
		if kit.TextLink(c, i18n.T("account.register.resend"), disabled).Clicked() {
			f.Status = ""
			f.dispatch("register-send")
		}
		if kit.TextLink(c, i18n.T("account.register.change_email"), f.busy).Clicked() {
			f.restartRegistration()
		}
	})
}

func registerPasswordView(c *ui.Context, f *Form) {
	disabled := f.busy || f.uncertain
	formHint(c, i18n.T("account.register.password_warning"))
	short := f.newPassword != "" && utf8.RuneCountInString(f.newPassword) < minMasterPassword
	ui.Field(c, i18n.T("login.master_password"), func() {
		field := kit.FormInput(ui.TextInput(c, &f.newPassword).Password().Disabled(disabled)).AutoFocus()
		if field.Changed() {
			f.scorePassword()
		}
	}).Description(i18n.T("account.register.password_requirement"))
	if f.newPassword != "" {
		strengthMeter(c, f.score)
	}
	mismatch := f.repeatPassword != "" && f.repeatPassword != f.newPassword
	submitted := false
	confirm := ui.Field(c, i18n.T("account.register.confirm_password"), func() {
		submitted = kit.FormInput(ui.TextInput(c, &f.repeatPassword).Password().Disabled(disabled)).Submitted()
	})
	if mismatch {
		confirm.Error(i18n.T("account.form.err_password_mismatch"))
	}
	ui.Field(c, i18n.T("account.register.hint"), func() {
		kit.FormInput(ui.TextInput(c, &f.hint).Disabled(disabled))
	}).Description(i18n.T("account.register.hint_description"))
	ui.Collapsible(c, i18n.T("account.register.advanced"), &f.kdfOpen, func() {
		ui.Column(c).Gap(12).Padding(8, 0, 0, 0).Children(func() {
			formHint(c, i18n.T("account.register.kdf_description"))
			kdfFields(c, f, disabled)
		})
	})
	label := i18n.T("account.register.submit")
	if f.busy {
		label = i18n.T("account.register.status_creating")
	}
	ready := !disabled && f.token != "" && f.newPassword != "" && !short && f.repeatPassword == f.newPassword
	if kit.WidePrimary(c, label, !ready).Clicked() || (ready && submitted) {
		f.Status = ""
		f.dispatch("register-finish")
	}
	ui.Row(c).Justify(ui.Center).Children(func() {
		if kit.TextLink(c, i18n.T("account.register.back"), f.busy).Clicked() {
			f.Status = ""
			if f.tokenFromServer {
				f.restartRegistration()
			} else {
				f.step = registerVerify
			}
		}
	})
}

// restartRegistration returns to the first step, forgetting the token and
// any password typed for it.
func (f *Form) restartRegistration() {
	f.clearSecrets()
	f.Status = ""
	f.score = -1
	f.step = registerDetails
	f.tokenFromServer = false
}

func (f *Form) scorePassword() {
	if f.newPassword == "" {
		f.score = -1
		return
	}
	f.evaluate()
}

// strengthMeter shows the zxcvbn score as four bars and a word, as
// registration pages commonly do.
func strengthMeter(c *ui.Context, score int) {
	keys := []string{"account.register.strength_very_weak", "account.register.strength_weak", "account.register.strength_fair", "account.register.strength_good", "account.register.strength_strong"}
	colors := []ui.Color{ui.Hex("#D9534F"), ui.Hex("#D9534F"), ui.Hex("#E0A030"), ui.Hex("#5B9BD5"), ui.Hex("#3A9A5B")}
	if score < 0 || score > 4 {
		return
	}
	ui.Row(c).Gap(10).AlignItems(ui.Center).Margin(-8, 0, 0, 0).Children(func() {
		ui.Row(c).Grow(1).Gap(4).Children(func() {
			for i := 1; i <= 4; i++ {
				bar := ui.Box(c).Grow(1).Height(4).Radius(2).Background(kit.Line)
				if i <= max(score, 1) {
					bar.Background(colors[score])
				}
			}
		})
		ui.Text(c, i18n.Tf("account.register.strength", i18n.T(keys[score]))).FontSize(12).TextColor(colors[score]).Shrink(0)
	}).Label(i18n.Tf("account.register.strength", i18n.T(keys[score])))
}

// kdfFields edits the key derivation settings, PBKDF2 by default.
func kdfFields(c *ui.Context, f *Form, disabled bool) {
	selected := 0
	if f.kdfType == "1" {
		selected = 1
	}
	ui.Field(c, i18n.T("account.register.kdf_algorithm"), func() {
		if ui.Segmented(c, &selected, "PBKDF2-SHA256", "Argon2id").Disabled(disabled).Changed() {
			if selected == 1 {
				f.kdfType, f.iterations = "1", "3"
			} else {
				f.kdfType, f.iterations = "0", "600000"
			}
		}
	})
	ui.Field(c, i18n.T("account.form.kdf_iterations"), func() {
		kit.FormInput(ui.TextInput(c, &f.iterations).Disabled(disabled))
	})
	if f.kdfType == "1" {
		ui.Field(c, i18n.T("account.form.kdf_memory"), func() {
			kit.FormInput(ui.TextInput(c, &f.memory).Disabled(disabled))
		})
		ui.Field(c, i18n.T("account.form.kdf_parallelism"), func() {
			kit.FormInput(ui.TextInput(c, &f.parallelism).Disabled(disabled))
		})
	}
}

func passwordHintView(c *ui.Context, f *Form) {
	disabled := f.busy || f.uncertain
	formHint(c, i18n.T("account.hint.description"))
	submitted := false
	ui.Field(c, i18n.T("common.email"), func() {
		field := kit.FormInput(ui.TextInput(c, &f.Email).Placeholder("you@example.com").Disabled(disabled)).AutoFocus()
		submitted = field.Submitted()
	})
	label := i18n.T("account.hint.submit")
	if f.busy {
		label = i18n.T("common.status_processing")
	}
	ready := !disabled && f.Email != ""
	if kit.WidePrimary(c, label, !ready).Clicked() || (ready && submitted) {
		f.Status = ""
		f.dispatch("password-hint")
	}
}
