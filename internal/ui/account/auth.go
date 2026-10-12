// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// authForm is UI-thread owned. Scheduler closes every emitted request and
// passes matching scope/epoch/sequence when posting completion on UI thread.
type AuthForm struct {
	scope                              vaultwarden.Scope
	epoch, sequence                    uint64
	Provider                           int
	Token, Status                      string
	remember, Confirming, Busy, Closed bool
	method, shownMethod                int
	recovery                           bool
	DisableRemember                    bool
	cancel                             context.CancelFunc
	submit                             func(AuthRequest)
}
type AuthRequest struct {
	Scope           vaultwarden.Scope
	Epoch, Sequence uint64
	Response        vaultwarden.MFAResponse
	Context         context.Context
}

func (r *AuthRequest) Close() { clear(r.Response.Token); r.Response.Token = nil }
func NewAuthForm(scope vaultwarden.Scope, epoch uint64, submit func(AuthRequest)) *AuthForm {
	return &AuthForm{scope: scope, epoch: epoch, submit: submit}
}
func (f *AuthForm) Close() {
	if f.cancel != nil {
		f.cancel()
	}
	f.Token = ""
	f.Confirming = false
	f.Busy = false
	f.Closed = true
	f.sequence++
}
func (f *AuthForm) Dispatch() {
	if f.Closed || f.Busy || f.submit == nil || f.Token == "" {
		return
	}
	if f.Provider == 8 && !f.Confirming {
		f.Confirming = true
		f.Status = i18n.T("account.mfa.confirm_recovery_code_impact")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.sequence++
	f.Busy = true
	r := AuthRequest{Scope: f.scope, Epoch: f.epoch, Sequence: f.sequence, Context: ctx, Response: vaultwarden.MFAResponse{Provider: f.Provider, Token: []byte(f.Token), Remember: f.remember, ConfirmRemoveAllMFA: f.Provider == 8 && f.Confirming}}
	f.Token = ""
	f.Confirming = false
	f.submit(r)
}
func (f *AuthForm) complete(scope vaultwarden.Scope, epoch, sequence uint64, err error) bool {
	if f.Closed || scope != f.scope || epoch != f.epoch || sequence != f.sequence {
		return false
	}
	if f.cancel != nil {
		f.cancel()
		f.cancel = nil
	}
	f.Busy = false
	f.Token = ""
	if err != nil {
		f.Status = i18n.T("account.mfa.err_verification_uncertain")
	} else {
		f.Status = i18n.T("account.mfa.status_response_completed")
	}
	return true
}

// AuthOptions adds the methods that do not take a typed code: platform
// providers (Duo, system security key) run outside the form, and email codes
// may need to be requested first.
type AuthOptions struct {
	Platform    map[int]string
	OnPlatform  func(int)
	SendEmail   func()
	SubmitLabel string
}

// AuthFormView is a sign-in style verification step: a switch between the
// code methods, one labeled input, one primary action, and the other methods
// below. The recovery code is a deliberate detour because it removes MFA.
func AuthFormView(c *ui.Context, f *AuthForm, providers map[int]string, opts AuthOptions) {
	if f == nil || f.Closed {
		return
	}
	var codes []int
	for _, p := range []int{0, 1, 3} {
		if _, ok := providers[p]; ok {
			codes = append(codes, p)
		}
	}
	var platforms []int
	if opts.OnPlatform != nil {
		for _, p := range []int{7, 2} {
			if _, ok := opts.Platform[p]; ok {
				platforms = append(platforms, p)
			}
		}
	}
	// Without another way in, the recovery code is the only form left.
	recovery := f.Provider == 8 && (f.recovery || len(codes) == 0 && len(platforms) == 0)
	codeForm := recovery || f.Provider != 8
	ui.Column(c).Gap(16).Children(func() {
		if codeForm {
			if !recovery && len(codes) > 1 {
				// The control writes the choice when clicked, between frames, so
				// it needs a field; a change since the last frame is the user's.
				labels := make([]string, len(codes))
				current := 0
				for i, p := range codes {
					labels[i] = providers[p]
					if p == f.Provider {
						current = i
					}
				}
				if f.method != f.shownMethod && f.method >= 0 && f.method < len(codes) && !f.Busy {
					f.Provider, current = codes[f.method], f.method
					f.Token, f.Status = "", ""
				}
				f.method, f.shownMethod = current, current
				kit.Segmented(c.Key("mfa-method"), &f.method, labels...).Disabled(f.Busy)
			}
			label := providers[f.Provider]
			if !recovery && len(codes) > 1 {
				label = "" // the switch above already names the method
			}
			authCodeField(c, f, label, opts, recovery)
			if !f.DisableRemember && !recovery {
				ui.Column(c).Gap(4).Children(func() {
					kit.Checkbox(c, &f.remember, i18n.T("account.mfa.remember_device"), f.Busy)
					if f.remember {
						ui.Text(c, i18n.T("account.mfa.remember_device_hint")).FontSize(11.5).TextColor(kit.Muted).MaxLines(3)
					}
				})
			}
			label = opts.SubmitLabel
			if label == "" {
				label = i18n.T("account.mfa.continue_verification")
			}
			if kit.WidePrimary(c, label, f.Busy || f.Confirming || f.Token == "").Clicked() {
				f.Dispatch()
			}
		}
		if f.Status != "" && !f.Confirming {
			ui.Text(c, f.Status).FontSize(12).LineHeight(1.5).TextColor(kit.Muted).TextAlign(ui.Center).MaxLines(5).Role(ui.RoleStatus)
		}
		if len(platforms) > 0 && !recovery {
			if codeForm {
				authDivider(c, i18n.T("account.mfa.other_methods"))
			}
			for _, p := range platforms {
				symbol := "key"
				if p == 2 {
					symbol = "external"
				}
				if kit.Button(c, opts.Platform[p], symbol, kit.ButtonSecondary, f.Busy).Height(40).Radius(20).Clicked() {
					opts.OnPlatform(p)
				}
			}
		}
		ui.Row(c).Justify(ui.Center).Children(func() {
			switch {
			case !recovery:
				if kit.TextLink(c, i18n.T("account.mfa.use_recovery_code_link"), f.Busy).Clicked() {
					f.Provider, f.recovery = 8, true
					f.Token, f.Status, f.Confirming = "", "", false
				}
			case len(codes) > 0 || len(platforms) > 0:
				if kit.TextLink(c, i18n.T("account.mfa.back_to_methods"), f.Busy).Clicked() {
					f.recovery = false
					if len(codes) > 0 {
						f.Provider = codes[0]
					}
					f.Token, f.Status, f.Confirming = "", "", false
				}
			}
		})
	})
	if f.Confirming {
		kit.ConfirmDialog(c, "mfa-recovery", i18n.T("account.mfa.use_recovery_code"), i18n.T("account.mfa.confirm_recovery_code_impact"), i18n.T("account.mfa.confirm_disable_all_login"), i18n.T("common.cancel"), f.Busy,
			f.Dispatch, func() {
				if !f.Busy {
					f.Confirming = false
					f.Status = ""
				}
			})
	}
}

func authCodeField(c *ui.Context, f *AuthForm, label string, opts AuthOptions, recovery bool) {
	placeholder := i18n.T("login.mfa.code_placeholder")
	switch {
	case recovery:
		label, placeholder = i18n.T("account.mfa.recovery_code"), i18n.T("account.mfa.recovery_code_placeholder")
	case f.Provider == 3:
		placeholder = i18n.T("account.mfa.yubikey_placeholder")
	}
	ui.Column(c).Gap(6).Children(func() {
		send := !recovery && f.Provider == 1 && opts.SendEmail != nil
		if label != "" || send {
			ui.Row(c).AlignItems(ui.Center).Height(22).Children(func() {
				ui.Text(c, label).FontSize(12).FontWeight(600).Grow(1).MinWidth(0).SingleLine()
				if send {
					if kit.TextLink(c, i18n.T("account.mfa.send_email_code"), f.Busy).Height(22).Padding(0, 6).Clicked() {
						opts.SendEmail()
					}
				}
			})
		}
		// Keyed by method so switching clears focus state and refocuses.
		field := kit.FormInput(ui.TextInput(c.Key(f.Provider), &f.Token).Password().Placeholder(placeholder)).
			Disabled(f.Busy).AutoFocus()
		if field.Submitted() {
			f.Dispatch()
		}
	})
	if recovery {
		kit.Notice(c, kit.ToneWarning, i18n.T("account.mfa.confirm_recovery_code_impact"))
	}
}

func authDivider(c *ui.Context, label string) {
	ui.Row(c).Gap(10).AlignItems(ui.Center).Margin(4, 0, 0, 0).Children(func() {
		ui.Box(c).Height(1).Grow(1).Background(ui.RGBA(38, 30, 62, .12))
		ui.Text(c, label).FontSize(12).TextColor(kit.Muted).SingleLine()
		ui.Box(c).Height(1).Grow(1).Background(ui.RGBA(38, 30, 62, .12))
	})
}
