// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

func (a *app) connectedServer() string {
	if a.snapshot != nil && a.snapshot.Scope != nil {
		return websiteHost(a.snapshot.Scope.Server)
	}
	return i18n.T("login.local_vault")
}

// Authentication replaces the whole vault view: locked metadata must never be
// visible behind an overlay or in the sidebar while authentication is pending.
func (a *app) authentication(c *ui.Context) {
	login := a.showLogin || a.snapshot == nil || !a.snapshot.Available
	page, title, subtitle := "unlock", i18n.T("login.unlock.title"), a.connectedServer()
	if login {
		page, title, subtitle = "login", i18n.T("login.title"), i18n.T("login.description")
		if a.showVerification {
			page, title, subtitle = "verification", i18n.T("login.mfa.title"), i18n.T("login.mfa.description")
		} else if a.accountForm != nil && a.accountForm.SignedOut() {
			title, subtitle = a.accountForm.Heading()
			page = "account-" + a.accountForm.Mode
		}
	}
	if a.targetRecovery != nil {
		page, title, subtitle = "target-recovery", i18n.T("login.recovery.title"), i18n.T("login.recovery.description")
	}
	width, _ := c.Size()
	ui.Column(c.Key("auth-"+page)).Fill().TextColor(kit.Ink).
		Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
		ui.Box(c).Height(max(c.TitleBar().Height, 52)).Shrink(0).DragWindow()
		ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
			// The form stays centered in the window; the footer sits at its bottom.
			ui.Column(c).MinHeight(max(float32(0), authContentHeight(c))).Padding(24, 24, 14, 24).
				AlignItems(ui.Center).Children(func() {
				ui.Box(c).Grow(1)
				ui.Column(c).Width(min(float32(360), max(float32(0), width-48))).Gap(28).Children(func() {
					ui.Column(c).AlignItems(ui.Center).Gap(12).Children(func() {
						if kit.AppLogo != nil {
							ui.Image(c, kit.AppLogo).Size(80, 80).Shrink(0)
						}
						ui.Text(c, title).FontSize(25).FontWeight(650).TextAlign(ui.Center)
						ui.Text(c, subtitle).FontSize(13).TextColor(kit.Muted).TextAlign(ui.Center).MaxLines(2)
					})
					if a.snapshot != nil && a.snapshot.AccountSwitchPending {
						ui.Text(c, i18n.T("login.account_switch.pending_hint")).MaxLines(5)
						if a.switchReceipt == nil {
							if kit.WidePrimary(c, i18n.T("login.account_switch.inspect"), a.pending != 0).Clicked() {
								a.runStorage(localstore.OperationInspectAccountSwitch)
							}
						} else {
							binding := a.switchReceipt.Binding
							ui.Text(c, i18n.Tf("login.account_switch.summary", binding.Source.Server, binding.Source.Account, binding.Target.Server, binding.Target.Account)).MaxLines(6)
							if kit.WidePrimary(c, i18n.T("login.account_switch.confirm_replace_account"), a.pending != 0).Clicked() {
								a.runStorage(localstore.OperationConfirmAccountSwitch)
							}
						}
						a.authStatus(c)
					} else if a.targetRecovery != nil {
						if a.mfaLogin != nil {
							a.mfaLoginView(c)
						} else {
							a.targetRecovery.View(c)
						}
					} else if a.deviceLoginPanel != nil {
						a.deviceLoginPanel.View(c)
						if kit.TextLink(c, i18n.T("login.device.end"), false).Clicked() {
							a.runStorage(localstore.OperationLock)
						}
					} else if a.recoveryForm != nil {
						if a.mfaLogin != nil {
							a.mfaLoginView(c)
						} else {
							a.accountRecoveryView(c)
						}
					} else if a.snapshot != nil && a.snapshot.RecoveryPending {
						ui.Text(c, i18n.T("login.recovery.pending_hint")).MaxLines(5)
						if kit.WidePrimary(c, i18n.T("login.recovery.open"), a.pending != 0).Clicked() {
							a.openAccountRecovery()
						}
						a.authStatus(c)
					} else if login && a.showVerification {
						a.twoFactorLogin(c)
					} else if login {
						a.serverLogin(c)
					} else {
						a.vaultUnlock(c)
					}
				})
				ui.Box(c).Grow(1).MinHeight(32)
				a.authFooter(c)
			})
		})
	})
}

// authFooter holds what applies to every authentication page rather than
// to the form: the language and the rarely used cross-account recovery.
func (a *app) authFooter(c *ui.Context) {
	ui.Row(c).Justify(ui.Center).AlignItems(ui.Center).Wrap().Children(func() {
		languageMenu(c)
		if a.targetRecovery == nil && (a.snapshot == nil || !a.snapshot.AccountSwitchPending) {
			ui.Text(c, "·").FontSize(12).TextColor(kit.Muted)
			if kit.TextLink(c, i18n.T("login.recovery.verify_as_owner"), a.pending != 0).TextColor(kit.Muted).Clicked() {
				a.openTargetRecovery()
			}
		}
	})
}

func authContentHeight(c *ui.Context) float32 {
	_, height := c.Size()
	return height - max(c.TitleBar().Height, 52)
}

func (a *app) authStatus(c *ui.Context) {
	if warning := a.mfaWarnings.warning(a.serverURL, a.email); warning != "" {
		ui.Text(c, warning).MaxLines(5)
	}
	if a.status != "" {
		ui.Text(c, a.status).FontSize(12).LineHeight(1.5).TextColor(kit.Muted).
			TextAlign(ui.Center).Role(ui.RoleStatus)
	}
}

func (a *app) serverLogin(c *ui.Context) {
	if a.deviceLoginSetup {
		a.deviceLoginSetupView(c)
		return
	}
	if a.accountForm != nil && a.accountForm.SignedOut() {
		account.SignedOutView(c, a.accountForm)
		ui.Row(c).Justify(ui.Center).Children(func() {
			if kit.TextLink(c, i18n.T("login.back"), false).Clicked() {
				a.advanceEpoch()
			}
		})
		return
	}
	busy := a.pending != 0
	ready := !busy && a.snapshot != nil && a.deviceID != ""
	submitted := false
	ui.Column(c.Key(a.secretInputVersion)).Gap(16).Children(func() {
		ui.Field(c, i18n.T("common.server_url"), func() {
			field := ui.TextInput(c, &a.serverURL).Placeholder("https://vault.example.com").
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(busy)
			if a.serverURL == "" {
				field.AutoFocus()
			}
			submitted = field.Submitted()
		})
		ui.Field(c, i18n.T("common.email"), func() {
			field := ui.TextInput(c, &a.email).Placeholder("you@example.com").
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(busy)
			if a.serverURL != "" && a.email == "" {
				field.AutoFocus()
			}
			submitted = submitted || field.Submitted()
		})
		ui.Field(c, i18n.T("login.master_password"), func() {
			field := ui.TextInput(c, &a.masterPassword).Password().Placeholder(i18n.T("login.master_password_placeholder")).
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(busy)
			if a.serverURL != "" && a.email != "" {
				field.AutoFocus()
			}
			submitted = submitted || field.Submitted()
		})
		// As on most login pages, the hint sits right under the password.
		ui.Row(c).Justify(ui.End).Margin(-8, 0, 0, 0).Children(func() {
			if kit.TextLink(c, i18n.T("login.forgot_password"), !ready).Padding(0, 4).Clicked() {
				a.openPasswordHint()
			}
		})
		if a.snapshot != nil && a.snapshot.Available {
			ui.Text(c, i18n.T("login.account_switch.login_hint")).FontSize(12).LineHeight(1.5).TextColor(kit.Muted).TextAlign(ui.Center)
		}
		label := i18n.T("login.submit")
		if busy {
			label = i18n.T("common.status_processing")
		}
		clicked := kit.WidePrimary(c, label, !ready).Clicked()
		if ready && (clicked || submitted) {
			a.loginSSO = false
			a.syncVault(true)
		}
		a.authStatus(c)
		ui.Row(c).Justify(ui.Center).Children(func() {
			if kit.TextLink(c, i18n.T("login.device.link"), !ready).Tooltip(i18n.T("login.device.hint")).Clicked() {
				a.deviceLoginSetup = true
			}
			if kit.TextLink(c, i18n.T("login.sso.submit"), !ready).Tooltip(i18n.T("login.sso.hint")).Clicked() {
				a.loginSSO = true
				a.syncVault(true)
			}
			switch {
			case a.cancel != nil:
				if kit.TextLink(c, i18n.T("login.cancel"), false).Clicked() {
					a.runStorage(localstore.OperationLock)
				}
			case a.unlocked():
				if kit.TextLink(c, i18n.T("login.back_to_vault"), busy).Clicked() {
					a.resetLoginForm()
					a.showLogin = false
					a.status = ""
				}
			case a.snapshot != nil && a.snapshot.Available:
				if kit.TextLink(c, i18n.T("login.unlock.back"), busy).Clicked() {
					a.resetLoginForm()
					a.showLogin = false
					a.status = ""
				}
			case a.snapshot == nil && !busy:
				if kit.TextLink(c, i18n.T("login.retry_connection"), false).Clicked() {
					a.runStorage(localstore.OperationSettings)
				}
			}
		})
		ui.Row(c).Justify(ui.Center).AlignItems(ui.Center).Children(func() {
			ui.Text(c, i18n.T("login.no_account")).FontSize(12).TextColor(kit.Muted)
			if kit.TextLink(c, i18n.T("login.create_account"), !ready).Padding(0, 6).Clicked() {
				a.openRegistration()
			}
		})
	})
}

func (a *app) twoFactorLogin(c *ui.Context) {
	if a.mfaLogin != nil {
		a.mfaLoginView(c)
		return
	}
	ready := a.loginChallenge != nil && a.loginChallenge.epoch == a.epoch && a.loginChallenge.ctx.Err() == nil
	submitted := false
	ui.Column(c.Key(a.secretInputVersion)).Gap(16).Children(func() {
		ui.Text(c, a.email+" · "+websiteHost(a.serverURL)).FontSize(12).TextColor(kit.Muted).TextAlign(ui.Center).MaxLines(2)
		ui.Field(c, i18n.T("common.verification_code"), func() {
			field := ui.TextInput(c, &a.verificationCode).Password().Placeholder(i18n.T("login.mfa.code_placeholder")).
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(!ready).AutoFocus()
			submitted = field.Submitted()
		})
		label := i18n.T("login.mfa.submit")
		if !ready {
			label = i18n.T("login.mfa.status_verifying")
		}
		clicked := kit.WidePrimary(c, label, !ready).Clicked()
		if ready && (clicked || submitted) {
			a.submitLoginCode()
		}
		a.authStatus(c)
		ui.Row(c).Justify(ui.Center).Children(func() {
			if kit.TextLink(c, i18n.T("login.cancel"), false).Clicked() {
				a.runStorage(localstore.OperationLock)
			}
		})
	})
}

func (a *app) vaultUnlock(c *ui.Context) {
	busy := a.pending != 0
	passwordReady := a.snapshot != nil && a.snapshot.PasswordUnlock != nil
	ui.Column(c.Key(a.secretInputVersion)).Gap(16).Children(func() {
		submitted := false
		ui.Field(c, i18n.T("login.master_password"), func() {
			field := ui.TextInput(c, &a.masterPassword).Password().Placeholder(i18n.T("login.master_password_placeholder")).
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(busy || !passwordReady).AutoFocus()
			submitted = field.Submitted()
		})
		label := i18n.T("login.unlock.submit")
		if busy {
			label = i18n.T("common.status_processing")
		}
		clicked := kit.WidePrimary(c, label, busy || !passwordReady).Clicked()
		if !busy && passwordReady && (clicked || submitted) {
			a.unlockWithPassword()
		}
		// The hint explains the button, so it stays right beneath it.
		ui.Column(c).Gap(8).Children(func() {
			if ui.Button(c, i18n.T("login.unlock.touch_id")).Height(40).Radius(20).Background(kit.White).
				Disabled(a.pending != 0).Clicked() {
				a.runStorage(localstore.OperationList)
			}
			ui.Text(c, i18n.T("login.unlock.touch_id_hint")).FontSize(12).TextColor(kit.Muted).TextAlign(ui.Center)
		})
		if !passwordReady {
			ui.Text(c, i18n.T("login.unlock.login_required_hint")).FontSize(12).TextColor(kit.Muted).TextAlign(ui.Center)
		}
		a.authStatus(c)
		// Other ways in share one row, as on the login page.
		ui.Row(c).Justify(ui.Center).Wrap().Children(func() {
			if !passwordReady && kit.TextLink(c, i18n.T("login.log_in_again"), busy).Clicked() {
				a.openUnlockLogin()
			}
			if kit.TextLink(c, i18n.T("account.device_login.title"), busy).Clicked() {
				a.openUnlockLogin()
				a.deviceLoginSetup = true
			}
			if kit.TextLink(c, i18n.T("login.use_another_account"), busy).Clicked() {
				a.openUnlockLogin()
			}
		})
	})
}

func (a *app) openUnlockLogin() {
	// Populate the last server only on navigation, not while the user edits.
	if strings.TrimSpace(a.serverURL) == "" && a.snapshot != nil && a.snapshot.Scope != nil {
		a.serverURL = a.snapshot.Scope.Server
	}
	if strings.TrimSpace(a.email) == "" && a.snapshot != nil && a.snapshot.PasswordUnlock != nil {
		a.email = a.snapshot.PasswordUnlock.Email
	}
	a.resetLoginForm()
	a.showLogin = true
	a.status = ""
}
