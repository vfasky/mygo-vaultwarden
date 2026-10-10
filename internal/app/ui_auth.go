// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

func (a *app) connectedServer() string {
	if a.snapshot != nil && a.snapshot.Scope != nil {
		return websiteHost(a.snapshot.Scope.Server)
	}
	return i18n.T("本机密码库")
}

// Authentication replaces the whole vault view: locked metadata must never be
// visible behind an overlay or in the sidebar while authentication is pending.
func (a *app) authentication(c *ui.Context) {
	login := a.showLogin || a.snapshot == nil || !a.snapshot.Available
	page, title, subtitle := "unlock", i18n.T("密码库已锁定"), a.connectedServer()
	if login {
		page, title, subtitle = "login", i18n.T("登录服务器"), i18n.T("连接你的 Vaultwarden 密码库")
		if a.showVerification {
			page, title, subtitle = "verification", i18n.T("两步验证"), i18n.T("选择此服务器提供的验证方式")
		}
	}
	if a.targetRecovery != nil {
		page, title, subtitle = "target-recovery", i18n.T("恢复目标账号"), i18n.T("全新认证、逐项核验与专用发布")
	}
	width, _ := c.Size()
	ui.Column(c.Key("auth-"+page)).Fill().TextColor(kit.Ink).
		Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
		ui.Box(c).Height(max(c.TitleBar().Height, 52)).Shrink(0).DragWindow()
		ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).MinHeight(max(float32(0), authContentHeight(c))).Padding(24, 24, 60, 24).
				Justify(ui.Center).AlignItems(ui.Center).Children(func() {
				ui.Column(c).Width(min(float32(360), max(float32(0), width-48))).Gap(28).Children(func() {
					ui.Column(c).AlignItems(ui.Center).Gap(12).Children(func() {
						if kit.AppLogo != nil {
							ui.Image(c, kit.AppLogo).Size(80, 80).Shrink(0)
						}
						ui.Text(c, title).FontSize(25).FontWeight(650).TextAlign(ui.Center)
						ui.Text(c, subtitle).FontSize(13).TextColor(kit.Muted).TextAlign(ui.Center).MaxLines(2)
					})
					if a.snapshot != nil && a.snapshot.AccountSwitchPending {
						ui.Text(c, i18n.T("本机账号替换已写入或回执未知。原账号加密副本与密钥在确认前保留，不会盲重试或回滚新状态。")).MaxLines(5)
						if a.switchReceipt == nil {
							if authPrimary(c, i18n.T("系统认证检查账号切换"), a.pending != 0).Clicked() {
								a.runStorage("inspectAccountSwitch")
							}
						} else {
							binding := a.switchReceipt.Binding
							ui.Text(c, i18n.Tf("原账号：%s / %s\n新账号：%s / %s", binding.Source.Server, binding.Source.Account, binding.Target.Server, binding.Target.Account)).MaxLines(6)
							if authPrimary(c, i18n.T("确认采用新账号并退休旧缓存密钥"), a.pending != 0).Clicked() {
								a.runStorage("confirmAccountSwitch")
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
						if authLink(c, i18n.T("结束设备登录"), false).Clicked() {
							a.runStorage("lock")
						}
					} else if a.recoveryForm != nil {
						if a.mfaLogin != nil {
							a.mfaLoginView(c)
						} else {
							a.accountRecoveryView(c)
						}
					} else if a.snapshot != nil && a.snapshot.RecoveryPending {
						ui.Text(c, i18n.T("此账号有未完成的安全变更恢复记录，旧库与自动填充已暂停。普通登录、同步和退出不能清除此记录。")).MaxLines(5)
						if authPrimary(c, i18n.T("进入账号恢复"), a.pending != 0).Clicked() {
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
					if a.targetRecovery == nil && (a.snapshot == nil || !a.snapshot.AccountSwitchPending) {
						if authLink(c, i18n.T("目标本人登录并核验跨账号恢复"), a.pending != 0).Clicked() {
							a.openTargetRecovery()
						}
					}
				})
			})
		})
	})
}

func authContentHeight(c *ui.Context) float32 {
	_, height := c.Size()
	return height - max(c.TitleBar().Height, 52)
}

// authPrimary spans the form width so it lines up with the inputs above it.
func authPrimary(c *ui.Context, label string, disabled bool) ui.Element {
	button := ui.PrimaryButton(c, "").Label(label).Height(40).Margin(8, 0, 0, 0).Padding(0, 16).Gap(6).
		Radius(20).Border(0, ui.Transparent).Shadow(0, 4, 12, 0, ui.RGBA(41, 41, 47, .18)).
		Justify(ui.Center).AlignItems(ui.Center).Disabled(disabled).Children(func() {
		ui.Text(c, label).FontSize(14).FontWeight(600)
		if !disabled {
			kit.Icon(c, "chevron", 15)
		}
	})
	return button
}

func authLink(c *ui.Context, label string, disabled bool) ui.Element {
	return ui.Button(c, label).Height(30).FontSize(12).Padding(0, 12).Radius(15).
		Border(0, ui.Transparent).Background(ui.Transparent).TextColor(kit.Purple).Disabled(disabled)
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
	if a.accountForm != nil && a.accountForm.Mode == "register" {
		account.FormView(c, a.accountForm)
		if authLink(c, i18n.T("返回登录"), false).Clicked() {
			a.advanceEpoch()
		}
		return
	}
	busy := a.pending != 0
	ready := !busy && a.snapshot != nil && a.deviceID != ""
	submitted := false
	ui.Column(c.Key(a.secretInputVersion)).Gap(16).Children(func() {
		ui.Field(c, i18n.T("服务器地址"), func() {
			field := ui.TextInput(c, &a.serverURL).Placeholder("https://vault.example.com").
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(busy)
			if a.serverURL == "" {
				field.AutoFocus()
			}
			submitted = field.Submitted()
		})
		ui.Field(c, i18n.T("邮箱"), func() {
			field := ui.TextInput(c, &a.email).Placeholder("you@example.com").
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(busy)
			if a.serverURL != "" && a.email == "" {
				field.AutoFocus()
			}
			submitted = submitted || field.Submitted()
		})
		ui.Field(c, i18n.T("主密码"), func() {
			field := ui.TextInput(c, &a.masterPassword).Password().Placeholder(i18n.T("输入主密码")).
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(busy)
			if a.serverURL != "" && a.email != "" {
				field.AutoFocus()
			}
			submitted = submitted || field.Submitted()
		})
		if a.snapshot != nil && a.snapshot.Available {
			ui.Text(c, i18n.T("继续登录将切换本机账号，并替换已有离线快照。")).FontSize(12).LineHeight(1.5).TextColor(kit.Muted).TextAlign(ui.Center)
		}
		label := i18n.T("登录并同步")
		if busy {
			label = i18n.T("处理中…")
		}
		clicked := authPrimary(c, label, !ready).Clicked()
		if ready && (clicked || submitted) {
			a.loginSSO = false
			a.syncVault(true)
		}
		a.authStatus(c)
		ui.Row(c).Justify(ui.Center).Children(func() {
			if authLink(c, i18n.T("设备"), !ready).Tooltip(i18n.T("通过已登记的另一台设备批准登录")).Clicked() {
				a.deviceLoginSetup = true
			}
			if authLink(c, i18n.T("注册 / 密码提示"), !ready).Clicked() {
				a.openRegistration()
			}
			if authLink(c, i18n.T("SSO 登录"), !ready).Tooltip(i18n.T("SSO 认证后仍需主密码解锁；新建 SSO 账号和 Key Connector 暂不支持。")).Clicked() {
				a.loginSSO = true
				a.syncVault(true)
			}
			switch {
			case a.cancel != nil:
				if authLink(c, i18n.T("取消登录"), false).Clicked() {
					a.runStorage("lock")
				}
			case a.unlocked():
				if authLink(c, i18n.T("返回密码库"), busy).Clicked() {
					a.resetLoginForm()
					a.showLogin = false
					a.status = ""
				}
			case a.snapshot != nil && a.snapshot.Available:
				if authLink(c, i18n.T("返回解锁"), busy).Clicked() {
					a.resetLoginForm()
					a.showLogin = false
					a.status = ""
				}
			case a.snapshot == nil && !busy:
				if authLink(c, i18n.T("重试连接"), false).Clicked() {
					a.runStorage("settings")
				}
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
		ui.Field(c, i18n.T("验证码"), func() {
			field := ui.TextInput(c, &a.verificationCode).Password().Placeholder(i18n.T("6 位数字验证码")).
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(!ready).AutoFocus()
			submitted = field.Submitted()
		})
		label := i18n.T("验证并登录")
		if !ready {
			label = i18n.T("正在验证…")
		}
		clicked := authPrimary(c, label, !ready).Clicked()
		if ready && (clicked || submitted) {
			a.submitLoginCode()
		}
		a.authStatus(c)
		ui.Row(c).Justify(ui.Center).Children(func() {
			if authLink(c, i18n.T("取消登录"), false).Clicked() {
				a.runStorage("lock")
			}
		})
	})
}

func (a *app) vaultUnlock(c *ui.Context) {
	busy := a.pending != 0
	passwordReady := a.snapshot != nil && a.snapshot.PasswordUnlock != nil
	ui.Column(c.Key(a.secretInputVersion)).Gap(16).Children(func() {
		submitted := false
		ui.Field(c, i18n.T("主密码"), func() {
			field := ui.TextInput(c, &a.masterPassword).Password().Placeholder(i18n.T("输入主密码")).
				Height(38).Padding(0, 14).Radius(19).Background(kit.White).Disabled(busy || !passwordReady).AutoFocus()
			submitted = field.Submitted()
		})
		label := i18n.T("解锁密码库")
		if busy {
			label = i18n.T("处理中…")
		}
		clicked := authPrimary(c, label, busy || !passwordReady).Clicked()
		if !busy && passwordReady && (clicked || submitted) {
			a.unlockWithPassword()
		}
		if ui.Button(c, i18n.T("使用 Touch ID 解锁")).Height(40).Radius(20).Background(kit.White).
			Disabled(a.pending != 0).Clicked() {
			a.runStorage("list")
		}
		ui.Text(c, i18n.T("Touch ID 不可用时，可按系统提示使用 Mac 登录密码。")).FontSize(12).TextColor(kit.Muted).TextAlign(ui.Center)
		if authLink(c, i18n.T("通过另一台设备登录"), busy).Clicked() {
			a.openUnlockLogin()
			a.deviceLoginSetup = true
		}
		if !passwordReady {
			ui.Text(c, i18n.T("此密码库需重新登录一次，以启用主密码解锁。")).FontSize(12).TextColor(kit.Muted).TextAlign(ui.Center)
			ui.Row(c).Justify(ui.Center).Children(func() {
				if authLink(c, i18n.T("重新登录"), busy).Clicked() {
					a.openUnlockLogin()
				}
			})
		}
		a.authStatus(c)
		ui.Row(c).Justify(ui.Center).Children(func() {
			if authLink(c, i18n.T("使用其他账号"), busy).Clicked() {
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
