// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"strconv"
	"sync"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Warnings contain no token or password, and remain bound to the original
// canonical server/email even when a later login switches account.
type mfaRecoveryWarnings struct {
	mu      sync.Mutex
	entries map[string]bool
}

func (w *mfaRecoveryWarnings) record(server, email string, confirmed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.entries == nil {
		w.entries = map[string]bool{}
	}
	key := server + "\n" + vaultwarden.NormalizeEmail(email)
	w.entries[key] = w.entries[key] || confirmed
}
func (w *mfaRecoveryWarnings) warning(server, email string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	confirmed, ok := w.entries[server+"\n"+vaultwarden.NormalizeEmail(email)]
	if !ok {
		return ""
	}
	if confirmed {
		return "此账号已关闭全部两步验证；请核验并重新设置。"
	}
	return "此账号可能已关闭全部两步验证；登录失败或取消不能证明未执行，请核验并重新设置。"
}

type controllerMFA struct {
	form              *account.AuthForm
	providers         map[int]string
	platformProviders map[int]string
	platform          func(int)
	sendEmail         func()
	cancel            context.CancelFunc
}

func (m *controllerMFA) Close() {
	if m != nil {
		m.cancel()
		m.form.Close()
	}
}

// The worker owns response bytes. UI only sends once and never waits for the
// platform or token exchange. Cancelling also clears a queued response.
func (a *app) requestMFA(ctx context.Context, server, email string, epoch uint64, ch vaultwarden.MFAChallenge, dispatch func(func()), platform func(context.Context, vaultwarden.MFAChallenge, int) (vaultwarden.MFAResponse, error)) (vaultwarden.MFAResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	replies := make(chan vaultwarden.MFAResponse)
	var once sync.Once
	deliver := func(r vaultwarden.MFAResponse) {
		accepted := false
		once.Do(func() {
			accepted = true
			go func() {
				select {
				case replies <- r:
				case <-ctx.Done():
					clear(r.Token)
				}
			}()
		})
		if !accepted {
			clear(r.Token)
		}
	}
	dispatch(func() {
		if a.epoch != epoch || !a.showLogin || ctx.Err() != nil {
			cancel()
			return
		}
		if a.mfaLogin != nil {
			a.mfaLogin.Close()
		}
		m := &controllerMFA{cancel: cancel, providers: map[int]string{}, platformProviders: map[int]string{}}
		m.form = account.NewAuthForm(vaultwarden.Scope{Server: server}, epoch, func(r account.AuthRequest) {
			defer r.Close()
			// Remember is optional and stays disabled until account/device-scoped
			// protected token storage is available.
			r.Response.Remember = false
			deliver(vaultwarden.MFAResponse{Provider: r.Response.Provider, Token: append([]byte(nil), r.Response.Token...), ConfirmRemoveAllMFA: r.Response.ConfirmRemoveAllMFA})
		})
		m.form.DisableRemember = true
		labels := map[int]string{0: "验证器验证码", 1: "邮件验证码", 2: "Duo 系统浏览器", 3: "YubiKey OTP", 7: "系统安全密钥"}
		for raw := range ch.Providers {
			id, err := strconv.Atoi(raw)
			if err != nil {
				continue
			}
			if id == 2 || id == 7 {
				if platform != nil {
					m.platformProviders[id] = labels[id]
				}
			} else if id == 0 || id == 1 || id == 3 {
				m.providers[id] = labels[id]
			}
		}
		m.form.Provider = 8
		for _, id := range []int{0, 1, 3} {
			if _, ok := m.providers[id]; ok {
				m.form.Provider = id
				break
			}
		}
		m.platform = func(id int) {
			if m.form.Busy || m.form.Closed {
				return
			}
			m.form.Busy = true
			go func() {
				r, err := platform(ctx, ch, id)
				if err != nil {
					clear(r.Token)
					dispatch(func() {
						if a.mfaLogin == m && ctx.Err() == nil {
							m.form.Busy = false
							m.form.Status = err.Error()
						}
					})
					return
				}
				deliver(r)
			}()
		}
		if ch.SendEmail != nil {
			m.sendEmail = func() {
				if m.form.Busy || m.form.Closed {
					return
				}
				m.form.Busy = true
				go func() {
					err := ch.SendEmail(ctx)
					dispatch(func() {
						if a.mfaLogin == m && ctx.Err() == nil {
							m.form.Busy = false
							if err != nil {
								m.form.Status = err.Error()
							} else {
								m.form.Status = "邮件验证码已请求。"
							}
						}
					})
				}()
			}
		}
		a.clearLoginInputs()
		a.mfaLogin = m
		a.showVerification = true
	})
	select {
	case r := <-replies:
		if ctx.Err() != nil {
			clear(r.Token)
			return vaultwarden.MFAResponse{}, vaultwarden.ErrCancelled
		}
		// Conservatively retain the side-effect warning at delivery. LoginMFA's
		// zero error result cannot tell whether provider8 already removed MFA.
		if r.Provider == 8 && r.ConfirmRemoveAllMFA {
			a.mfaWarnings.record(server, email, false)
		}
		return r, nil
	case <-ctx.Done():
		return vaultwarden.MFAResponse{}, vaultwarden.ErrCancelled
	}
}
func (a *app) mfaLoginView(c *ui.Context) {
	m := a.mfaLogin
	if m == nil {
		return
	}
	account.AuthFormView(c, m.form, m.providers)
	if m.form.Closed {
		m.cancel()
		return
	}
	for _, id := range []int{2, 7} {
		if label, ok := m.platformProviders[id]; ok {
			if ui.Button(c, label).Disabled(m.form.Busy).Clicked() {
				m.platform(id)
			}
		}
	}
	if m.sendEmail != nil && ui.Button(c, "发送邮件验证码").Disabled(m.form.Busy).Clicked() {
		m.sendEmail()
	}
	ui.Text(c, "本次登录不保存两步验证设备令牌。")
	if ui.Button(c, "取消登录").Clicked() {
		a.runStorage("lock")
	}
}
