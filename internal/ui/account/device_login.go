// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"errors"
	"strconv"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// DeviceLoginHost is injected by integration. Dispatch uses window.Update; Check
// is worker-safe, checks scope/epoch and rejects lock/account changes. Accept
// runs on UI thread, rechecks the lease and takes ownership of a live flow only
// on success. Retain that flow and Close it on lock/logout/session replacement.
// Publish no saved session before explicit BindPassword + fresh Sync. Platform
// uses the existing Duo/WebAuthn native bridge and verifies its scoped response.
type DeviceLoginHost struct {
	AcceptingMessage string
	Dispatch         func(func())
	Check            func(vaultwarden.Scope, uint64) error
	Accept           func(*vaultwarden.DeviceLogin, vaultwarden.DeviceLoginResult) error
	Platform         func(context.Context, vaultwarden.MFAChallenge, int) (vaultwarden.MFAResponse, error)
}
type DeviceLoginPanel struct {
	client                 *vaultwarden.Client
	scope                  vaultwarden.Scope
	email                  string
	epoch, sequence        uint64
	host                   DeviceLoginHost
	cancel                 context.CancelFunc
	flow                   *vaultwarden.DeviceLogin
	busy, closed, accepted bool
	status, fingerprint    string
	auth                   *AuthForm
	providers              map[int]string
	platformProviders      map[int]string
	platform               func(int)
	recovery               []vaultwarden.DeviceLoginRecovery
}

func NewDeviceLoginPanel(client *vaultwarden.Client, email string, scope vaultwarden.Scope, epoch uint64, host DeviceLoginHost) *DeviceLoginPanel {
	p := &DeviceLoginPanel{client: client, email: email, scope: scope, epoch: epoch, host: host, status: i18n.T("account.device_login.registered_device_hint")}
	if client == nil || host.Check == nil || host.Dispatch == nil || host.Accept == nil {
		p.closed = true
	}
	return p
}

// RecoveryOutcomes returns credential-free account/attempt records, including
// late completions after cancellation or Close. Read on the UI thread.
func (p *DeviceLoginPanel) RecoveryOutcomes() []vaultwarden.DeviceLoginRecovery {
	return append([]vaultwarden.DeviceLoginRecovery(nil), p.recovery...)
}
func (p *DeviceLoginPanel) retainRecovery(r vaultwarden.DeviceLoginRecovery) {
	if r.State == vaultwarden.DeviceLoginRecoveryNotSubmitted || r.Scope != p.scope || r.Epoch != p.epoch || r.RequestID == "" {
		return
	}
	for i, old := range p.recovery {
		if old.RequestID == r.RequestID {
			if r.State > old.State {
				p.recovery[i] = r
			}
			return
		}
	}
	p.recovery = append(p.recovery, r)
}
func deviceLoginRecoveryWarning(r vaultwarden.DeviceLoginRecovery) string {
	if r.State == vaultwarden.DeviceLoginRecoveryConfirmed {
		return i18n.T("account.mfa.status_all_disabled")
	}
	return i18n.T("account.mfa.status_all_maybe_disabled")
}
func (p *DeviceLoginPanel) cancelAttempt() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	if p.flow != nil {
		flow := p.flow
		p.flow = nil
		flow.Cancel()
		go func() {
			flow.Close()
			recovery := flow.Recovery()
			p.host.Dispatch(func() { p.retainRecovery(recovery) })
		}()
	}
	if p.auth != nil {
		p.auth.Close()
		p.auth = nil
	}
	p.platform = nil
	p.fingerprint = ""
	p.sequence++
	p.busy = false
}
func (p *DeviceLoginPanel) Close() {
	if !p.accepted {
		p.cancelAttempt()
	}
	p.closed = true
}
func (p *DeviceLoginPanel) Cancel() {
	if p.closed || p.accepted {
		return
	}
	p.cancelAttempt()
	p.status = i18n.T("account.device_login.status_cancelled")
}
func (p *DeviceLoginPanel) current(seq uint64) bool {
	return !p.closed && p.sequence == seq && p.host.Check(p.scope, p.epoch) == nil
}
func (p *DeviceLoginPanel) Start() {
	if p.closed || p.busy || p.accepted {
		return
	}
	if p.host.Check(p.scope, p.epoch) != nil {
		p.Close()
		return
	}
	p.cancelAttempt()
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.busy = true
	seq := p.sequence
	p.status = i18n.T("account.device_login.status_requesting")
	go func() {
		flow, err := p.client.BeginDeviceLogin(ctx, p.email, p.scope, p.epoch, p.host.Check)
		if err != nil {
			p.host.Dispatch(func() { p.finish(seq, nil, vaultwarden.DeviceLoginResult{}, err) })
			return
		}
		p.host.Dispatch(func() {
			if !p.current(seq) {
				flow.Cancel()
				go flow.Close()
				return
			}
			p.flow = flow
			p.fingerprint = authPublicFingerprint(flow.Metadata().PublicKey)
			p.status = i18n.T("account.device_login.status_awaiting_approval")
		})
		result, err := flow.Run(func(callCtx context.Context, ch vaultwarden.MFAChallenge) (vaultwarden.MFAResponse, error) {
			return p.prompt(callCtx, seq, ch)
		})
		p.host.Dispatch(func() { p.finish(seq, flow, result, err) })
	}()
}
func (p *DeviceLoginPanel) finish(seq uint64, flow *vaultwarden.DeviceLogin, result vaultwarden.DeviceLoginResult, err error) {
	// Preserve only non-secret metadata on this original account panel, even
	// when the attempt/epoch is no longer eligible to install a session.
	p.retainRecovery(result.Recovery)
	if !p.current(seq) {
		if flow != nil {
			flow.Cancel()
			go flow.Close()
		}
		return
	}
	if p.auth != nil {
		p.auth.Close()
		p.auth = nil
	}
	p.platform = nil
	p.busy = false
	if err != nil {
		p.status = i18n.T("account.device_login.err_login_failed")
		switch {
		case errors.Is(err, vaultwarden.ErrDeviceUnknown):
			p.status = i18n.T("account.device_login.err_unknown_device")
		case errors.Is(err, vaultwarden.ErrDeviceRejected):
			p.status = i18n.T("account.device_login.err_approval_rejected")
		case errors.Is(err, vaultwarden.ErrExpired), errors.Is(err, vaultwarden.ErrCancelled):
			p.status = i18n.T("account.device_login.status_expired")
		}
		var uncertain *vaultwarden.MutationUncertainError
		if errors.As(err, &uncertain) {
			p.status = i18n.T("account.device_login.status_exchange_unknown")
		}
		if flow != nil {
			flow.Cancel()
			go flow.Close()
		}
		p.flow = nil
		return
	}
	if err = p.host.Accept(flow, result); err != nil {
		flow.Cancel()
		go flow.Close()
		p.flow = nil
		p.status = i18n.T("account.device_login.status_result_discarded")
		return
	}
	// Ownership including cancellation moves to integration; closing this panel
	// must not revoke the adopted session. Integration closes the returned flow.
	p.accepted = true
	p.flow = nil
	p.cancel = nil
	p.status = i18n.T("account.device_login.status_logged_in")
	if p.host.AcceptingMessage != "" {
		p.status = p.host.AcceptingMessage
	}
}
func (p *DeviceLoginPanel) prompt(ctx context.Context, seq uint64, ch vaultwarden.MFAChallenge) (vaultwarden.MFAResponse, error) {
	replies := make(chan vaultwarden.MFAResponse)
	deliver := func(response vaultwarden.MFAResponse) {
		go func() {
			select {
			case replies <- response:
			case <-ctx.Done():
				clear(response.Token)
			}
		}()
	}
	p.host.Dispatch(func() {
		if !p.current(seq) || ctx.Err() != nil {
			return
		}
		if p.auth != nil {
			p.auth.Close()
		}
		p.providers = map[int]string{}
		p.platformProviders = map[int]string{}
		labels := map[int]string{0: i18n.T("account.mfa.authenticator_code"), 1: i18n.T("account.mfa.email_code"), 2: i18n.T("account.mfa.duo_browser"), 3: "YubiKey OTP", 7: i18n.T("account.mfa.system_security_key")}
		for raw := range ch.Providers {
			provider, e := strconv.Atoi(raw)
			if e != nil {
				continue
			}
			if provider == 2 || provider == 7 {
				if p.host.Platform != nil {
					p.platformProviders[provider] = labels[provider]
				}
			} else if provider == 0 || provider == 1 || provider == 3 {
				p.providers[provider] = labels[provider]
			}
		}
		p.auth = NewAuthForm(p.scope, p.epoch, func(r AuthRequest) {
			defer r.Close()
			deliver(vaultwarden.MFAResponse{Provider: r.Response.Provider, Token: append([]byte(nil), r.Response.Token...), Remember: r.Response.Remember, ConfirmRemoveAllMFA: r.Response.ConfirmRemoveAllMFA})
		})
		for _, id := range []int{0, 1, 3} {
			if _, ok := p.providers[id]; ok {
				p.auth.Provider = id
				break
			}
		}
		p.platform = func(provider int) {
			if p.auth.Busy {
				return
			}
			p.auth.Busy = true
			go func() {
				response, e := p.host.Platform(ctx, ch, provider)
				if e != nil {
					clear(response.Token)
					response = vaultwarden.MFAResponse{}
				}
				deliver(response)
			}()
		}
		p.status = i18n.T("account.device_login.status_mfa_required")
	})
	select {
	case response := <-replies:
		return response, nil
	case <-ctx.Done():
		return vaultwarden.MFAResponse{}, vaultwarden.ErrCancelled
	}
}
func (p *DeviceLoginPanel) View(c *ui.Context) {
	ui.Scroll(c).Children(func() {
		ui.Column(c).Padding(18).Gap(10).Children(func() {
			ui.Text(c, i18n.T("account.device_login.title")).FontSize(23)
			ui.Text(c, p.email)
			ui.Text(c, i18n.T("account.device_login.fingerprint_hint")).MaxLines(6)
			for _, r := range p.recovery {
				ui.Text(c, r.Email+"（"+r.Scope.Server+"）："+deviceLoginRecoveryWarning(r)).MaxLines(6)
			}
			if p.closed {
				ui.Text(c, i18n.T("account.device.status_panel_closed"))
				return
			}
			if p.fingerprint != "" {
				ui.Text(c, p.fingerprint).MaxLines(4)
			}
			ui.Text(c, p.status).MaxLines(6)
			ui.Text(c, i18n.T("account.device_login.unbound_session_hint")).MaxLines(6)
			if p.auth != nil {
				AuthFormView(c, p.auth, p.providers, AuthOptions{Platform: p.platformProviders, OnPlatform: p.platform})
				if p.auth.Closed {
					p.Cancel()
					return
				}
			}
			if ui.Button(c, i18n.T("account.device_login.request_new_approval")).Disabled(p.busy || p.accepted).Clicked() {
				p.Start()
			}
			if ui.Button(c, i18n.T("account.device_login.cancel_request")).Disabled(!p.busy || p.accepted).Clicked() {
				p.Cancel()
			}
		})
	})
}
