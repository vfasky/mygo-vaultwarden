// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"errors"
	"strconv"

	"github.com/egoist/mygo/ui"
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
	auth                   *authForm
	providers              map[int]string
	platformProviders      map[int]string
	platform               func(int)
	recovery               []vaultwarden.DeviceLoginRecovery
}

func NewDeviceLoginPanel(client *vaultwarden.Client, email string, scope vaultwarden.Scope, epoch uint64, host DeviceLoginHost) *DeviceLoginPanel {
	p := &DeviceLoginPanel{client: client, email: email, scope: scope, epoch: epoch, host: host, status: "仅支持此账号以前登录过的设备。需在另一台已解锁设备批准。"}
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
		return "已关闭全部两步验证，需核验并重新设置。"
	}
	return "可能已关闭全部两步验证，需核验并重新设置。"
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
	p.status = "已取消本机等待；服务器请求可能保留到五分钟过期，迟到批准不会在本机登录。"
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
	p.status = "正在核对此设备并发起审批请求…"
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
			p.status = "等待另一台设备核对完整公钥指纹并批准；断线时仍会轮询。"
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
		p.status = "登录失败；请核对账号与设备，再手动发起新请求。"
		switch {
		case errors.Is(err, vaultwarden.ErrDeviceUnknown):
			p.status = "服务器不认识此账号的当前设备。请先使用主密码登录登记设备。"
		case errors.Is(err, vaultwarden.ErrDeviceRejected):
			p.status = "审批请求已拒绝、被移除，或设备/IP 来源条件已变化。"
		case errors.Is(err, vaultwarden.ErrExpired), errors.Is(err, vaultwarden.ErrCancelled):
			p.status = "审批等待已过期或取消。"
		}
		var uncertain *vaultwarden.MutationUncertainError
		if errors.As(err, &uncertain) {
			p.status = "服务器操作结果未知；本次交换不会重放。请核验设备会话后手动发起新请求。"
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
		p.status = "账号或存储状态已变化，登录结果未采用。"
		return
	}
	// Ownership including cancellation moves to integration; closing this panel
	// must not revoke the adopted session. Integration closes the returned flow.
	p.accepted = true
	p.flow = nil
	p.cancel = nil
	p.status = "登录成功（当前运行期）。锁定或访问令牌到期后需重新审批或主密码登录。"
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
		labels := map[int]string{0: "验证器验证码", 1: "邮件验证码", 2: "Duo 系统浏览器", 3: "YubiKey OTP", 7: "系统安全密钥"}
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
		p.auth = newAuthForm(p.scope, p.epoch, func(r authRequest) {
			defer r.Close()
			deliver(vaultwarden.MFAResponse{Provider: r.Response.Provider, Token: append([]byte(nil), r.Response.Token...), Remember: r.Response.Remember, ConfirmRemoveAllMFA: r.Response.ConfirmRemoveAllMFA})
		})
		for _, id := range []int{0, 1, 3} {
			if _, ok := p.providers[id]; ok {
				p.auth.provider = id
				break
			}
		}
		p.platform = func(provider int) {
			if p.auth.busy {
				return
			}
			p.auth.busy = true
			go func() {
				response, e := p.host.Platform(ctx, ch, provider)
				if e != nil {
					clear(response.Token)
					response = vaultwarden.MFAResponse{}
				}
				deliver(response)
			}()
		}
		p.status = "审批已通过，还需双重验证。邮件仅支持服务器自动发码；本流程不使用 accessCode 冒充密码证明。"
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
			ui.Text(c, "通过另一台设备登录").FontSize(23)
			ui.Text(c, p.email)
			ui.Text(c, "请通过可信的当面或独立通信渠道，在审批设备核对下面完整 SHA-256 公钥指纹。不要只信任服务器显示的请求。 ").MaxLines(6)
			for _, r := range p.recovery {
				ui.Text(c, r.Email+"（"+r.Scope.Server+"）："+deviceLoginRecoveryWarning(r)).MaxLines(6)
			}
			if p.closed {
				ui.Text(c, "面板已关闭")
				return
			}
			if p.fingerprint != "" {
				ui.Text(c, p.fingerprint).MaxLines(4)
			}
			ui.Text(c, p.status).MaxLines(6)
			ui.Text(c, "未绑定主密码时不会保存可恢复的登录会话，也不能在访问令牌到期后续期。系统认证快照只可提供受保护的最小自动填充数据，不能恢复主界面网络会话。已有密码快照会保留。 ").MaxLines(6)
			if p.auth != nil {
				authFormView(c, p.auth, p.providers)
				if p.auth.closed {
					p.Cancel()
					return
				}
				for _, id := range []int{2, 7} {
					if label, ok := p.platformProviders[id]; ok {
						if ui.Button(c, label).Disabled(p.auth.busy).Clicked() {
							p.platform(id)
						}
					}
				}
			}
			if ui.Button(c, "发起新的审批请求").Disabled(p.busy || p.accepted).Clicked() {
				p.Start()
			}
			if ui.Button(c, "取消本次请求").Disabled(!p.busy || p.accepted).Clicked() {
				p.Cancel()
			}
		})
	})
}
