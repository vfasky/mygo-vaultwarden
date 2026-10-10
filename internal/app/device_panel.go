// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// DeviceHost.Dispatch schedules on window.Update. Check is worker-safe and
// checks account, unlocked state, epoch and authenticated storage revision.
// Close must run on UI thread before revoking that lease. Changed schedules a
// safe full sync; it must not publish a stale worker result.
type DeviceHost struct {
	Busy       func(bool) // UI-thread worker accounting, including late completion
	Dispatch   func(func())
	Check      func() error
	Checkpoint func(vaultwarden.SessionCheckpoint) error
	Changed    func()
}
type DevicePanel struct {
	host                              DeviceHost
	session                           *vaultwarden.Session
	vault                             *vaultwarden.VaultData
	ctx                               context.Context
	cancel                            context.CancelFunc
	generation                        uint64
	closed, busy, uncertain, verified bool
	status, confirm                   string
	devices                           []vaultwarden.Device
	requests                          []vaultwarden.AuthRequest
	selected                          *vaultwarden.AuthRequest
}

func NewDevicePanel(s *vaultwarden.Session, v *vaultwarden.VaultData, host DeviceHost) *DevicePanel {
	ctx, cancel := context.WithCancel(context.Background())
	p := &DevicePanel{session: s, vault: v, host: host, ctx: ctx, cancel: cancel}
	if s == nil || v == nil || host.Check == nil || host.Dispatch == nil {
		p.closed = true
		cancel()
	}
	return p
}
func (p *DevicePanel) Close() {
	p.cancel()
	p.generation++
	p.closed = true
	p.devices = nil
	p.requests = nil
	p.selected = nil
	p.verified = false
	p.confirm = ""
	p.status = ""
}
func (p *DevicePanel) run(work func(context.Context) error, done func()) {
	if p.closed || p.busy {
		return
	}
	if p.host.Check() != nil {
		p.Close()
		return
	}
	p.busy = true
	if p.host.Busy != nil {
		p.host.Busy(true)
	}
	generation := p.generation
	go func() {
		err := p.host.Check()
		if err == nil {
			err = work(p.ctx)
		}
		p.host.Dispatch(func() {
			if p.host.Busy != nil {
				p.host.Busy(false)
			}
			if p.closed || p.generation != generation {
				return
			}
			p.busy = false
			if p.host.Check() != nil || p.ctx.Err() != nil {
				p.Close()
				return
			}
			if err != nil {
				p.status = "操作失败，请刷新核对后再试。"
				var uncertain *vaultwarden.MutationUncertainError
				p.uncertain = errors.As(err, &uncertain)
				if p.uncertain {
					p.status = "操作结果未确认，请刷新核对；不会自动重试。"
				}
				return
			}
			p.status = "操作完成"
			if done != nil {
				done()
			}
		})
	}()
}
func (p *DevicePanel) Refresh() {
	var devices []vaultwarden.Device
	var requests []vaultwarden.AuthRequest
	p.run(func(ctx context.Context) error {
		var err error
		devices, err = p.session.Devices(ctx, p.vault.Scope, p.host.Checkpoint)
		if err == nil {
			requests, err = p.session.AuthRequests(ctx, p.vault.Scope, true, p.host.Checkpoint)
		}
		return err
	}, func() {
		p.devices = devices
		p.requests = requests
		p.selected = nil
		p.verified = false
		p.confirm = ""
		p.uncertain = false
	})
}
func (p *DevicePanel) respond(approve bool) {
	if p.selected == nil || p.uncertain || approve && !p.verified || p.confirm != "auth" {
		return
	}
	row := *p.selected
	p.confirm = ""
	p.verified = false
	p.run(func(ctx context.Context) error {
		return p.session.RespondAuthRequest(ctx, p.vault, row.ID, row.PublicKey, approve, true, p.host.Checkpoint)
	}, func() {
		p.selected = nil
		p.requests = nil
		if p.host.Changed != nil {
			p.host.Changed()
		}
	})
}
func (p *DevicePanel) clearPush() {
	if p.confirm != "push" || p.uncertain {
		return
	}
	p.confirm = ""
	p.run(func(ctx context.Context) error {
		return p.session.ClearDevicePushToken(ctx, p.vault.Scope, true, p.host.Checkpoint)
	}, func() { p.status = "已请求清除推送登记；登录会话仍有效。" })
}
func authPublicFingerprint(public string) string {
	der, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		return "无效公钥"
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
func (p *DevicePanel) View(c *ui.Context) {
	ui.Scroll(c).Children(func() {
		ui.Column(c).Padding(18).Gap(10).Children(func() {
			ui.Text(c, "设备与登录审批").FontSize(23)
			if p.closed {
				ui.Text(c, "面板已关闭")
				return
			}
			button := func(label string, disabled bool, f func()) {
				if ui.Button(c, label).Disabled(disabled).Clicked() {
					f()
				}
			}
			button("刷新设备与待审批请求", p.busy, p.Refresh)
			ui.Text(c, p.status).MaxLines(4)
			for _, d := range p.devices {
				ui.Text(c, d.Name+" · "+d.Identifier).MaxLines(2)
			}
			if p.confirm != "push" {
				button("清除当前设备推送登记", p.busy || p.uncertain, func() { p.confirm = "push" })
			} else {
				ui.Text(c, "仅清除推送登记，不会退出登录或撤销会话。同一设备标识的其他账号也可能受影响。").MaxLines(4)
				button("确认清除推送登记", p.busy, p.clearPush)
				button("取消", p.busy, func() { p.confirm = "" })
			}
			for _, r := range p.requests {
				row := r
				button("查看登录请求 · "+r.RequestDeviceType+" · "+r.RequestIPAddress, p.busy, func() { p.selected = &row; p.verified = false; p.confirm = "auth" })
			}
			if r := p.selected; r != nil {
				ui.Text(c, "请求来源："+r.Origin).MaxLines(2)
				ui.Text(c, "请求时间："+r.CreationDate)
				ui.Text(c, "公钥 SHA-256："+authPublicFingerprint(r.PublicKey)).MaxLines(4)
				ui.Text(c, "请与请求设备上显示的公钥指纹逐字核对。批准将向该设备提供保险库解密密钥。").MaxLines(4)
				button("我已在请求设备核对完整指纹", p.busy || p.uncertain, func() { p.verified = true })
				button("确认批准此登录", p.busy || p.uncertain || !p.verified, func() { p.respond(true) })
				button("确认拒绝此登录", p.busy || p.uncertain, func() { p.respond(false) })
				button("取消审批", p.busy, func() { p.selected = nil; p.verified = false; p.confirm = "" })
			}
			button("关闭", false, p.Close)
		})
	})
}
