// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
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
	closed, Busy, Uncertain, Verified bool
	Status, Confirm                   string
	Devices                           []vaultwarden.Device
	Requests                          []vaultwarden.AuthRequest
	Selected                          *vaultwarden.AuthRequest
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
	p.Devices = nil
	p.Requests = nil
	p.Selected = nil
	p.Verified = false
	p.Confirm = ""
	p.Status = ""
}
func (p *DevicePanel) Run(work func(context.Context) error, done func()) {
	if p.closed || p.Busy {
		return
	}
	if p.host.Check() != nil {
		p.Close()
		return
	}
	p.Busy = true
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
			p.Busy = false
			if p.host.Check() != nil || p.ctx.Err() != nil {
				p.Close()
				return
			}
			if err != nil {
				p.Status = i18n.T("account.device.err_operation_failed")
				var uncertain *vaultwarden.MutationUncertainError
				p.Uncertain = errors.As(err, &uncertain)
				if p.Uncertain {
					p.Status = i18n.T("account.device.status_unconfirmed")
				}
				return
			}
			p.Status = i18n.T("account.device.status_completed")
			if done != nil {
				done()
			}
		})
	}()
}
func (p *DevicePanel) Refresh() {
	var devices []vaultwarden.Device
	var requests []vaultwarden.AuthRequest
	p.Run(func(ctx context.Context) error {
		var err error
		devices, err = p.session.Devices(ctx, p.vault.Scope, p.host.Checkpoint)
		if err == nil {
			requests, err = p.session.AuthRequests(ctx, p.vault.Scope, true, p.host.Checkpoint)
		}
		return err
	}, func() {
		p.Devices = devices
		p.Requests = requests
		p.Selected = nil
		p.Verified = false
		p.Confirm = ""
		p.Uncertain = false
	})
}
func (p *DevicePanel) Respond(approve bool) {
	if p.Selected == nil || p.Uncertain || approve && !p.Verified || p.Confirm != "auth" {
		return
	}
	row := *p.Selected
	p.Confirm = ""
	p.Verified = false
	p.Run(func(ctx context.Context) error {
		return p.session.RespondAuthRequest(ctx, p.vault, row.ID, row.PublicKey, approve, true, p.host.Checkpoint)
	}, func() {
		p.Selected = nil
		p.Requests = nil
		if p.host.Changed != nil {
			p.host.Changed()
		}
	})
}
func (p *DevicePanel) clearPush() {
	if p.Confirm != "push" || p.Uncertain {
		return
	}
	p.Confirm = ""
	p.Run(func(ctx context.Context) error {
		return p.session.ClearDevicePushToken(ctx, p.vault.Scope, true, p.host.Checkpoint)
	}, func() { p.Status = i18n.T("account.device.status_push_removal_requested") })
}
func authPublicFingerprint(public string) string {
	der, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		return i18n.T("account.device.err_invalid_public_key")
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
func (p *DevicePanel) View(c *ui.Context) {
	ui.Scroll(c).Children(func() {
		ui.Column(c).Padding(18).Gap(10).Children(func() {
			ui.Text(c, i18n.T("account.device.title")).FontSize(23)
			if p.closed {
				ui.Text(c, i18n.T("account.device.status_panel_closed"))
				return
			}
			button := func(label string, disabled bool, f func()) {
				if ui.Button(c, label).Disabled(disabled).Clicked() {
					f()
				}
			}
			button(i18n.T("account.device.refresh_requests"), p.Busy, p.Refresh)
			ui.Text(c, p.Status).MaxLines(4)
			for _, d := range p.Devices {
				ui.Text(c, d.Name+" · "+d.Identifier).MaxLines(2)
			}
			if p.Confirm != "push" {
				button(i18n.T("account.device.clear_push"), p.Busy || p.Uncertain, func() { p.Confirm = "push" })
			} else {
				ui.Text(c, i18n.T("account.device.clear_push_hint")).MaxLines(4)
				button(i18n.T("account.device.confirm_clear_push"), p.Busy, p.clearPush)
				button(i18n.T("common.cancel"), p.Busy, func() { p.Confirm = "" })
			}
			for _, r := range p.Requests {
				row := r
				button(i18n.Tf("account.device.view_login_request", r.RequestDeviceType, r.RequestIPAddress), p.Busy, func() { p.Selected = &row; p.Verified = false; p.Confirm = "auth" })
			}
			if r := p.Selected; r != nil {
				ui.Text(c, i18n.Tf("account.device.request_origin", r.Origin)).MaxLines(2)
				ui.Text(c, i18n.Tf("account.device.request_time", r.CreationDate))
				ui.Text(c, i18n.Tf("account.device.public_key_fingerprint", authPublicFingerprint(r.PublicKey))).MaxLines(4)
				ui.Text(c, i18n.T("account.device.approval_fingerprint_hint")).MaxLines(4)
				button(i18n.T("account.device.confirm_fingerprint"), p.Busy || p.Uncertain, func() { p.Verified = true })
				button(i18n.T("account.device.confirm_approve_login"), p.Busy || p.Uncertain || !p.Verified, func() { p.Respond(true) })
				button(i18n.T("account.device.confirm_reject_login"), p.Busy || p.Uncertain, func() { p.Respond(false) })
				button(i18n.T("account.device.cancel_approval"), p.Busy, func() { p.Selected = nil; p.Verified = false; p.Confirm = "" })
			}
			button(i18n.T("common.close"), false, p.Close)
		})
	})
}
