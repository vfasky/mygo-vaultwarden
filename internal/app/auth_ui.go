// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// authForm is UI-thread owned. Scheduler closes every emitted request and
// passes matching scope/epoch/sequence when posting completion on UI thread.
type authForm struct {
	scope                              vaultwarden.Scope
	epoch, sequence                    uint64
	provider                           int
	token, status                      string
	remember, confirming, busy, closed bool
	disableRemember                    bool
	cancel                             context.CancelFunc
	submit                             func(authRequest)
}
type authRequest struct {
	Scope           vaultwarden.Scope
	Epoch, Sequence uint64
	Response        vaultwarden.MFAResponse
	Context         context.Context
}

func (r *authRequest) Close() { clear(r.Response.Token); r.Response.Token = nil }
func newAuthForm(scope vaultwarden.Scope, epoch uint64, submit func(authRequest)) *authForm {
	return &authForm{scope: scope, epoch: epoch, submit: submit}
}
func (f *authForm) Close() {
	if f.cancel != nil {
		f.cancel()
	}
	f.token = ""
	f.confirming = false
	f.busy = false
	f.closed = true
	f.sequence++
}
func (f *authForm) dispatch() {
	if f.closed || f.busy || f.submit == nil || f.token == "" {
		return
	}
	if f.provider == 8 && !f.confirming {
		f.confirming = true
		f.status = "恢复码会删除此账号的全部双重验证及恢复码。确认后需要重新设置 MFA。"
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.sequence++
	f.busy = true
	r := authRequest{Scope: f.scope, Epoch: f.epoch, Sequence: f.sequence, Context: ctx, Response: vaultwarden.MFAResponse{Provider: f.provider, Token: []byte(f.token), Remember: f.remember, ConfirmRemoveAllMFA: f.provider == 8 && f.confirming}}
	f.token = ""
	f.confirming = false
	f.submit(r)
}
func (f *authForm) complete(scope vaultwarden.Scope, epoch, sequence uint64, err error) bool {
	if f.closed || scope != f.scope || epoch != f.epoch || sequence != f.sequence {
		return false
	}
	if f.cancel != nil {
		f.cancel()
		f.cancel = nil
	}
	f.busy = false
	f.token = ""
	if err != nil {
		f.status = "验证失败或结果未知；恢复码可能已关闭全部 MFA，请先核验账号状态。"
	} else {
		f.status = "认证响应已完成，等待账号与保险库核验。"
	}
	return true
}
func authFormView(c *ui.Context, f *authForm, providers map[int]string) {
	if f == nil || f.closed {
		return
	}
	for _, p := range []int{0, 1, 2, 3, 7, 8} {
		label, ok := providers[p]
		if !ok && p != 8 {
			continue
		}
		if p == 8 {
			label = "使用恢复码（关闭全部 MFA）"
		}
		if ui.Button(c, label).Disabled(f.busy).Clicked() {
			f.provider = p
			f.token = ""
			f.confirming = false
		}
	}
	ui.TextInput(c, &f.token).Label("验证响应 / 恢复码").Password().Disabled(f.busy)
	if !f.disableRemember && ui.Button(c, "记住此设备").Disabled(f.busy || f.provider == 8).Clicked() {
		f.remember = !f.remember
	}
	if f.remember {
		ui.Text(c, "此设备将在安全存储中保存 MFA 设备令牌")
	}
	label := "继续验证"
	if f.confirming {
		label = "确认关闭全部 MFA 并登录"
	}
	if ui.Button(c, label).Disabled(f.busy).Clicked() {
		f.dispatch()
	}
	if ui.Button(c, "取消并清除输入").Clicked() {
		f.Close()
	}
	ui.Text(c, f.status).MaxLines(5)
}
