// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
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
		f.Status = i18n.T("恢复码会删除此账号的全部双重验证及恢复码。确认后需要重新设置 MFA。")
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
		f.Status = i18n.T("验证失败或结果未知；恢复码可能已关闭全部 MFA，请先核验账号状态。")
	} else {
		f.Status = i18n.T("认证响应已完成，等待账号与保险库核验。")
	}
	return true
}
func AuthFormView(c *ui.Context, f *AuthForm, providers map[int]string) {
	if f == nil || f.Closed {
		return
	}
	for _, p := range []int{0, 1, 2, 3, 7, 8} {
		label, ok := providers[p]
		if !ok && p != 8 {
			continue
		}
		if p == 8 {
			label = i18n.T("使用恢复码（关闭全部 MFA）")
		}
		if ui.Button(c, label).Disabled(f.Busy).Clicked() {
			f.Provider = p
			f.Token = ""
			f.Confirming = false
		}
	}
	ui.TextInput(c, &f.Token).Label(i18n.T("验证响应 / 恢复码")).Password().Disabled(f.Busy)
	if !f.DisableRemember && ui.Button(c, i18n.T("记住此设备")).Disabled(f.Busy || f.Provider == 8).Clicked() {
		f.remember = !f.remember
	}
	if f.remember {
		ui.Text(c, i18n.T("此设备将在安全存储中保存 MFA 设备令牌"))
	}
	label := i18n.T("继续验证")
	if f.Confirming {
		label = i18n.T("确认关闭全部 MFA 并登录")
	}
	if ui.Button(c, label).Disabled(f.Busy).Clicked() {
		f.Dispatch()
	}
	if ui.Button(c, i18n.T("取消并清除输入")).Clicked() {
		f.Close()
	}
	ui.Text(c, f.Status).MaxLines(5)
}
