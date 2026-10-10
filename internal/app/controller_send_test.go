// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func sendPanelFixture(t *testing.T) (*send.Panel, chan func()) {
	t.Helper()
	a := writableUIFixture(t)
	t.Cleanup(a.stopNetwork)
	s := a.session.(*vaultwarden.Session)
	var raw map[string]any
	json.Unmarshal(a.vault.Sync, &raw)
	raw["sends"] = []any{}
	a.vault.Sync, _ = json.Marshal(raw)
	if e := s.AcceptAuthenticatedSnapshot(a.vault, a.sessionRevision); e != nil {
		t.Fatal(e)
	}
	queue := make(chan func(), 4)
	p := send.NewPanel(s, nil, a.vault, *a.liveScope, send.Host{Dispatch: func(f func()) { queue <- f }, Check: func() error { return nil }})
	t.Cleanup(p.Close)
	return p, queue
}
func TestSendPanelNativeFormAndLock(t *testing.T) {
	p, _ := sendPanelFixture(t)
	tt := ui.NewTester(p.View, 1100, 1700)
	uitest.Click(t, tt, "新建文本")
	if p.Draft == nil || p.Fields.Type != 0 || !tt.HasText("此服务器版本不支持邮件验证型 Send。") {
		t.Fatal("native form absent")
	}
	p.Fields.Name = "sensitive send title"
	p.Fields.Text = "sensitive send plaintext"
	p.Password = "private password"
	p.ReceivePassword = "private receiver password"
	p.Link = "private fragment"
	uitest.Click(t, tt, "禁用：false")
	if !p.Fields.Disabled {
		t.Fatal("disable control")
	}
	uitest.Click(t, tt, "隐藏邮箱：false")
	if !p.Fields.HideEmail {
		t.Fatal("hide email control")
	}
	p.Deletion = "invalid"
	p.Save()
	if p.Busy || p.Draft == nil || p.Fields.Text == "" {
		t.Fatal("invalid form dispatched or destroyed")
	}
	p.Close()
	tt.Frame()
	if p.Draft != nil || p.Fields.Text != "" || p.Password != "" || p.ReceivePassword != "" || p.Link != "" || tt.HasText("sensitive send plaintext") {
		t.Fatal("lock retained secrets")
	}
}
func TestSendPanelOfflineAndFileForm(t *testing.T) {
	p, _ := sendPanelFixture(t)
	p.Offline()
	if p.Status != "离线受信快照；访问次数可能已变化" || len(p.Rows) != 0 {
		t.Fatal("trusted empty offline list", p.Status)
	}
	p.New(1)
	tt := ui.NewTester(p.View, 1000, 1600)
	if p.Draft == nil || p.Fields.Type != 1 || !tt.HasText("文件内容不可编辑；新建时选择本地文件。") {
		t.Fatal("file form")
	}
	p.Host.Check = func() error { return vaultwarden.ErrExpired }
	p.Save()
	if p.Busy || p.Draft == nil {
		t.Fatal("stale host dispatched")
	}
}
func TestSendPanelLateCallbackAndUnknownOutcome(t *testing.T) {
	p, queue := sendPanelFixture(t)
	p.New(0)
	d := p.Draft
	p.Draft = nil
	released := make(chan struct{})
	p.Run(func(ctx context.Context) send.Result { <-released; return send.Result{Draft: d} })
	p.Close()
	close(released)
	select {
	case done := <-queue:
		done()
	case <-time.After(time.Second):
		t.Fatal("worker did not complete")
	}
	if p.Draft != nil || d.Fields.Name != "" {
		t.Fatal("late result resurrected")
	}
	if _, e := d.ShareLink(); !errors.Is(e, vaultwarden.ErrExpired) {
		t.Fatal("late result not closed")
	}
	p2, q2 := sendPanelFixture(t)
	p2.Run(func(context.Context) send.Result {
		return send.Result{Err: &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrNetwork}}
	})
	select {
	case done := <-q2:
		done()
	case <-time.After(time.Second):
		t.Fatal("completion")
	}
	if !p2.Uncertain || p2.Busy {
		t.Fatal("unknown not blocked")
	}
	tt := ui.NewTester(p2.View, 900, 900)
	if !tt.HasText("结果未确认，请刷新或同步核对。不会自动重试。") {
		t.Fatal("unknown guidance")
	}
}
