// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func devicePanelFixture(t *testing.T) (*DevicePanel, chan func()) {
	t.Helper()
	a := writableUIFixture(t)
	t.Cleanup(a.stopNetwork)
	queue := make(chan func(), 4)
	p := NewDevicePanel(a.session.(*vaultwarden.Session), a.vault, DeviceHost{Dispatch: func(f func()) { queue <- f }, Check: func() error { return nil }})
	t.Cleanup(p.Close)
	return p, queue
}
func TestDevicePanelNativeConfirmationAndLock(t *testing.T) {
	p, _ := devicePanelFixture(t)
	p.requests = []vaultwarden.AuthRequest{{ID: "request", PublicKey: "dGVzdA==", RequestDeviceType: "Desktop", RequestIPAddress: "127.0.0.1"}}
	tt := ui.NewTester(p.View, 1100, 1700)
	clickUI(t, tt, "查看登录请求 · Desktop · 127.0.0.1")
	if p.selected == nil || p.verified {
		t.Fatal("approval selected automatically")
	}
	p.respond(true)
	if p.busy {
		t.Fatal("unverified dispatched")
	}
	clickUI(t, tt, "我已在请求设备核对完整指纹")
	if !p.verified {
		t.Fatal("confirmation unavailable")
	}
	clickUI(t, tt, "取消审批")
	if p.selected != nil || p.verified {
		t.Fatal("cancel did not clear approval")
	}
	clickUI(t, tt, "清除当前设备推送登记")
	if p.confirm != "push" || p.busy {
		t.Fatal("push wrote without confirmation")
	}
	clickUI(t, tt, "取消")
	p.Close()
	tt.Frame()
	if !tt.HasText("面板已关闭") || p.selected != nil || p.devices != nil {
		t.Fatal("locked UI retained data")
	}
}
func TestDevicePanelLateResultAndUnknownMutation(t *testing.T) {
	p, q := devicePanelFixture(t)
	release := make(chan struct{})
	installed := false
	p.run(func(context.Context) error { <-release; return nil }, func() { installed = true })
	p.Close()
	close(release)
	select {
	case done := <-q:
		done()
	case <-time.After(time.Second):
		t.Fatal("no callback")
	}
	if installed {
		t.Fatal("late result resurrected UI")
	}
	p, q = devicePanelFixture(t)
	p.run(func(context.Context) error { return &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrNetwork} }, nil)
	select {
	case done := <-q:
		done()
	case <-time.After(time.Second):
		t.Fatal("no error callback")
	}
	if !p.uncertain || p.status != "操作结果未确认，请刷新核对；不会自动重试。" {
		t.Fatal("uncertain result hidden")
	}
}
