// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func devicePanelFixture(t *testing.T) (*account.DevicePanel, chan func()) {
	t.Helper()
	a := writableUIFixture(t)
	t.Cleanup(a.stopNetwork)
	queue := make(chan func(), 4)
	p := account.NewDevicePanel(a.session.(*vaultwarden.Session), a.vault, account.DeviceHost{Dispatch: func(f func()) { queue <- f }, Check: func() error { return nil }})
	t.Cleanup(p.Close)
	return p, queue
}
func TestDevicePanelNativeConfirmationAndLock(t *testing.T) {
	p, _ := devicePanelFixture(t)
	p.Requests = []vaultwarden.AuthRequest{{ID: "request", PublicKey: "dGVzdA==", RequestDeviceType: "Desktop", RequestIPAddress: "127.0.0.1"}}
	tt := ui.NewTester(p.View, 1100, 1700)
	uitest.Click(t, tt, "查看登录请求 · Desktop · 127.0.0.1")
	if p.Selected == nil || p.Verified {
		t.Fatal("approval selected automatically")
	}
	p.Respond(true)
	if p.Busy {
		t.Fatal("unverified dispatched")
	}
	uitest.Click(t, tt, "我已在请求设备核对完整指纹")
	if !p.Verified {
		t.Fatal("confirmation unavailable")
	}
	uitest.Click(t, tt, "取消审批")
	if p.Selected != nil || p.Verified {
		t.Fatal("cancel did not clear approval")
	}
	uitest.Click(t, tt, "清除当前设备推送登记")
	if p.Confirm != "push" || p.Busy {
		t.Fatal("push wrote without confirmation")
	}
	uitest.Click(t, tt, "取消")
	p.Close()
	tt.Frame()
	if !tt.HasText("面板已关闭") || p.Selected != nil || p.Devices != nil {
		t.Fatal("locked UI retained data")
	}
}
func TestDevicePanelLateResultAndUnknownMutation(t *testing.T) {
	p, q := devicePanelFixture(t)
	release := make(chan struct{})
	installed := false
	p.Run(func(context.Context) error { <-release; return nil }, func() { installed = true })
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
	p.Run(func(context.Context) error { return &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrNetwork} }, nil)
	select {
	case done := <-q:
		done()
	case <-time.After(time.Second):
		t.Fatal("no error callback")
	}
	if !p.Uncertain || p.Status != "操作结果未确认，请刷新核对；不会自动重试。" {
		t.Fatal("uncertain result hidden")
	}
}
