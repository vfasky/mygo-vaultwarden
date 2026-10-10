// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"slices"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func assertVaultHidden(t *testing.T, tt *ui.Tester) {
	t.Helper()
	for _, text := range []string{"所有项目", "搜索密码库", "GitHub", "alex@example.com", "复制用户名", "账号与设置"} {
		if slices.Contains(tt.Texts(), text) {
			t.Fatalf("authentication page exposed vault UI: %s", text)
		}
	}
}

func TestAuthenticationRoutesAndNavigation(t *testing.T) {
	a := &app{status: "正在读取本机存储状态…"}
	tt := ui.NewTester(a.view, 1060, 700)
	if !tt.HasText("登录服务器") || !tt.HasText("服务器地址") || !tt.HasText("邮箱") {
		t.Fatal("first launch did not show server login")
	}
	assertVaultHidden(t, tt)

	// A retained snapshot with stale display metadata must only show the lock page.
	a = previewApp()
	a.snapshot.Scope = &vaultwarden.Scope{Server: "https://vault.example.com", Account: "fixture"}
	a.itemsRevision = "stale"
	a.status = ""
	tt = ui.NewTester(a.view, 1060, 700)
	if !tt.HasText("密码库已锁定") || !tt.HasText("解锁密码库") || !tt.HasText("vault.example.com") {
		t.Fatal("locked snapshot did not show unlock page")
	}
	assertVaultHidden(t, tt)
	uitest.Click(t, tt, "使用其他账号")
	if !a.showLogin || !tt.HasText("登录服务器") || a.serverURL != "https://vault.example.com" {
		t.Fatal("switch account did not open/prepopulate server login")
	}
	if !tt.HasText("替换已有离线快照") {
		t.Fatal("account replacement warning missing")
	}
	assertVaultHidden(t, tt)
	uitest.Click(t, tt, "返回解锁")
	if a.showLogin || !tt.HasText("密码库已锁定") {
		t.Fatal("back did not return to locked vault")
	}
	a.pending = 1
	tt.Frame()
	uitest.Click(t, tt, "使用其他账号")
	if a.showLogin {
		t.Fatal("changed account while authentication was pending")
	}
	a.pending = 0
	a.observeSnapshot(&localstore.SnapshotStatus{Revision: "revoked"})
	tt.Frame()
	if !tt.HasText("登录服务器") || tt.HasText("解锁密码库") {
		t.Fatal("revoked snapshot did not return to login")
	}
}

func TestServerLoginCanReturnWithoutSwitchingAccount(t *testing.T) {
	a := previewApp()
	tt := ui.NewTester(a.view, 1280, 820)
	uitest.Click(t, tt, "账号与设置")
	settings := ui.NewTester(a.settingsWindowView, 720, 560)
	uitest.Click(t, settings, "登录服务器")
	tt.Frame()
	assertVaultHidden(t, tt)
	if !a.unlocked() {
		t.Fatal("opening login changed the current account before submission")
	}
	uitest.Click(t, tt, "返回密码库")
	if a.showLogin || !a.unlocked() || !tt.HasText("账号与设置") {
		t.Fatal("cancelled navigation lost existing vault")
	}
}

func TestServerLoginValidationAndAvailability(t *testing.T) {
	// Invalid email guarantees these UI tests cannot reach native storage or
	// contact a server even if a disabled-control regression occurs.
	a := &app{snapshot: &localstore.SnapshotStatus{Revision: "empty"}, deviceID: "fixture",
		serverURL: "https://vault.example.com", email: "invalid"}
	tt := ui.NewTester(a.view, 1060, 700)
	uitest.Click(t, tt, "登录并同步")
	if a.status != "请输入登录邮箱。" || a.pending != 0 {
		t.Fatal("login did not validate before native authentication")
	}
	a.status = ""
	tt.Frame()
	uitest.Click(t, tt, "服务器地址")
	tt.Key(0, ui.KeyEnter)
	if a.status != "请输入登录邮箱。" {
		t.Fatal("Enter did not submit login form")
	}
	a.status, a.deviceID = "安全存储组件不可用。", ""
	tt.Frame()
	uitest.Click(t, tt, "登录并同步")
	if a.status != "安全存储组件不可用。" || a.pending != 0 {
		t.Fatal("login attempted without secure storage identity")
	}
}

func TestEmptyUnlockedVaultStillEntersMainView(t *testing.T) {
	a := previewApp()
	a.items = nil
	a.snapshot.Count = 0
	tt := ui.NewTester(a.view, 1060, 700)
	if tt.HasText("密码库已锁定") || !tt.HasText("所有项目") {
		t.Fatal("empty but unlocked vault was treated as locked")
	}
}
