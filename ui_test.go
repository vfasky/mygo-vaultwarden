// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Public, invented metadata only. Rendering never opens the real vault or Keychain.
func previewApp() *app {
	return &app{
		status: "离线快照已解锁。", itemsRevision: "preview",
		snapshot: &snapshotStatus{Revision: "preview", Available: true, Count: 8, UpdatedAt: 1791302700000},
		items: []displayCredential{
			{ID: "1", Title: "Apple", Username: "alex@example.com", URL: "https://account.apple.com"},
			{ID: "2", Title: "Figma", Username: "alex.design@example.com", URL: "https://www.figma.com"},
			{ID: "3", Title: "GitHub", Username: "alex-dev", URL: "https://github.com/login"},
			{ID: "4", Title: "Google", Username: "alex@example.com", URL: "https://accounts.google.com"},
			{ID: "5", Title: "Linear", Username: "alex@example.com", URL: "https://linear.app"},
			{ID: "6", Title: "Notion", Username: "alex@example.com", URL: "https://www.notion.so"},
			{ID: "7", Title: "Vercel", Username: "alex-dev", URL: "https://vercel.com"},
			{ID: "8", Title: "工作邮箱", Username: "alex@work.example.com", URL: "https://mail.example.com"},
		},
	}
}

func clickUI(t *testing.T, tt *ui.Tester, label string) {
	t.Helper()
	if err := tt.Click(label); err != nil {
		t.Fatal(err)
	}
}

func TestDumpAlignment(t *testing.T) {
	tt := ui.NewTester(func(c *ui.Context) {
		c.SetTheme(vaultTheme)
		ui.Column(c).Fill().Padding(20).Gap(24).Background(vaultPanel).Children(func() {
			ui.Row(c).Padding(10, 8, 0, 8).Background(ui.Hex("#EEE")).Children(func() {
				ui.Text(c, "所有项目").FontSize(22).FontWeight(650).Label("heading")
				ui.Spacer(c)
				pill(c, "947", vaultWhite, vaultMuted)
			})
			ui.Row(c).Gap(8).Background(ui.Hex("#EEE")).Children(func() {
				ui.Text(c, "我的密码库").FontSize(12).TextColor(vaultMuted).Label("crumb-vault")
				icon(c, "chevron", 12).TextColor(vaultMuted).Label("crumb-chevron")
				ui.Text(c, "登录").FontSize(12).TextColor(vaultMuted).Label("crumb-login")
				ui.Spacer(c)
				pill(c, "只读", vaultWhite, vaultMuted)
			})
			ui.Row(c).Gap(8).AlignItems(ui.Center).Background(ui.Hex("#DDD")).Children(func() {
				ui.Text(c, "我的密码库").FontSize(12).TextColor(vaultMuted).Label("c2-vault")
				icon(c, "chevron", 12).TextColor(vaultMuted).Label("c2-chevron")
				ui.Text(c, "登录").FontSize(12).TextColor(vaultMuted).Label("c2-login")
				ui.Spacer(c)
				pill(c, "只读", vaultWhite, vaultMuted)
			})
			ui.Row(c).Height(32).AlignItems(ui.Center).Background(ui.Hex("#CCC")).Children(func() {
				ui.Text(c, "所有项目").FontSize(22).FontWeight(650).Label("h2")
				ui.Spacer(c)
				pill(c, "947", vaultWhite, vaultMuted)
			})
		})
	}, 640, 220)
	for _, s := range []string{"heading", "947", "crumb-vault", "crumb-chevron", "crumb-login", "只读", "c2-vault", "c2-chevron", "c2-login", "h2"} {
		if r, ok := tt.Find(s); ok {
			t.Logf("%q x=%.1f y=%.1f w=%.1f h=%.1f cy=%.1f", s, r.X, r.Y, r.W, r.H, r.Y+r.H/2)
		} else {
			t.Logf("%q missing", s)
		}
	}
	path := filepath.Join(os.Getenv("TMPDIR"), "align-rows.png")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, tt.Image()); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log(path)
}

func TestVaultSidebarToggle(t *testing.T) {
	a := previewApp()
	tt := ui.NewTester(a.view, 1060, 700)
	if a.sidebarCollapsed || a.sidebarWidth() != 236 {
		t.Fatal("sidebar should start expanded")
	}
	tt.SetTitleBar(ui.TitleBar{Height: 52, Left: 88})
	if r, ok := tt.Find("折叠侧栏"); !ok || r.X < 88 || r.X+r.W > a.sidebarWidth() || r.Y < 0 || r.Y+r.H > 52 {
		t.Fatal("expanded toggle must remain in sidebar title bar past native window controls")
	}
	clickUI(t, tt, "折叠侧栏")
	if !a.sidebarCollapsed || a.sidebarWidth() != 64 {
		t.Fatal("sidebar did not collapse")
	}
	if r, ok := tt.Find("展开侧栏"); !ok || r.X < 88 || r.Y < 0 || r.Y+r.H > 52 {
		t.Fatal("collapsed toggle overlaps native window controls")
	}
	for _, text := range []string{"Vaultwarden", "个人密码库", "所有密码库", "项目", "组织", "文件夹"} {
		if slices.Contains(tt.Texts(), text) {
			t.Fatalf("collapsed sidebar retained text %q", text)
		}
	}
	clickUI(t, tt, "支付卡")
	if a.category != "card" {
		t.Fatal("collapsed category navigation failed")
	}
	clickUI(t, tt, "我的密码库")
	if a.category != "personal" || a.showSettings {
		t.Fatal("collapsed vault navigation failed")
	}
	clickUI(t, tt, "展开侧栏")
	if a.sidebarCollapsed || !slices.Contains(tt.Texts(), "所有密码库") {
		t.Fatal("sidebar did not expand")
	}
	tt.Key(ui.Cmd, ui.KeyB)
	if !a.sidebarCollapsed {
		t.Fatal("keyboard shortcut did not collapse sidebar")
	}
	tt.Key(ui.Cmd, ui.KeyB)
	if a.sidebarCollapsed {
		t.Fatal("keyboard shortcut did not expand sidebar")
	}
}

func TestCollapsedSidebarNavigation(t *testing.T) {
	a := previewApp()
	a.sidebarCollapsed = true
	tt := ui.NewTester(func(c *ui.Context) {
		ui.Row(c).Fill().AlignItems(ui.Stretch).Children(func() { a.sidebar(c) })
	}, 65, 700)
	if slices.Contains(tt.Texts(), "8") {
		t.Fatal("collapsed sidebar retained count badge")
	}
	for _, category := range vaultCategories {
		clickUI(t, tt, category.title)
		if a.category != category.id || a.showSettings {
			t.Fatalf("collapsed navigation failed for %s", category.title)
		}
		// Texts includes accessibility labels; each icon button keeps its label,
		// but must not also render a text child.
		count := 0
		for _, text := range tt.Texts() {
			if text == category.title {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("collapsed button %q has %d labels/texts, want 1", category.title, count)
		}
	}
	clickUI(t, tt, "账号与设置")
	if !a.showSettings {
		t.Fatal("collapsed sidebar settings did not open")
	}
	clickUI(t, tt, "我的密码库")
	if a.category != "personal" || a.showSettings {
		t.Fatal("collapsed vault navigation did not close settings")
	}
}

func TestCollapsedSidebarBaselineNavigationAndRevocation(t *testing.T) {
	a := organizationUIFixture(t, true, true, 0)
	defer a.stopNetwork()
	a.sidebarCollapsed = true
	a.folders = []vaultwarden.Folder{{ID: "folder-1", Name: "测试文件夹"}}
	tt := ui.NewTester(a.view, 1280, 820)
	if organizationUIEnabled {
		clickUI(t, tt, "团队组织")
		if a.category != "org:organization-1" || len(a.filteredItems()) != 1 {
			t.Fatal("collapsed organization navigation lost baseline filter")
		}
		clickUI(t, tt, "  团队集合")
		if a.category != "collection:collection-1" {
			t.Fatal("collapsed collection navigation lost destination")
		}
		clickUI(t, tt, "查看与编辑")
		if a.editor == nil || a.editor.inputs[1].value != "org secret" {
			t.Fatal("collapsed navigation lost authorized editor")
		}
		a.editor = nil
	} else if tt.HasText("团队组织") || tt.HasText("创建或加入组织") {
		t.Fatal("deferred organization UI exposed")
	}
	tt.Frame()
	clickUI(t, tt, "测试文件夹")
	if a.category != "folder:folder-1" {
		t.Fatal("collapsed folder navigation lost filter")
	}
	clickUI(t, tt, "我的密码库")
	for _, item := range a.filteredItems() {
		if item.ID == "organization-item" {
			t.Fatal("personal navigation leaked organization item")
		}
	}
	a.lockInterface()
	tt.Frame()
	if a.editor != nil || len(a.organizations) != 0 || len(a.folders) != 0 || tt.HasText("团队组织") || tt.HasText("org secret") {
		t.Fatal("collapsed navigation retained revoked content")
	}
}

func TestVaultSelectionSearchAndRevocation(t *testing.T) {
	a := previewApp()
	tt := ui.NewTester(a.view, 1280, 820)
	if a.selectedID != "1" {
		t.Fatalf("initial selection = %s", a.selectedID)
	}
	clickUI(t, tt, "GitHub")
	if a.selectedID != "3" {
		t.Fatalf("clicked selection = %s", a.selectedID)
	}
	clickUI(t, tt, "复制用户名")
	if tt.Clipboard() != "alex-dev" {
		t.Fatal("copy did not use selected credential")
	}
	clickUI(t, tt, "打开网站")
	if !slices.Equal(tt.OpenedURLs(), []string{"https://github.com/login"}) {
		t.Fatal("wrong site opened")
	}
	clickUI(t, tt, "GitHub")
	tt.Key(0, ui.KeyDown)
	if a.selectedID != "4" {
		t.Fatalf("keyboard selection = %s", a.selectedID)
	}
	tt.Key(ui.Cmd, ui.KeyF)
	tt.Type("figma")
	if a.selectedID != "2" {
		t.Fatalf("filtered selection = %s", a.selectedID)
	}
	tt.Type(" unmatched")
	if a.selectedID != "" || slices.Contains(tt.Texts(), "alex.design@example.com") {
		t.Fatal("search retained stale detail")
	}
	clickUI(t, tt, "清除搜索")
	clickUI(t, tt, "支付卡")
	if a.selectedID != "" || len(a.filteredItems()) != 0 {
		t.Fatal("empty card category showed login credentials")
	}
	clickUI(t, tt, "登录")
	if a.selectedID == "" {
		t.Fatal("returning to logins did not select item")
	}
	a.observeSnapshot(&snapshotStatus{Revision: "revoked", Available: true})
	tt.Frame()
	if a.selectedID != "" || slices.Contains(tt.Texts(), "alex@example.com") {
		t.Fatal("revocation retained credential details")
	}
}

func TestVaultSelectionSurvivesReplacement(t *testing.T) {
	a := previewApp()
	tt := ui.NewTester(a.view, 1060, 700)
	clickUI(t, tt, "Figma")
	a.items = append([]displayCredential{{ID: "0", Title: "A new login"}}, a.items...)
	tt.Frame()
	if a.selectedID != "2" {
		t.Fatal("insertion changed selected identity")
	}
	a.items = slices.DeleteFunc(a.items, func(item displayCredential) bool { return item.ID == "2" })
	tt.Frame()
	if a.selectedID == "2" || slices.Contains(tt.Texts(), "alex.design@example.com") {
		t.Fatal("deleted item survived in details")
	}
}

func TestVaultSettingsAndSafeLinks(t *testing.T) {
	a := previewApp()
	a.items[0].URL = "javascript:alert(1)"
	tt := ui.NewTester(a.view, 1060, 700)
	clickUI(t, tt, "打开网站")
	if len(tt.OpenedURLs()) != 0 {
		t.Fatal("unsafe URL opened")
	}
	clickUI(t, tt, "账号与设置")
	if !a.showSettings || !slices.Contains(tt.Texts(), "连接密码库") {
		t.Fatal("settings did not open")
	}
	clickUI(t, tt, "关闭设置")
	if a.showSettings {
		t.Fatal("settings did not close")
	}
}

// Opt-in previews are generated by the real native UI renderer, not an HTML mock.
func TestVaultVisualPreviews(t *testing.T) {
	dir := os.Getenv("MYGO_UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MYGO_UI_PREVIEW_DIR to export public fixture previews")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, size := range [][2]int{{1280, 820}, {1060, 700}, {460, 580}} {
		for _, state := range []string{"detail", "settings", "login", "verification", "verification-error", "locked", "locked-legacy", "empty-search"} {
			if size[0] < 1060 && state != "login" && state != "locked" && state != "locked-legacy" && state != "verification" && state != "verification-error" {
				continue
			}
			a := previewApp()
			a.selectedID = "3"
			switch state {
			case "settings":
				a.showSettings = true
			case "login":
				a = &app{snapshot: &snapshotStatus{Revision: "empty"}, deviceID: "preview",
					serverURL: "https://vault.example.com", email: "alex@example.com", masterPassword: "fixture-password"}
			case "verification", "verification-error":
				a = &app{snapshot: &snapshotStatus{Revision: "empty"}, showLogin: true, epoch: 1, pending: 1,
					serverURL: "https://vault.example.com", email: "alex@example.com"}
				challenge := newLoginChallenge(context.Background(), 1)
				t.Cleanup(challenge.cancel)
				attempt := 1
				if state == "verification-error" {
					attempt = 2
				}
				a.presentLoginChallenge(challenge, attempt)
			case "locked", "locked-legacy":
				a = passwordLockedApp()
				if state == "locked-legacy" {
					a.snapshot.PasswordUnlock = nil
				}
				a.status = ""
			case "empty-search":
				a.query = "no such item"
			}
			tt := ui.NewTester(a.view, size[0], size[1])
			path := filepath.Join(dir, fmt.Sprintf("vault-%s-%d.png", state, size[0]))
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			err = png.Encode(f, tt.Image())
			closeErr := f.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
		}
	}
}
