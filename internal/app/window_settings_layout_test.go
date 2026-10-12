// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
)

func TestSettingsWindowOptions(t *testing.T) {
	opts := settingsWindowOptions()
	if opts.Width != 860 || opts.Height != 600 || opts.MinWidth != 720 || opts.MinHeight != 500 {
		t.Fatalf("unexpected settings dimensions: %+v", opts)
	}
	if opts.TitleBarStyle != mygo.TitleBarHiddenInset || opts.TrafficLightPosition == nil || opts.TrafficLightPosition.X != 18 || opts.TrafficLightPosition.Y != 18 {
		t.Fatalf("unexpected settings title bar: %+v", opts)
	}
}

// Tester has no public accessibility-tree API; check role declarations here
// and exercise the rendered five-item group and selection below.
func TestSettingsSidebarRoleDeclarations(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "window_settings_shell.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]int{}
	selectedBinding := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if method.Sel.Name == "Selected" {
			selected, ok := call.Args[0].(*ast.Ident)
			selectedBinding = ok && selected.Name == "selected"
		}
		if method.Sel.Name != "Role" {
			return true
		}
		if role, ok := call.Args[0].(*ast.SelectorExpr); ok {
			roles[role.Sel.Name]++
		}
		return true
	})
	if roles["RoleTabList"] != 1 || roles["RoleTab"] != 1 || !selectedBinding {
		t.Fatalf("sidebar must declare a tab list and bind each tab's selected state: roles=%v selected=%v", roles, selectedBinding)
	}
}

func TestSettingsSidebarLayoutAndSelection(t *testing.T) {
	language := i18n.Current()
	defer i18n.Set(language)
	for _, locale := range []i18n.Lang{i18n.Chinese, i18n.English} {
		i18n.Set(locale)
		for _, size := range [][2]int{{860, 600}, {720, 500}, {1200, 700}} {
			for _, locked := range []bool{false, true} {
				a := previewApp()
				if locked {
					a = passwordLockedApp()
				}
				tt := ui.NewTester(a.settingsWindowView, size[0], size[1])
				tt.SetTitleBar(ui.TitleBar{Height: 50, Left: 88})
				panes := []struct {
					tab settingsTab
					key string
				}{
					{settingsTabGeneral, "settings.tab.general"},
					{settingsTabAccount, "settings.tab.account"},
					{settingsTabStorage, "app.settings.local_storage_autofill"},
					{settingsTabUpdates, "settings.tab.updates"},
					{settingsTabAbout, "settings.tab.about"},
				}
				check := func(selected settingsTab) {
					t.Helper()
					bottom := float32(52)
					for _, pane := range panes {
						label := i18n.T(pane.key)
						r, ok := tt.Find(label)
						if !ok || r.X < 0 || r.X+r.W > 220 || r.Y < bottom || r.Y+r.H > float32(size[1]) {
							t.Fatalf("%s %v locked=%v: sidebar %q overlaps or leaves sidebar: %+v", locale, size, locked, label, r)
						}
						bottom = r.Y + r.H
						pixel := tt.Image().RGBAAt(int(r.X+r.W-12), int(r.Y+r.H/2))
						white := pixel.R == 255 && pixel.G == 255 && pixel.B == 255
						if white != (pane.tab == selected) {
							t.Fatalf("%s %v: %s highlight does not match selected %s", locale, size, pane.tab, selected)
						}
					}
					texts := tt.Texts()
					// The tab-list label and each item's label/text precede the detail title.
					if len(texts) < 12 || texts[11] != i18n.T(panes[settingsPaneIndex(selected)].key) {
						t.Fatalf("detail toolbar did not follow selected %s: %q", selected, texts)
					}
				}
				check(settingsTabAccount)
				for _, pane := range panes {
					uitest.Click(t, tt, i18n.T(pane.key))
					if a.windows.settingsTab != pane.tab {
						t.Fatalf("sidebar click did not select %s", pane.tab)
					}
					check(pane.tab)
					for _, text := range tt.Texts()[12:] {
						r, ok := tt.Find(text)
						if !ok || r.X < 220 || r.W == 0 || r.H == 0 {
							continue
						}
						if r.X < 245 || r.X+r.W > float32(size[0]-24)+1 || r.Y < 52 {
							t.Fatalf("%s %v locked=%v panel=%s: detail text %q outside content: %+v", locale, size, locked, pane.tab, text, r)
						}
					}
				}
			}
		}
	}
}

func settingsPaneIndex(tab settingsTab) int {
	for i, pane := range []settingsTab{settingsTabGeneral, settingsTabAccount, settingsTabStorage, settingsTabUpdates, settingsTabAbout} {
		if tab == pane {
			return i
		}
	}
	return -1
}
