// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
)

// settingsWindowOptions are the Settings window's native options;
// showSettingsWindow adds its StateKey and Content.
func settingsWindowOptions() mygo.WindowOptions {
	return mygo.WindowOptions{
		Title: i18n.T("app.window.settings_title"), Width: 860, Height: 600, MinWidth: 720, MinHeight: 500,
		TitleBarStyle: mygo.TitleBarHiddenInset, TrafficLightPosition: &mygo.Point{X: 18, Y: 18},
	}
}

// settingsWindowView is the Settings window (⌘,).
func (a *app) settingsWindowView(c *ui.Context) {
	a.framePrelude(c)
	c.SetTheme(kit.Theme)
	panes := []struct {
		tab         settingsTab
		label, icon string
	}{
		{settingsTabGeneral, i18n.T("settings.tab.general"), "globe"},
		{settingsTabAccount, i18n.T("settings.tab.account"), "user"},
		{settingsTabStorage, i18n.T("app.settings.local_storage_autofill"), "vault"},
		{settingsTabUpdates, i18n.T("settings.tab.updates"), "sync"},
		{settingsTabAbout, i18n.T("settings.tab.about"), "shield"},
	}
	current := a.windows.settingsTab
	if current == "" {
		current = settingsTabAccount
	}
	row, below := titleBarRow(c.TitleBar())
	ui.Row(c).Fill().TextColor(kit.Ink).AlignItems(ui.Stretch).Children(func() {
		ui.Column(c).Width(220).Shrink(0).Background(kit.SidebarBackground).Children(func() {
			ui.Box(c).Height(row + below).Shrink(0).DragWindow()
			ui.Column(c).Gap(4).Padding(4, 10, 12, 10).
				Role(ui.RoleTabList).Label(i18n.T("app.window.settings_title")).Children(func() {
				for _, pane := range panes {
					selected := current == pane.tab
					tab := ui.ButtonBase(c.Key(string(pane.tab))).Role(ui.RoleTab).Selected(selected).Label(pane.label).
						MinHeight(32).Padding(7, 10).Gap(10).Radius(9).AlignItems(ui.Center).TextColor(ui.Hex("#3E3D47"))
					iconColor := ui.Hex("#86858F")
					if selected {
						tab.Background(kit.White).TextColor(kit.Ink).Shadow(0, 1, 3, 0, ui.RGBA(38, 30, 62, .08))
						iconColor = kit.Purple
					} else if tab.Pressed() {
						tab.Background(ui.RGBA(38, 30, 62, .08))
					} else if tab.Hovered() {
						tab.Background(ui.RGBA(38, 30, 62, .045))
					}
					tab.Children(func() {
						kit.Icon(c, pane.icon, 17).TextColor(iconColor).Shrink(0)
						text := ui.Text(c, pane.label).Grow(1).MinWidth(0).FontSize(13).MaxLines(2)
						if selected {
							text.FontWeight(600)
						}
					})
					if tab.Clicked() {
						a.windows.settingsTab = pane.tab
						current = pane.tab
					}
				}
			})
		})
		ui.Box(c).Width(1).Shrink(0).Background(kit.Line)
		ui.Column(c).Grow(1).MinWidth(0).Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).Children(func() {
			ui.Row(c).Height(row+below).Shrink(0).AlignItems(ui.Center).
				Padding(0, 24, below, 24).DragWindow().Children(func() {
				for _, pane := range panes {
					if pane.tab == current {
						ui.Text(c, pane.label).FontSize(15).FontWeight(600).TextColor(kit.Ink).SingleLine()
						break
					}
				}
			})
			ui.Column(c).Grow(1).MinHeight(0).Padding(0, 24, 18, 24).AlignItems(ui.Center).Children(func() {
				ui.Column(c).WidthPercent(100).MaxWidth(640).Grow(1).MinHeight(0).Children(func() { a.settings(c) })
			})
		})
	})
}
