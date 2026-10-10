// SPDX-License-Identifier: GPL-3.0-only

// Package kit holds the shared MyGo UI theme, icons and generic widgets used
// by the application shell and every domain panel.
package kit

import (
	"github.com/egoist/mygo/ui"
)

var (
	Ink      = ui.Hex("#29292F")
	Muted    = ui.Hex("#777681")
	Panel    = ui.Hex("#F4F3F8")
	White    = ui.Hex("#FFFFFF")
	Lavender = ui.Hex("#EAE5FA")
	Purple   = ui.Hex("#7561AA")
	Line     = ui.Hex("#E7E5ED")
	Theme    = makeVaultTheme()
)

func makeVaultTheme() *ui.Theme {
	t := ui.LightTheme()
	t.Background, t.Surface = Panel, White
	t.Text, t.TextMuted, t.Border = Ink, Muted, Line
	t.Accent, t.AccentHover, t.AccentPressed = Ink, ui.Hex("#41414B"), ui.Hex("#17171C")
	t.SurfaceHover, t.SurfacePressed = ui.Hex("#EFECF7"), Lavender
	t.Selection, t.Focus = ui.RGBA(142, 121, 198, .2), ui.RGBA(117, 97, 170, .55)
	t.FontSize, t.Radius = 14, 16
	t.Scrollbar, t.ScrollbarWidth = ui.RGBA(38, 30, 62, .22), 5
	return t
}

func Pill(c *ui.Context, text string, bg, fg ui.Color) {
	ui.Text(c, text).FontSize(11).TextColor(fg).Background(bg).Padding(5, 10).Radius(20).Shrink(0)
}

func Action(c *ui.Context, label, symbol string, primary, disabled bool) ui.Element {
	var b ui.Element
	if primary {
		b = ui.PrimaryButton(c, "")
	} else {
		b = ui.Button(c, "")
	}
	b.Label(label).Height(38).Padding(0, 14).Radius(20).Border(0, ui.Transparent).Disabled(disabled).Children(func() {
		if symbol != "" {
			Icon(c, symbol, 17)
		}
		ui.Text(c, label).FontSize(13)
	})
	return b
}

func IconButton(c *ui.Context, label, symbol string) ui.Element {
	return ui.Button(c, "").Label(label).Tooltip(label).Size(36, 36).Padding(8).Radius(18).Border(0, ui.Transparent).
		Children(func() { Icon(c, symbol, 18) })
}

// titleBarButton is a borderless toolbar icon button, like the sidebar toggle
// of native macOS apps: no fill until hovered, sitting on the title bar row.
func TitleBarButton(c *ui.Context, label, symbol string) ui.Element {
	b := ui.ButtonBase(c).Label(label).Tooltip(label).Size(28, 28).Padding(5).Radius(7).Shrink(0).TextColor(Muted)
	if b.Pressed() {
		b.Background(ui.RGBA(38, 30, 62, .12)).TextColor(Ink)
	} else if b.Hovered() {
		b.Background(ui.RGBA(38, 30, 62, .07)).TextColor(Ink)
	}
	return b.Children(func() { Icon(c, symbol, 18) })
}

func ToolbarButton(c *ui.Context, label, symbol string, primary, disabled bool) ui.Element {
	var b ui.Element
	if primary {
		b = ui.PrimaryButton(c, "")
	} else {
		b = ui.Button(c, "")
	}
	b.Label(label).Height(32).Padding(0, 13).Gap(6).Radius(16).Disabled(disabled).Children(func() {
		Icon(c, symbol, 15)
		ui.Text(c, label).FontSize(13)
	})
	if !primary {
		b.Border(1, ui.RGBA(255, 255, 255, .7)).Background(ui.RGBA(255, 255, 255, .55))
	} else {
		b.Border(0, ui.Transparent)
	}
	return b
}

var (
	SidebarBackground = ui.Hex("#F2F1F7")
	sidebarText       = ui.Hex("#3E3D47")
	sidebarIcon       = ui.Hex("#86858F")
	SidebarFaint      = ui.Hex("#A4A3AE")
)

// sidebarAction is a quiet inline button beside a sidebar section title.
func SidebarAction(c *ui.Context, label, symbol string, disabled bool) ui.Element {
	b := ui.ButtonBase(c).Label(label).Tooltip(label).Size(22, 22).Padding(4).Radius(6).Shrink(0).Disabled(disabled).TextColor(sidebarIcon)
	if disabled {
		b.Opacity(.45)
	} else if b.Pressed() {
		b.Background(ui.RGBA(38, 30, 62, .1)).TextColor(Ink)
	} else if b.Hovered() {
		b.Background(ui.RGBA(38, 30, 62, .06)).TextColor(Ink)
	}
	return b.Children(func() { Icon(c, symbol, 14) })
}

// sidebarItem is a source-list row: a soft rounded rectangle, a tinted icon
// when selected, and a quiet trailing count instead of a badge.
func SidebarItem(c *ui.Context, title, symbol, count string, selected, disabled, collapsed bool) ui.Element {
	b := ui.ButtonBase(c).Label(title).Height(32).Padding(0, 10).Gap(10).Radius(9).Disabled(disabled).TextColor(sidebarText)
	if collapsed {
		b.Tooltip(title).Height(36).Padding(0).Justify(ui.Center)
	}
	iconColor := sidebarIcon
	if selected {
		b.Background(White).TextColor(Ink).Shadow(0, 1, 3, 0, ui.RGBA(38, 30, 62, .08))
		iconColor = Purple
	} else if disabled {
		b.Opacity(.45)
	} else if b.Pressed() {
		b.Background(ui.RGBA(38, 30, 62, .08))
	} else if b.Hovered() {
		b.Background(ui.RGBA(38, 30, 62, .045))
	}
	b.Children(func() {
		Icon(c, symbol, 17).TextColor(iconColor)
		if collapsed {
			return
		}
		text := ui.Text(c, title).Grow(1).MinWidth(0).FontSize(13).SingleLine()
		if selected {
			text.FontWeight(600)
		}
		if count != "" {
			badge := ui.Text(c, count).FontSize(11).TextColor(SidebarFaint).Shrink(0)
			if selected {
				badge.TextColor(Purple)
			}
		}
	})
	return b
}

func NavItem(c *ui.Context, title, symbol, count string, selected, disabled bool) ui.Element {
	return navigationItem(c, title, symbol, count, selected, disabled, false)
}

func navigationItem(c *ui.Context, title, symbol, count string, selected, disabled, collapsed bool) ui.Element {
	b := ui.ButtonBase(c).Label(title).Height(32).Padding(0, 11).Gap(10).Radius(20).Disabled(disabled).TextColor(Muted)
	if collapsed {
		b.Tooltip(title).Justify(ui.Center)
	}
	if selected {
		b.Background(White).TextColor(Ink).Shadow(0, 2, 6, 0, ui.RGBA(38, 30, 62, .06))
	} else if b.Hovered() && !disabled {
		b.Background(ui.RGBA(255, 255, 255, .6))
	}
	if disabled {
		b.Opacity(.5)
	}
	b.Children(func() {
		Icon(c, symbol, 18)
		if collapsed {
			return
		}
		ui.Text(c, title).Grow(1).FontSize(13).SingleLine()
		if count != "" {
			ui.Text(c, count).FontSize(11).Background(ui.RGBA(255, 255, 255, .7)).Padding(2, 6).Radius(9)
		}
	})
	return b
}

func DetailCard(c *ui.Context, title string, content func()) {
	ui.Column(c).Gap(8).Padding(10).Background(Panel).Radius(24).Children(func() {
		ui.Text(c, title).Padding(3, 6).FontSize(14).FontWeight(550)
		ui.Column(c).Background(White).Radius(16).Clip().Children(content)
	})
}

func DetailField(c *ui.Context, label, value, empty string) {
	ui.Column(c).Gap(8).Padding(12, 16).Children(func() {
		ui.Text(c, label).FontSize(11).TextColor(Muted)
		if value == "" {
			ui.Text(c, empty).FontSize(14).TextColor(Muted)
		} else {
			ui.Text(c, value).FontSize(14).MaxLines(3).Tooltip(value)
		}
	})
}
