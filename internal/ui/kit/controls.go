// SPDX-License-Identifier: GPL-3.0-only
package kit

import "github.com/egoist/mygo/ui"

// The controls below are the app's one look for interaction, built on the
// headless bases of MyGo so the keyboard, focus and accessibility stay
// native: buttons of four kinds, a segmented switch between modes, choice
// cards for one option of a few, check and switch rows, form fields,
// notices, page headers and the action bar at the foot of a page.
//
// Selection is purple; the one primary action of a page is ink. Controls
// are rounded rectangles of ControlRadius, cards of CardRadius.

const (
	ControlHeight float32 = 32
	ControlRadius float32 = 9
	CardRadius    float32 = 14
)

var (
	// ControlBorder outlines buttons, inputs and unselected cards.
	ControlBorder = ui.Hex("#DCD8E6")
	// Selected tints what is chosen: a choice card, a checked row.
	Selected = ui.Hex("#F5F2FD")
	Danger   = ui.Hex("#B3261E")
	hover    = ui.RGBA(38, 30, 62, .05)
	press    = ui.RGBA(38, 30, 62, .1)
)

// ButtonKind is the weight of a button.
type ButtonKind int

const (
	// ButtonSecondary is an outlined button, for most actions.
	ButtonSecondary ButtonKind = iota
	// ButtonPrimary is the filled main action; one per page or group.
	ButtonPrimary
	// ButtonQuiet has no fill until hovered, for actions inside rows and links.
	ButtonQuiet
	// ButtonDanger is an outlined red button for actions that destroy data.
	ButtonDanger
)

// Button is the app's button: a symbol (or none) and a label, hugging its
// content. Chain Height(38) for the large buttons of single-column forms.
func Button(c *ui.Context, label, symbol string, kind ButtonKind, disabled bool) ui.Element {
	b := ui.ButtonBase(c).Label(label).Height(ControlHeight).Padding(0, 14).Gap(6).Radius(ControlRadius).
		Shrink(0).Justify(ui.Center).AlignItems(ui.Center).Disabled(disabled)
	pressed, hovered := !disabled && b.Pressed(), !disabled && b.Hovered()
	switch kind {
	case ButtonPrimary:
		b.Background(Ink).TextColor(White).Shadow(0, 1, 2, 0, ui.RGBA(41, 41, 47, .18))
		if pressed {
			b.Background(ui.Hex("#17171C"))
		} else if hovered {
			b.Background(ui.Hex("#41414B"))
		}
	case ButtonQuiet:
		b.TextColor(Purple).Padding(0, 10)
		if pressed {
			b.Background(ui.RGBA(117, 97, 170, .16))
		} else if hovered {
			b.Background(ui.RGBA(117, 97, 170, .08))
		}
	case ButtonDanger:
		b.Background(White).Border(1, ui.Hex("#EFD3D1")).TextColor(Danger)
		if pressed {
			b.Background(ui.Hex("#F9E1DF"))
		} else if hovered {
			b.Background(ui.Hex("#FDF1F0"))
		}
	default:
		b.Background(White).Border(1, ControlBorder).TextColor(Ink)
		if pressed {
			b.Background(Lavender)
		} else if hovered {
			b.Background(ui.Hex("#F8F7FB"))
		}
	}
	if disabled {
		b.Opacity(.45)
	}
	return b.Children(func() {
		if symbol != "" {
			Icon(c, symbol, 15)
		}
		ui.Text(c, label).FontSize(13).FontWeight(550).SingleLine()
	})
}

// Segmented switches between the modes of a page, such as export and
// import. Give c a key (c.Key("mode")): the control keeps state.
func Segmented(c *ui.Context, selected *int, labels ...string) ui.Element {
	seg := ui.SegmentedBase(c, selected, len(labels))
	seg.Track.Height(ControlHeight).Padding(3).Gap(2).Radius(ControlRadius).Background(ui.RGBA(38, 30, 62, .07)).Children(func() {
		for i, label := range labels {
			s := seg.Segment(i).Grow(1).Height(ControlHeight-6).Padding(0, 14).Radius(ControlRadius - 2).
				Justify(ui.Center).AlignItems(ui.Center).Label(label).TextColor(Muted)
			if i == *selected {
				s.Background(White).TextColor(Ink).Shadow(0, 1, 3, 0, ui.RGBA(38, 30, 62, .12))
			} else if s.Hovered() {
				s.TextColor(Ink)
			}
			s.Children(func() {
				t := ui.Text(c, label).FontSize(13).SingleLine()
				if i == *selected {
					t.FontWeight(600)
				}
			})
		}
	})
	return seg.Track
}

// ChoiceGroup holds the Choice cards of one choice, one stop of Tab whose
// arrows move the choice.
func ChoiceGroup(c *ui.Context, label string, fn func()) ui.Element {
	return ui.RadioGroup(c, fn).Gap(8).Label(label)
}

// Choice is one option of a single choice as a card: a radio mark, an
// optional symbol, a title and an optional detail. Put the cards of one
// choice in a ChoiceGroup.
func Choice[T comparable](c *ui.Context, selected *T, value T, title, detail, symbol string, disabled bool) ui.Element {
	on := *selected == value
	card := ui.RadioBase(c, selected, value).Label(title).Padding(12, 14).Gap(12).Radius(CardRadius-2).
		AlignItems(ui.Center).Background(White).Border(1, ControlBorder).Disabled(disabled)
	if on {
		card.Background(Selected).Border(1.5, Purple)
	} else if !disabled && card.Hovered() {
		card.Background(ui.Hex("#FBFAFD"))
	}
	if disabled {
		card.Opacity(.5)
	}
	return card.Children(func() {
		radioMark(c, on)
		if symbol != "" {
			icon := Icon(c, symbol, 20).TextColor(Muted)
			if on {
				icon.TextColor(Purple)
			}
		}
		ui.Column(c).Grow(1).MinWidth(0).Gap(3).Children(func() {
			ui.Text(c, title).FontSize(13.5).FontWeight(600)
			if detail != "" {
				ui.Text(c, detail).FontSize(12).LineHeight(1.4).TextColor(Muted).MaxLines(3)
			}
		})
	})
}

func radioMark(c *ui.Context, on bool) {
	mark := ui.Row(c).Size(18, 18).Shrink(0).Radius(9).Justify(ui.Center).AlignItems(ui.Center).Border(1.5, ui.Hex("#C4BFD3")).Background(White)
	if on {
		mark.Border(0, ui.Transparent).Background(Purple).Children(func() {
			ui.Box(c).Size(8, 8).Radius(4).Background(White)
		})
	}
}

func checkMark(c *ui.Context, on bool) {
	mark := ui.Row(c).Size(18, 18).Shrink(0).Radius(5).Justify(ui.Center).AlignItems(ui.Center).Border(1.5, ui.Hex("#C4BFD3")).Background(White)
	if on {
		mark.Border(0, ui.Transparent).Background(Purple).TextColor(White).Children(func() { Icon(c, "check", 13) })
	}
}

// Checkbox is a check box and its label, inline in a form.
func Checkbox(c *ui.Context, checked *bool, label string, disabled bool) ui.Element {
	b := ui.CheckboxBase(c, checked).Label(label).Gap(9).AlignItems(ui.Center).Padding(4, 0).Disabled(disabled)
	if disabled {
		b.Opacity(.45)
	}
	return b.Children(func() {
		checkMark(c, *checked)
		ui.Text(c, label).FontSize(13).MaxLines(3)
	})
}

// CheckRow is a row of a list to pick several from: a check box, a title,
// and a detail at the trailing edge. Rows are 40 tall, for ui.List.
func CheckRow(c *ui.Context, checked *bool, title, detail string, disabled bool) ui.Element {
	row := ui.CheckboxBase(c, checked).Label(title).Height(40).Padding(0, 12).Gap(10).Radius(ControlRadius).
		AlignItems(ui.Center).Disabled(disabled)
	// The check box shows the choice; a fill on every checked row of a long
	// list reads as one block. Hover alone highlights, as in the main list.
	if !disabled && row.Pressed() {
		row.Background(press)
	} else if !disabled && row.Hovered() {
		row.Background(hover)
	}
	if disabled {
		row.Opacity(.45)
	}
	return row.Children(func() {
		checkMark(c, *checked)
		ui.Text(c, title).FontSize(13).Grow(1).MinWidth(0).SingleLine()
		if detail != "" {
			ui.Text(c, detail).FontSize(12).TextColor(Muted).Shrink(1).MinWidth(0).SingleLine()
		}
	})
}

// SwitchRow is a setting that applies at once: a title, an optional
// detail, and a switch at the trailing edge; the whole row toggles it.
func SwitchRow(c *ui.Context, on *bool, title, detail string, disabled bool) ui.Element {
	row := ui.SwitchBase(c, on).Label(title).Padding(10, 0).Gap(16).AlignItems(ui.Center).Disabled(disabled)
	if disabled {
		row.Opacity(.45)
	}
	return row.Children(func() {
		ui.Column(c).Grow(1).MinWidth(0).Gap(3).Children(func() {
			ui.Text(c, title).FontSize(13).FontWeight(550)
			if detail != "" {
				ui.Text(c, detail).FontSize(12).LineHeight(1.4).TextColor(Muted).MaxLines(3)
			}
		})
		track := ui.Row(c).Size(36, 21).Shrink(0).Radius(10.5).Padding(2.5).Background(ui.Hex("#D9D5E3"))
		if *on {
			track.Background(Purple).Justify(ui.End)
		}
		track.Children(func() {
			ui.Box(c).Size(16, 16).Radius(8).Background(White).Shadow(0, 1, 2, 0, ui.RGBA(0, 0, 0, .2))
		})
	})
}

// Field is a labeled form control: the label above, the control content
// builds, and an optional hint below.
func Field(c *ui.Context, label, hint string, content func()) ui.Element {
	return ui.Column(c).Gap(6).Children(func() {
		if label != "" {
			ui.Text(c, label).FontSize(12).FontWeight(600).TextColor(Ink)
		}
		content()
		if hint != "" {
			ui.Text(c, hint).FontSize(11.5).LineHeight(1.4).TextColor(Muted).MaxLines(4)
		}
	})
}

// Input styles a text input of a page or editor (FormInput is the login
// pages' larger, round one).
func Input(e ui.Element) ui.Element {
	return e.Height(ControlHeight+2).Padding(0, 12).Radius(ControlRadius).Background(White).Border(1, ControlBorder)
}

// Tone colors a Notice.
type Tone int

const (
	ToneInfo Tone = iota
	ToneWarning
	ToneDanger
	ToneSuccess
)

// Notice is a message that stays on the page: what to know before an
// action, a warning, an error or an outcome.
func Notice(c *ui.Context, tone Tone, text string) ui.Element {
	bg, fg, symbol := ui.Hex("#F1EEFA"), ui.Hex("#5A4A8C"), "info"
	switch tone {
	case ToneWarning:
		bg, fg, symbol = ui.Hex("#FDF5E4"), ui.Hex("#80570A"), "alert"
	case ToneDanger:
		bg, fg, symbol = ui.Hex("#FCEDEC"), ui.Hex("#9B231C"), "alert"
	case ToneSuccess:
		bg, fg, symbol = ui.Hex("#EAF5EE"), ui.Hex("#1F6B3A"), "check"
	}
	return ui.Row(c).Padding(10, 12).Gap(10).Radius(ControlRadius + 1).Background(bg).TextColor(fg).AlignItems(ui.Start).Children(func() {
		Icon(c, symbol, 16).Shrink(0).Margin(1, 0, 0, 0)
		ui.Text(c, text).FontSize(12).LineHeight(1.45).Grow(1).MinWidth(0)
	})
}

// PageHeader titles a page or a window's content, with a subtitle and
// trailing controls such as a Segmented.
func PageHeader(c *ui.Context, title, subtitle string, trailing func()) ui.Element {
	return ui.Column(c).Gap(5).Shrink(0).Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			ui.Text(c, title).FontSize(20).FontWeight(650).Grow(1).MinWidth(0).SingleLine()
			if trailing != nil {
				trailing()
			}
		})
		if subtitle != "" {
			ui.Text(c, subtitle).FontSize(12.5).LineHeight(1.45).TextColor(Muted).MaxLines(4)
		}
	})
}

// Section groups related controls in a white card under a title.
func Section(c *ui.Context, title string, content func()) ui.Element {
	return ui.Column(c).Gap(8).Children(func() {
		if title != "" {
			ui.Text(c, title).Padding(0, 4).FontSize(12.5).FontWeight(600).TextColor(Muted)
		}
		ui.Column(c).Padding(14, 16).Gap(12).Background(White).Radius(CardRadius).Border(1, Line).Children(content)
	})
}

// ActionBar is the foot of a page or window: status at the leading edge,
// its actions at the trailing edge (put a ui.Spacer before them), below a
// hairline across the content. It has no fill of its own, so it sits on the
// window as the content does instead of floating as a box.
func ActionBar(c *ui.Context, content func()) ui.Element {
	return ui.Row(c).Shrink(0).Padding(14, 0, 0, 0).Gap(8).AlignItems(ui.Center).
		DrawOver(func(p *ui.Painter, r ui.Rect) { p.Fill(ui.Rect{X: r.X, Y: r.Y, W: r.W, H: 1}, Line, 0) }).Children(content)
}

// EmptyState fills a page that has nothing to show yet.
func EmptyState(c *ui.Context, symbol, title, detail string) ui.Element {
	return ui.Column(c).Grow(1).Padding(32).Gap(10).Justify(ui.Center).AlignItems(ui.Center).Children(func() {
		ui.Row(c).Size(56, 56).Radius(18).Justify(ui.Center).AlignItems(ui.Center).Background(White).Children(func() {
			Icon(c, symbol, 26).TextColor(Purple)
		})
		ui.Text(c, title).FontSize(15).FontWeight(600).TextAlign(ui.Center)
		if detail != "" {
			ui.Text(c, detail).FontSize(12.5).LineHeight(1.5).TextColor(Muted).TextAlign(ui.Center).MaxLines(4)
		}
	})
}
