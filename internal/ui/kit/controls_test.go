// SPDX-License-Identifier: GPL-3.0-only
package kit

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
)

type gallery struct {
	mode, format       int
	checked, unchecked bool
	inline, on, off    bool
	text               string
	clicks             int
}

// galleryView shows every shared control, for the behavior test and for
// the preview that MYGO_UI_PREVIEW_DIR exports.
func galleryView(g *gallery) func(c *ui.Context) {
	return func(c *ui.Context) {
		c.SetTheme(Theme)
		ui.Column(c).Fill().Gradient(ui.Hex("#EAEAEF"), ui.Hex("#DDD6EF"), 155).TextColor(Ink).Children(func() {
			ui.Column(c).Grow(1).Padding(24).Gap(16).Children(func() {
				PageHeader(c, "Import & export", "Files hold unencrypted secrets; keep them somewhere you trust.", func() {
					Segmented(c.Key("mode"), &g.mode, "Export", "Import").Width(200)
				})
				Notice(c, ToneWarning, "The export contains unencrypted passwords.")
				ChoiceGroup(c, "Format", func() {
					Choice(c, &g.format, 0, "Bitwarden JSON", "Items of types 1–7, without attachments.", "file", false)
					Choice(c, &g.format, 1, "MyGo backup", "All eight types (.mygovault).", "vault", false)
					Choice(c, &g.format, 2, "Disabled choice", "", "", true)
				})
				Section(c, "Items", func() {
					CheckRow(c, &g.checked, "github.com", "alex@example.com", false)
					CheckRow(c, &g.unchecked, "discord.com", "", false)
					Checkbox(c, &g.inline, "Include folders", false)
					SwitchRow(c, &g.on, "Check automatically", "Once a day.", false)
					SwitchRow(c, &g.off, "Disabled switch", "", true)
					Field(c, "Password", "At least 12 characters.", func() {
						Input(ui.TextInput(c, &g.text).Label("Password").Placeholder("Password")).Password()
					})
				})
				ui.Row(c).Gap(8).Children(func() {
					if Button(c, "Primary", "download", ButtonPrimary, false).Clicked() {
						g.clicks++
					}
					Button(c, "Secondary", "", ButtonSecondary, false)
					Button(c, "Quiet", "", ButtonQuiet, false)
					Button(c, "Delete", "trash", ButtonDanger, false)
					Button(c, "Disabled", "", ButtonPrimary, true)
					IconButton(c, "Close", "close")
				})
			})
			ActionBar(c, func() {
				ui.Text(c, "3 selected").FontSize(12).TextColor(Muted)
				ui.Spacer(c)
				Button(c, "Cancel", "", ButtonSecondary, false)
				Button(c, "Export", "download", ButtonPrimary, false)
			})
		})
	}
}

func TestControlsBehave(t *testing.T) {
	g := &gallery{checked: true, on: true}
	tt := ui.NewTester(galleryView(g), 760, 900)
	click := func(label string) {
		t.Helper()
		if err := tt.Click(label); err != nil {
			t.Fatal(err)
		}
	}
	click("Import")
	click("MyGo backup")
	click("discord.com")
	click("github.com")
	click("Include folders")
	click("Check automatically")
	click("Disabled switch")
	click("Disabled choice")
	click("Primary")
	click("Disabled")
	if g.mode != 1 || g.format != 1 || !g.unchecked || g.checked || !g.inline || g.on || g.off || g.clicks != 1 {
		t.Fatalf("controls did not apply the clicks: %+v", *g)
	}
}

func TestControlsPreview(t *testing.T) {
	dir := os.Getenv("MYGO_UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MYGO_UI_PREVIEW_DIR to export the control gallery")
	}
	tt := ui.NewTester(galleryView(&gallery{checked: true, on: true, text: "secret"}), 760, 900)
	f, err := os.Create(filepath.Join(dir, "kit-controls.png"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, tt.Image()); err != nil {
		t.Fatal(err)
	}
}
