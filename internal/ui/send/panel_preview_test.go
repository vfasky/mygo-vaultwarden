// SPDX-License-Identifier: GPL-3.0-only
package send

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func previewSendPanel() *Panel {
	// Rendering-only session marker; callbacks never dispatch a network operation.
	return NewPanel(&vaultwarden.Session{}, nil, nil, vaultwarden.Scope{}, Host{Dispatch: func(f func()) { f() }, Check: func() error { return nil }})
}

func TestPanelsSendVisualPreviews(t *testing.T) {
	dir := os.Getenv("MYGO_UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MYGO_UI_PREVIEW_DIR to export Send previews")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer i18n.Set(i18n.Current())
	for _, lang := range []i18n.Lang{i18n.Chinese, i18n.English} {
		i18n.Set(lang)
		suffix := "zh"
		if lang == i18n.English {
			suffix = "en"
		}
		for _, state := range []string{"empty", "list", "new-text", "new-file"} {
			p := previewSendPanel()
			defer p.Close()
			fields := vaultwarden.SendFields{Name: "Trip details", Text: "Meeting at 10:00 in the lobby.", DeletionDate: time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)}
			switch state {
			case "list":
				p.Rows = []*vaultwarden.SendDraft{{Fields: fields}, {Fields: vaultwarden.SendFields{Name: "Travel documents", Type: 1, Disabled: true}}}
			case "new-text":
				p.installDraft(&vaultwarden.SendDraft{Fields: fields})
			case "new-file":
				p.newKind = 1
				fields.Type = 1
				fields.FileName = "travel.pdf"
				p.installDraft(&vaultwarden.SendDraft{Fields: fields})
			}
			tt := ui.NewTester(func(c *ui.Context) {
				c.SetTheme(kit.Theme)
				ui.Scroll(c).Fill().Background(kit.Panel).Children(func() {
					ui.Column(c).Padding(24).Gap(16).Children(func() { kit.PageHeader(c, i18n.T("accountcenter.send_title"), "", nil); p.View(c) })
				})
			}, 820, 900)
			save := func(name string) {
				f, err := os.Create(filepath.Join(dir, name+"-"+suffix+".png"))
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
			save("send-" + state)
			if p.Draft != nil {
				tt.Scroll(750, 700, 0, 650)
				tt.Frame()
				save("send-" + state + "-footer")
			}
		}
	}
}

func TestSendCheckboxesPreserveDraftAndBusyState(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	p := previewSendPanel()
	defer p.Close()
	p.installDraft(&vaultwarden.SendDraft{Fields: vaultwarden.SendFields{Type: 0, Name: "Public fixture"}})
	tt := ui.NewTester(p.View, 820, 1800)
	for _, label := range []string{i18n.T("send.editor.hidden_text"), i18n.T("send.editor.disabled"), i18n.T("send.editor.hide_email")} {
		if err := tt.Click(label); err != nil {
			t.Fatal(err)
		}
	}
	if !p.Fields.Hidden || !p.Fields.Disabled || !p.Fields.HideEmail {
		t.Fatal("draft checkboxes did not update fields")
	}
	p.session = &vaultwarden.Session{} // Only enable the local type selector; this test performs no network actions.
	p.Busy = true
	tt.Frame()
	if err := tt.Click(i18n.T("send.editor.file_type")); err != nil {
		t.Fatal(err)
	}
	if p.newKind != 0 {
		t.Fatal("busy panel changed the new Send type")
	}
	for _, label := range []string{i18n.T("send.editor.hidden_text"), i18n.T("send.editor.disabled"), i18n.T("send.editor.hide_email")} {
		if err := tt.Click(label); err != nil {
			t.Fatal(err)
		}
	}
	if !p.Fields.Hidden || !p.Fields.Disabled || !p.Fields.HideEmail {
		t.Fatal("busy draft was edited")
	}
	p.Close()
	tt.Frame()
	if _, ok := tt.Find(i18n.T("send.receive.link")); ok {
		t.Fatal("closed panel retained sensitive inputs")
	}
}
