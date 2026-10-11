// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// The editors open in a drawer over the vault: the vault behind it is
// inert, Escape is the editor's own cancel, and nothing is left on screen
// once the editor closes or the vault locks.
func TestEditorDrawer(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	tt := ui.NewTester(a.view, 1280, 820)
	uitest.Click(t, tt, "Fixture card")
	uitest.Click(t, tt, i18n.T("app.detail.view_edit"))
	if a.editor == nil || !tt.HasText("编辑支付卡") || !tt.HasText("Fixture card") {
		t.Fatal("editor did not open over the vault")
	}
	if r, _ := tt.Find("编辑支付卡"); r.X < 1280-680 {
		t.Fatalf("editor is not in the right-hand drawer: %+v", r)
	}
	// The toolbar behind the drawer is inert.
	editor := a.editor
	_ = tt.Click(i18n.T("app.toolbar.add"))
	if a.editor != editor {
		t.Fatal("the vault behind the drawer took a click")
	}

	a.pending = 1
	tt.Key(0, ui.KeyEscape)
	if a.editor == nil {
		t.Fatal("Escape closed the drawer while an operation ran")
	}
	a.pending = 0
	tt.Frame()
	tt.Key(0, ui.KeyEscape)
	if a.editor != nil || tt.HasText("编辑支付卡") {
		t.Fatal("Escape did not cancel the editor")
	}

	a.openFolderEditor("")
	tt.Frame()
	if !tt.HasText(i18n.T("vault.folder.close")) {
		t.Fatal("folder editor not in the drawer")
	}
	a.lockInterface()
	tt.Frame()
	if a.folderEditor != nil || tt.HasText(i18n.T("vault.folder.close")) {
		t.Fatal("lock left the drawer on screen")
	}
}

// Escape does nothing where the editor has no plain cancel: the comparison
// of a conflict keeps its explicit choices.
func TestEditorDrawerEscapeKeepsComparison(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openCipherEditor("card-1", 3)
	a.editor.comparison = &vaultwarden.CipherRebase{}
	a.cancelDrawerEditor()
	if a.editor == nil {
		t.Fatal("Escape discarded a conflict comparison")
	}
}

// The drawer slides in from the right, and closing leaves no copy behind.
func TestEditorDrawerSlidesIn(t *testing.T) {
	// A slow slide keeps the drawer moving through the first frames on any machine.
	drawerSlides, drawerSlideDuration = true, 10*time.Second
	defer func() { drawerSlides, drawerSlideDuration = false, 240*time.Millisecond }()
	a := writableUIFixture(t)
	defer a.stopNetwork()
	tt := ui.NewTester(a.view, 1280, 820)
	a.openCipherEditor("card-1", 3)
	tt.Frame()
	start, ok := tt.Find("编辑支付卡")
	if !ok {
		t.Fatal("drawer missing")
	}
	// At rest the title is 20 inside the drawer, half of the 1280 window.
	if start.X <= 1280-drawerWidthFor(1280)+20+40 {
		t.Fatalf("drawer did not start to the right of where it rests: %v", start.X)
	}
	a.editor = nil
	tt.Frame()
	if tt.HasText("编辑支付卡") {
		t.Fatal("closing left a copy of the editor on screen")
	}
}

// The editor's footer shows what happened while it was open, not the main
// window's status from before.
func TestEditorDrawerFooterShowsOnlyEditorStatus(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.status = "main window sync summary"
	a.openCipherEditor("card-1", 3)
	tt := ui.NewTester(a.view, 1280, 820)
	footer := func() bool {
		t.Helper()
		n := 0
		for _, text := range tt.Texts() {
			if text == a.status {
				n++
			}
		}
		return n > 1 // the main window's status line shows it once
	}
	if footer() {
		t.Fatal("the editor footer repeated the main window's status")
	}
	a.status = "save failed: example reason"
	tt.Frame()
	if !footer() {
		t.Fatal("the editor footer hid its own status")
	}
}
