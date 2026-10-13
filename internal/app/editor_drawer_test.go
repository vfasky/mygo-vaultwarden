// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"image/color"
	"runtime"
	"testing"
	"testing/synctest"
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
	uitest.Click(t, tt, i18n.T("app.detail.edit"))
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
	if _, ok := tt.Find(i18n.T("common.close")); !ok || !tt.HasText(i18n.T("vault.folder.add_title")) {
		t.Fatal("folder editor not in the drawer")
	}
	a.lockInterface()
	tt.Frame()
	if _, ok := tt.Find(i18n.T("common.close")); a.folderEditor != nil || ok {
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
	slides := drawerSlides
	drawerSlides = true
	defer func() { drawerSlides = slides }()
	a := writableUIFixture(t)
	defer a.stopNetwork()
	// MyGo's persistent raster workers wait on a process-wide channel.
	// Render on one worker so they cannot keep the synctest bubble alive.
	procs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(procs)
	// Frame settles up to 20 rendered frames. Use virtual time so a slow
	// renderer (especially under -race) cannot finish the animation before
	// we inspect its starting position.
	synctest.Test(t, func(t *testing.T) {
		tt := ui.NewTester(a.view, 1280, 820)
		a.openCipherEditor("card-1", 3)
		tt.Frame()
		start, ok := tt.Find("编辑支付卡")
		if !ok {
			t.Fatal("drawer missing")
		}
		// At rest the title is 20 inside the drawer.
		restX := 1280 - drawerWidthFor(1280) + 20
		if start.X <= restX+40 {
			t.Fatalf("drawer did not start to the right of where it rests: %v", start.X)
		}
		time.Sleep(drawerSlideDuration)
		tt.Frame()
		end, ok := tt.Find("编辑支付卡")
		if !ok || end.X != restX {
			t.Fatalf("drawer did not settle at %v: %+v (found=%v)", restX, end, ok)
		}
		a.editor = nil
		tt.Frame()
		if tt.HasText("编辑支付卡") {
			t.Fatal("closing left a copy of the editor on screen")
		}
	})
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

// The title bar keeps only app-wide state, its buttons alike in height; list
// actions sit on the list header and import/export at the sidebar's foot.
func TestToolbarActionPlacement(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	tt := ui.NewTester(a.view, 1280, 820)
	tt.Frame()
	sync, _ := tt.Find(i18n.T("common.sync"))
	lock, _ := tt.Find(i18n.T("common.lock"))
	settings, ok := tt.Find(i18n.T("app.window.settings_title"))
	if !ok || sync.H != lock.H || settings.H != sync.H || settings.W != settings.H {
		t.Fatalf("title bar buttons differ: sync=%+v lock=%+v settings=%+v", sync, lock, settings)
	}
	backup, ok := tt.Find(i18n.T("app.toolbar.import_export"))
	account, _ := tt.Find(i18n.T("app.window.account_center_title"))
	if !ok || backup.X+backup.W > a.sidebarWidth(nil) || backup.X < account.X+account.W || backup.Y+backup.H/2 < account.Y || backup.Y+backup.H/2 > account.Y+account.H {
		t.Fatalf("import/export not beside the account center: %+v account=%+v", backup, account)
	}
	bulk, ok := tt.Find(i18n.T("vault.bulk.title"))
	if !ok || bulk.Y > sync.Y+sync.H+80 || bulk.X < a.sidebarWidth(nil) || bulk.X > 700 {
		t.Fatalf("bulk action not on the list header: %+v", bulk)
	}
	if _, ok := tt.Find(i18n.T("app.toolbar.empty_trash")); ok {
		t.Fatal("empty trash shown outside the trash")
	}
	uitest.Click(t, tt, i18n.T("vault.bulk.title"))
	if a.bulkEditor == nil {
		t.Fatal("bulk action did not open the editor")
	}
	a.bulkEditor = nil
	a.category = "trash"
	tt.Frame()
	uitest.Click(t, tt, i18n.T("app.toolbar.empty_trash"))
	if a.bulkEditor == nil {
		t.Fatal("empty trash did not open the editor")
	}
	a.bulkEditor = nil
	tt.Frame()
	uitest.Click(t, tt, i18n.T("app.toolbar.import_export"))
	if a.backupEditor == nil {
		t.Fatal("import/export did not open the editor")
	}
}

// The drawer's close button tints under the pointer like other icon buttons.
func TestEditorDrawerCloseHover(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openBulkEditor(false)
	tt := ui.NewTester(a.view, 1280, 820)
	tt.Frame()
	r, ok := tt.Find(i18n.T("common.close"))
	if !ok {
		t.Fatal("close button missing")
	}
	at := func() color.Color { return tt.Image().At(int(r.X+r.W/2), int(r.Y+3)) }
	before := at()
	tt.Move(r.X+r.W/2, r.Y+r.H/2)
	tt.Frame()
	if after := at(); after == before {
		t.Fatalf("close button did not react to hover: %v", after)
	}
}
