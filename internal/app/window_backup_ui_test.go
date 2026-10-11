// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/organization"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func backupWindowFixture(t *testing.T) *app {
	t.Helper()
	a := writableUIFixture(t)
	t.Cleanup(a.stopNetwork)
	a.items = previewApp().items
	a.status = ""
	a.openBackupEditor()
	return a
}

func backupPreviewPlan(t *testing.T) *vaultwarden.ImportPlan {
	t.Helper()
	plan, err := vaultwarden.ParseImport([]byte(`{"encrypted":false,"folders":[{"id":"00000000-0000-0000-0000-000000000001","name":"Personal"}],"items":[{"id":"00000000-0000-0000-0000-000000000002","type":1,"name":"GitHub","favorite":false,"login":{"username":"alex-dev","password":"example"}},{"id":"00000000-0000-0000-0000-000000000003","type":2,"favorite":false,"name":"Travel notes","secureNote":{"type":0},"notes":"Example only"}]}`), vaultwarden.BitwardenJSON)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plan.Clear)
	return plan
}

func TestBackupWindowControls(t *testing.T) {
	a := backupWindowFixture(t)
	e := a.backupEditor
	tt := ui.NewTester(a.backupWindowView, 760, 680)
	click := func(key string) { t.Helper(); uitest.Click(t, tt, i18n.T(key)) }
	click("backup.import.switch_mode")
	if !e.importing {
		t.Fatal("segment did not select import")
	}
	click("backup.export.switch_mode")
	if e.importing || e.format != vaultwarden.BitwardenJSON {
		t.Fatal("mode choice not applied")
	}
	click("backup.export.select_none")
	for _, yes := range e.selected {
		if yes {
			t.Fatal("deselect all retained selection")
		}
	}
	click("backup.export.select_all")
	if e.selected["1"] != true || e.selected["8"] != true {
		t.Fatal("select all missed items")
	}
	uitest.Click(t, tt, "Apple")
	if e.selected["1"] {
		t.Fatal("check row did not deselect")
	}
	click("backup.export.search")
	tt.Type("alex-dev")
	if !tt.HasText("GitHub") || tt.HasText("Figma") {
		t.Fatal("search did not filter usernames")
	}
	if e.selected["1"] || !e.selected["2"] {
		t.Fatal("search changed selection")
	}
	click("backup.export.select_current")
	if !e.selected["1"] || !e.selected["2"] {
		t.Fatal("current main list was replaced by search results")
	}
	click("backup.export.continue")
	_, modeVisible := tt.Find(i18n.T("backup.import.switch_mode"))
	if !e.confirm || modeVisible {
		t.Fatal("confirmation permits mode switch")
	}
	e.exportPassword = "example password"
	epoch := a.epoch
	cancelled := false
	a.cancel = func() { cancelled = true }
	click("backup.editor.cancel_close")
	if a.windows.backupOpen || a.backupEditor != nil || e.exportPassword != "" || !cancelled || a.epoch <= epoch {
		t.Fatal("cancel did not close and clear window state")
	}
}

func TestBackupWindowModesStayFixed(t *testing.T) {
	for _, state := range []string{"busy", "preview", "submitted"} {
		t.Run(state, func(t *testing.T) {
			a := backupWindowFixture(t)
			e := a.backupEditor
			e.importing = true
			switch state {
			case "busy":
				a.pending = 1
			case "preview":
				e.plan = backupPreviewPlan(t)
			case "submitted":
				e.submitted = true
			}
			tt := ui.NewTester(a.backupWindowView, 760, 680)
			if _, found := tt.Find(i18n.T("backup.export.switch_mode")); found {
				t.Fatal("mode switch remains available")
			}
		})
	}
}

func TestBackupWindowLockedHidesMetadata(t *testing.T) {
	a := backupWindowFixture(t)
	a.showLogin = true
	tt := ui.NewTester(a.backupWindowView, 760, 680)
	if tt.HasText("Apple") || tt.HasText("alex@example.com") || tt.HasText(i18n.T("backup.export.search")) {
		t.Fatal("locked window exposed vault metadata")
	}
	if !tt.HasText(i18n.T("app.list.status_locked")) {
		t.Fatal("missing lock placeholder")
	}
}

func TestBackupWindowVisualPreviews(t *testing.T) {
	dir := os.Getenv("MYGO_UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MYGO_UI_PREVIEW_DIR to export backup previews")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"export", "export-password", "import-empty", "import-preview", "import-results", "resources", "resource-restore", "share-recovery", "locked", "export-english", "export-small", "export-empty", "import-no-receipts"} {
		t.Run(name, func(t *testing.T) {
			a := backupWindowFixture(t)
			e := a.backupEditor
			switch name {
			case "export-empty":
				e.candidates = nil
			case "import-no-receipts":
				e.importing, e.submitted = true, true
			case "export-password":
				e.confirm = true
				e.candidates[0].RequiresPassword = true
				e.selected[e.candidates[0].ID] = true
				e.exportPassword = "preview only"
			case "import-empty":
				e.importing = true
			case "import-preview":
				e.importing = true
				e.plan = backupPreviewPlan(t)
			case "import-results":
				e.importing = true
				e.submitted = true
				e.results = []vaultwarden.ImportEntry{{Kind: vaultwarden.ImportKindItem, Name: "GitHub", State: vaultwarden.ImportStateCreatedPendingSync}, {Kind: vaultwarden.ImportKindFolder, Name: "Personal", State: vaultwarden.ImportStateCreated}}
			case "resources":
				e.format = vaultwarden.MyGoResources
			case "resource-restore":
				e.importing, e.submitted = true, true
				e.resources = &backupResourceEditor{rows: []organization.ResourceRow{{Resource: vaultwarden.BackupResource{FileName: "example.pdf", CipherID: "source-item", AttachmentID: "source-file"}, Target: "restored-item", State: organization.ResourceNotStarted}}}
			case "share-recovery":
				e.recovery = &cipherShareRecoveryEditor{id: "example-item", inspected: true, inspection: vaultwarden.CipherShareRecoveryInspection{CipherID: "example-item", CipherState: vaultwarden.ShareRecoveryOldPersonal, CanRepair: true, Attachments: []vaultwarden.CipherShareRecoveryAttachment{{ID: "example-file", State: vaultwarden.ShareRecoveryOldWrapping}}}}
			case "locked":
				a.showLogin = true
			}
			defer i18n.Set(i18n.Current())
			if name == "export-english" {
				i18n.Set(i18n.English)
			}
			width, height := 760, 680
			if name == "export-small" {
				width, height = 640, 540
			}
			tt := ui.NewTester(a.backupWindowView, width, height)
			f, err := os.Create(filepath.Join(dir, "backup-"+name+".png"))
			if err != nil {
				t.Fatal(err)
			}
			if err := png.Encode(f, tt.Image()); err != nil {
				f.Close()
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
