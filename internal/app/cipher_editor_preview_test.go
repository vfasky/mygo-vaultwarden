// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestVaultEditorVisualPreviews(t *testing.T) {
	dir := os.Getenv("MYGO_UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MYGO_UI_PREVIEW_DIR to export public fixture previews")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"login-editor", "card-editor", "folder-editor", "bulk-editor", "comparison", "attachments", "detail", "empty-detail", "authorization", "locked", "login-bottom", "bulk-confirmation", "folder-confirmation", "migration", "history", "comparison-en", "bulk-confirmation-en"} {
		t.Run(state, func(t *testing.T) {
			lang := i18n.Current()
			defer i18n.Set(lang)
			if state == "comparison-en" || state == "bulk-confirmation-en" {
				i18n.Set(i18n.English)
			}
			a := writableUIFixture(t)
			defer a.stopNetwork()
			a.folders = []vaultwarden.Folder{{ID: "personal", Name: "Personal"}, {ID: "work", Name: "Work"}}
			switch state {
			case "login-editor", "login-bottom":
				a.openCipherEditor("", 1)
				a.editor.fields.Name = "GitHub"
				for i := range a.editor.inputs {
					if a.editor.inputs[i].key == "username" {
						a.editor.inputs[i].value = "alex@example.com"
					}
				}
				a.editor.uris = []editorURI{{source: map[string]any{"match": nil}, value: "https://github.com/login"}}
			case "card-editor":
				a.openCipherEditor("card-1", 3)
			case "folder-editor", "folder-confirmation":
				a.openFolderEditor("work")
				a.folderEditor.confirm = state == "folder-confirmation"
			case "bulk-editor", "bulk-confirmation", "bulk-confirmation-en":
				a.items = previewApp().items
				a.openBulkEditor(false)
				a.bulkEditor.selected["1"], a.bulkEditor.selected["3"] = true, true
				if state == "bulk-confirmation" || state == "bulk-confirmation-en" {
					a.bulkEditor.action = vaultwarden.CipherDeletePermanently
					a.bulkEditor.confirm = true
				}
			case "comparison", "comparison-en":
				a.openCipherEditor("card-1", 3)
				a.editor.fields.Name = "My updated card"
				publishComparisonFixture(t, a, func(object map[string]any) {})
				a.compareCipher(nil)
				if a.editor.comparison == nil {
					t.Fatal("comparison fixture missing", a.status)
				}
			case "attachments":
				a.openCipherEditor("card-1", 3)
				a.editor.attachmentsLoaded = true
				a.editor.attachments = []vaultwarden.AttachmentInfo{{ID: "attachment-1", FileName: "recovery-notes.pdf", CiphertextSize: 24576}, {ID: "attachment-2", FileName: "purchase-receipt.pdf", CiphertextSize: 16384}}
			case "migration":
				a.openCipherEditor("card-1", 3)
				a.editor.attachmentMigration = &cipherAttachmentMigrationEditor{rows: []vaultwarden.CipherAttachmentMigrationInfo{{ID: "old", FileName: "legacy-recovery.pdf", Legacy: true}, {ID: "new", FileName: "recovery.pdf"}}, original: "old", replacement: "new"}
			case "history":
				a.openCipherEditor("card-1", 3)
				a.editor.fields.PasswordHistory = []map[string]any{{"password": "preview-old-password"}}
				a.editor.shownHistory = []vaultwarden.PasswordHistoryValue{{Password: "preview-old-password", LastUsedDate: "2026-01-01"}}
				a.editor.showHistory = true
				a.editor.historyExpires = time.Now().Add(30 * time.Second)
			case "detail":
				a.items = previewApp().items
				a.selectedID = "3"
			case "empty-detail":
				a.items = nil
			case "authorization":
				a.openCipherEditor("card-1", 3)
				a.editor.repromptID = "card-1"
			case "locked":
				a.openCipherEditor("card-1", 3)
				a.lockInterface()
			}
			tt := ui.NewTester(a.view, 1280, 820)
			if state == "attachments" || state == "login-bottom" || state == "bulk-confirmation" || state == "migration" || state == "history" || state == "bulk-confirmation-en" {
				tt.Scroll(1100, 600, 0, 2000)
			}
			path := filepath.Join(dir, state+".png")
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
			t.Log(path)
		})
	}
}

func TestVaultEditorFooterStaysVisibleAndPendingBlocksCancel(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openCipherEditor("card-1", 3)
	tt := ui.NewTester(a.view, 1280, 820)
	before, ok := tt.Find(i18n.T("common.save"))
	if !ok {
		t.Fatal("save missing")
	}
	tt.Scroll(1100, 600, 0, 2000)
	after, ok := tt.Find(i18n.T("common.save"))
	if !ok || before.Y != after.Y || after.Y+after.H > 820 {
		t.Fatal("save does not stay in footer", before, after)
	}
	a.pending = 1
	tt.Frame()
	tt.ClickAt(1245, 49)
	if a.editor == nil {
		t.Fatal("pending close discarded draft")
	}
	a.pending = 0
	tt.Frame()
	tt.ClickAt(1245, 49)
	if a.editor != nil {
		t.Fatal("close did not close draft")
	}
}

func TestVaultBulkCheckRowsSelectionAndConfirmation(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.items = []localstore.DisplayCredential{{ID: "one", Title: "First item"}, {ID: "two", Title: "Second item"}}
	a.openBulkEditor(false)
	tt := ui.NewTester(func(c *ui.Context) { a.bulkEditorView(c) }, 660, 820)
	uitest.Click(t, tt, "First item")
	if !a.bulkEditor.selected["one"] || a.bulkEditor.selected["two"] {
		t.Fatal("check row changed wrong selection")
	}
	uitest.Click(t, tt, i18n.T("vault.bulk.select_all"))
	if !a.bulkEditor.selected["one"] || !a.bulkEditor.selected["two"] {
		t.Fatal("select all missed candidates")
	}
	uitest.Click(t, tt, i18n.T("vault.bulk.select_none"))
	if len(a.bulkEditor.selected) != 0 {
		t.Fatal("select none retained candidates")
	}
	uitest.Click(t, tt, "Second item")
	uitest.Click(t, tt, i18n.T("vault.bulk.continue"))
	uitest.Click(t, tt, "First item")
	if !a.bulkEditor.confirm || a.bulkEditor.selected["one"] || !a.bulkEditor.selected["two"] || a.pending != 0 {
		t.Fatal("confirmation changed selection or submitted")
	}
}
