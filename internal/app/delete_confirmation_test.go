// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestDeleteDialogAboveDrawerPreservesDraftAndClearsOnLock(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openCipherEditor("card-1", 3)
	editor := a.editor
	editor.fields.Name = "Unsaved card name"
	tt := ui.NewTester(a.view, 1280, 820)
	tt.Scroll(1100, 600, 0, 2000)
	uitest.Click(t, tt, "移入回收站")
	if !tt.Focused("取消操作") || editor.confirm != vaultwarden.CipherTrash {
		t.Fatal("delete dialog is not focused")
	}
	warning, ok := tt.Find("Unsaved card name\n\n确认将项目移入回收站？")
	if !ok || warning.X < 350 || warning.X > 650 || warning.Y < 150 || warning.Y > 500 {
		t.Fatalf("confirmation is not centered over the window: %+v", warning)
	}
	// The editor's save action and close shortcut must be inert behind the alert.
	uitest.Click(t, tt, "保存")
	uitest.Click(t, tt, "关闭")
	if a.editor != editor || a.pending != 0 || editor.confirm != vaultwarden.CipherTrash {
		t.Fatal("dialog leaked a save click")
	}
	tt.Key(0, ui.KeyEscape)
	if a.editor != editor || editor.confirm != "" || editor.fields.Name != "Unsaved card name" {
		t.Fatal("Escape discarded the drawer or draft")
	}
	uitest.Click(t, tt, "移入回收站")
	if dir := os.Getenv("MYGO_UI_PREVIEW_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(filepath.Join(dir, "delete-confirmation.png"))
		if err != nil {
			t.Fatal(err)
		}
		err = png.Encode(f, tt.Image())
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("save preview: %v %v", err, closeErr)
		}
	}
	a.lockInterface()
	tt.Frame()
	if a.editor != nil || tt.HasText("Unsaved card name\n\n确认将项目移入回收站？") || tt.HasText("取消操作") {
		t.Fatal("lock retained the confirmation")
	}
}

func TestFolderAndBulkDeleteEscapeClosesOnlyConfirmation(t *testing.T) {
	for _, kind := range []string{"folder", "bulk"} {
		t.Run(kind, func(t *testing.T) {
			a := writableUIFixture(t)
			defer a.stopNetwork()
			if kind == "folder" {
				a.folders = []vaultwarden.Folder{{ID: "work", Name: "Draft folder"}}
				a.openFolderEditor("work")
				a.folderEditor.confirm = true
			} else {
				a.openBulkEditor(false)
				a.bulkEditor.action = vaultwarden.CipherDeletePermanently
				a.bulkEditor.confirm = true
				a.bulkEditor.selected["card-1"] = true
			}
			tt := ui.NewTester(a.view, 1280, 820)
			tt.Key(0, ui.KeyEscape)
			if kind == "folder" {
				if a.folderEditor == nil || a.folderEditor.confirm || a.folderEditor.name != "Draft folder" {
					t.Fatal("Escape discarded folder draft")
				}
			} else if a.bulkEditor == nil || a.bulkEditor.confirm || !a.bulkEditor.selected["card-1"] {
				t.Fatal("Escape discarded bulk selection")
			}
			if a.pending != 0 {
				t.Fatal("cancellation dispatched an action")
			}
		})
	}
}
