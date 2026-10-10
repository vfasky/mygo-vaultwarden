// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
)

func TestFolderEditorEnglishConfirmation(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	a := &app{folderEditor: &folderEditor{id: "folder-1", name: "Personal"}}
	tt := ui.NewTester(a.folderEditorView, 800, 600)
	if !tt.HasText("Manage folder") || tt.HasText("管理文件夹") {
		t.Fatal("folder editor did not render in English")
	}
	uitest.Click(t, tt, "Delete folder")
	if !a.folderEditor.confirm || !tt.HasText("Deleting this folder moves its items to No folder. The items themselves are not deleted. Continue?") {
		t.Fatal("English deletion warning or confirmation is missing")
	}
	uitest.Click(t, tt, "Cancel deletion")
	if a.folderEditor.confirm || a.folderEditor.name != "Personal" {
		t.Fatal("cancel changed the folder draft")
	}
	// Type names also form organization selector keys; English must not change them.
	if cipherTypeNames[3] != "支付卡" || i18n.T(cipherTypeNames[3]) != "Card" {
		t.Fatal("item type identity changed or its display label was not translated")
	}
}
