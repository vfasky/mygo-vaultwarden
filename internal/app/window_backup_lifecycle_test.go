// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
)

// The import and export editor lives exactly as long as its window.
func TestBackupWindowLifecycle(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openBackupEditor()
	e := a.backupEditor
	if e == nil || !a.windows.backupOpen {
		t.Fatal("import and export did not open its window")
	}
	main := ui.NewTester(a.view, 1280, 820)
	if main.HasText(i18n.T("backup.editor.title")) {
		t.Fatal("import and export still drawn in the main window")
	}
	a.runMenuCommand(menuBackup)
	if a.backupEditor != e {
		t.Fatal("menu replaced the open editor instead of showing its window")
	}
	e.exportPassword = "secret"
	a.closeBackupWindow()
	if a.backupEditor != nil || a.windows.backupOpen || e.exportPassword != "" {
		t.Fatal("closing the window kept the editor or its password")
	}

	a.openBackupEditor()
	a.stopNetwork() // as a lock does: the editor is cleared
	main.Frame()
	if a.backupEditor != nil || a.windows.backupOpen {
		t.Fatal("lock left the import and export window open")
	}
}

func TestBackupEditorWithoutWindowIsCancelled(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.backupEditor = &backupEditor{revision: a.sessionRevision, exportPassword: "secret"}
	e := a.backupEditor
	ui.NewTester(a.view, 1280, 820)
	if a.backupEditor != nil || e.exportPassword != "" {
		t.Fatal("an editor without its window survived")
	}
}
