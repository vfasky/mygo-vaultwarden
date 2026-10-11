// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestBackupWindowBusyPreventsSelectionChanges(t *testing.T) {
	a := backupWindowFixture(t)
	e := a.backupEditor
	a.pending = 1
	tt := ui.NewTester(a.backupWindowView, 760, 680)
	for _, key := range []string{"backup.format.mygo_backup", "backup.format.mygo_resources", "backup.export.select_none", "backup.export.continue"} {
		uitest.Click(t, tt, i18n.T(key))
	}
	uitest.Click(t, tt, "Apple")
	if e.format != vaultwarden.BitwardenJSON || e.confirm || !e.selected["1"] || !e.selected["8"] {
		t.Fatal("busy controls changed the plan")
	}
}

func TestBackupWindowRecoveryCancelClearsSecrets(t *testing.T) {
	a := backupWindowFixture(t)
	e := a.backupEditor
	e.recovery = &cipherShareRecoveryEditor{file: []byte("example recovery file"), password: "example password"}
	r := e.recovery
	e.exportPassword = "example export password"
	e.plan = backupPreviewPlan(t)
	tt := ui.NewTester(a.backupWindowView, 760, 680)
	uitest.Click(t, tt, i18n.T("backup.editor.cancel_close"))
	if a.backupEditor != nil || a.windows.backupOpen || r.password != "" || e.exportPassword != "" || len(e.plan.PreviewItems()) != 0 {
		t.Fatal("recovery cancellation retained editor data")
	}
	for _, b := range r.file {
		if b != 0 {
			t.Fatal("recovery file was not cleared")
		}
	}
}

func TestBackupWindowFormatChoices(t *testing.T) {
	a := backupWindowFixture(t)
	tt := ui.NewTester(a.backupWindowView, 760, 680)
	for _, choice := range []struct {
		key    string
		format vaultwarden.BackupFormat
	}{
		{"backup.format.mygo_resources", vaultwarden.MyGoResources},
		{"backup.format.mygo_backup", vaultwarden.MyGoBackup},
		{"backup.format.bitwarden_json", vaultwarden.BitwardenJSON},
	} {
		uitest.Click(t, tt, i18n.T(choice.key))
		if a.backupEditor.format != choice.format {
			t.Fatal("format selection did not apply")
		}
	}
}
