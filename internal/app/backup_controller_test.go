// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/testfixture"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/fileio"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func backupTestDirectory(t *testing.T) string {
	return testfixture.BackupDirectory(t)
}

func TestExportLateLockCancelAndRevisionNeverPublish(t *testing.T) {
	for _, scenario := range []string{"lock", "cancel", "revision"} {
		t.Run(scenario, func(t *testing.T) {
			a := writableUIFixture(t)
			defer a.stopNetwork()
			a.openBackupEditor()
			e := a.backupEditor
			if e == nil {
				t.Fatal("editor not opened")
			}
			target := filepath.Join(backupTestDirectory(t), "backup.json")
			stage, err := fileio.StageBackupFile(context.Background(), target, []byte("secret"))
			if err != nil {
				t.Fatal(err)
			}
			temp := stage.Temporary
			epoch := a.epoch
			ctx, cancel := context.WithCancel(context.Background())
			a.pending = 1
			switch scenario {
			case "lock":
				a.stopNetwork()
			case "cancel":
				cancel()
			case "revision":
				e.revision = "old"
			}
			a.completeBackupExport(e, epoch, ctx, stage, nil, cancel)
			if _, err = os.Stat(target); !os.IsNotExist(err) {
				t.Fatal("late export published")
			}
			if _, err = os.Stat(filepath.Join(filepath.Dir(target), temp)); !os.IsNotExist(err) {
				t.Fatal("late temporary leaked")
			}
		})
	}
}

func TestBackupPreviewConfirmationAndLock(t *testing.T) {
	a := writableUIFixture(t)
	defer a.stopNetwork()
	a.openBackupEditor()
	e := a.backupEditor
	if e == nil {
		t.Fatal("missing editor")
	}
	tt := ui.NewTester(func(c *ui.Context) {
		if a.backupEditor != nil {
			a.backupEditorView(c)
		}
	}, 1000, 1000)
	uitest.Click(t, tt, "继续导出…")
	if !e.confirm || a.pending != 0 {
		t.Fatal("export without explicit confirmation")
	}
	uitest.Click(t, tt, "取消并关闭导入导出")
	if a.backupEditor != nil {
		t.Fatal("cancel retained form")
	}
	a.openBackupEditor()
	e = a.backupEditor
	e.importing = true
	plan, err := vaultwarden.ParseImport([]byte(`{"encrypted":false,"folders":[],"items":[]}`), vaultwarden.BitwardenJSON)
	if err != nil {
		t.Fatal(err)
	}
	e.plan = plan
	a.stopNetwork()
	if a.backupEditor != nil {
		t.Fatal("lock retained preview")
	}
	// Clearing the preview invalidates its private import data as well.
	if plan.Items != 0 {
		t.Fatal("unexpected preview")
	}
}
