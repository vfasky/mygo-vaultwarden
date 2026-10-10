// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func backupTestDirectory(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestBackupFormatCannotMasqueradeAsOfficialJSON(t *testing.T) {
	for _, format := range []vaultwarden.BackupFormat{vaultwarden.BitwardenJSON, vaultwarden.MyGoBackup} {
		path, err := backupOutputPath("/local/backup", format)
		if err != nil {
			t.Fatal(err)
		}
		want := "/local/backup.json"
		wrong := "/local/backup.mygovault"
		if format == vaultwarden.MyGoBackup {
			want, wrong = wrong, want
		}
		if path != want {
			t.Fatal("wrong extension")
		}
		if _, err := backupOutputPath(wrong, format); err == nil {
			t.Fatal("mixed extension allowed")
		}
	}
	if _, err := backupOutputPath("", vaultwarden.MyGoBackup); err == nil {
		t.Fatal("cancelled path accepted")
	}
}

func TestBackupFileNoOverwriteSymlinkAndCancel(t *testing.T) {
	dir := backupTestDirectory(t)
	target := filepath.Join(dir, "vault.mygovault")
	data := []byte("sensitive backup")
	stage, err := stageBackupFile(context.Background(), target, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("published before confirmation")
	}
	info, err := os.Stat(filepath.Join(dir, stage.temporary))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe temporary mode", err)
	}
	if err = stage.Commit(); err != nil {
		t.Fatal(err)
	}
	stage.Close()
	info, _ = os.Stat(target)
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe final mode")
	}
	if _, err = stageBackupFile(context.Background(), target, []byte("replacement")); err == nil {
		t.Fatal("existing file overwritten")
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(data) {
		t.Fatal("target changed")
	}
	link := filepath.Join(dir, "symlink")
	if err = os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err = stageBackupFile(context.Background(), link, data); err == nil {
		t.Fatal("symlink written")
	}
	if _, err = readBackupFile(context.Background(), link); err == nil {
		t.Fatal("symlink read")
	}
	parent := filepath.Join(dir, "directory-link")
	os.Symlink(dir, parent)
	if _, err = stageBackupFile(context.Background(), filepath.Join(parent, "new"), data); err == nil {
		t.Fatal("parent symlink followed")
	}
	newTarget := filepath.Join(dir, "race")
	stage, err = stageBackupFile(context.Background(), newTarget, data)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(newTarget, []byte("other writer"), 0600)
	if err = stage.Commit(); err == nil {
		t.Fatal("publication overwrote concurrent writer")
	}
	stage.Close()
	got, _ = os.ReadFile(newTarget)
	if string(got) != "other writer" {
		t.Fatal("race data lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = stageBackupFile(ctx, filepath.Join(dir, "cancelled"), data); err == nil {
		t.Fatal("cancelled stage")
	}
	if _, err = readBackupFile(ctx, target); err == nil {
		t.Fatal("cancelled read")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if len(entry.Name()) > 13 && entry.Name()[:13] == ".mygo-backup-" {
			t.Fatal("temp leaked")
		}
	}
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
			stage, err := stageBackupFile(context.Background(), target, []byte("secret"))
			if err != nil {
				t.Fatal(err)
			}
			temp := stage.temporary
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
