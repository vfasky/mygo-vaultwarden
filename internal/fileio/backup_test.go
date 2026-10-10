// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package fileio

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Keep this helper identical to backupTestDirectory in internal/app tests.
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
		path, err := BackupOutputPath("/local/backup", format)
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
		if _, err := BackupOutputPath(wrong, format); err == nil {
			t.Fatal("mixed extension allowed")
		}
	}
	if _, err := BackupOutputPath("", vaultwarden.MyGoBackup); err == nil {
		t.Fatal("cancelled path accepted")
	}
}

func TestBackupFileNoOverwriteSymlinkAndCancel(t *testing.T) {
	dir := backupTestDirectory(t)
	target := filepath.Join(dir, "vault.mygovault")
	data := []byte("sensitive backup")
	stage, err := StageBackupFile(context.Background(), target, data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("published before confirmation")
	}
	info, err := os.Stat(filepath.Join(dir, stage.Temporary))
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
	if _, err = StageBackupFile(context.Background(), target, []byte("replacement")); err == nil {
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
	if _, err = StageBackupFile(context.Background(), link, data); err == nil {
		t.Fatal("symlink written")
	}
	if _, err = ReadBackupFile(context.Background(), link); err == nil {
		t.Fatal("symlink read")
	}
	parent := filepath.Join(dir, "directory-link")
	os.Symlink(dir, parent)
	if _, err = StageBackupFile(context.Background(), filepath.Join(parent, "new"), data); err == nil {
		t.Fatal("parent symlink followed")
	}
	newTarget := filepath.Join(dir, "race")
	stage, err = StageBackupFile(context.Background(), newTarget, data)
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
	if _, err = StageBackupFile(ctx, filepath.Join(dir, "cancelled"), data); err == nil {
		t.Fatal("cancelled stage")
	}
	if _, err = ReadBackupFile(ctx, target); err == nil {
		t.Fatal("cancelled read")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if len(entry.Name()) > 13 && entry.Name()[:13] == ".mygo-backup-" {
			t.Fatal("temp leaked")
		}
	}
}
