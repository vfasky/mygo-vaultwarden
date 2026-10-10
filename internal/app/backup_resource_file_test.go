// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestResourceFileUsesDistinctFormatAndStreamingStage(t *testing.T) {
	path, err := backupOutputPath("/safe/archive", vaultwarden.MyGoResources)
	if err != nil || path != "/safe/archive.mygoresources" {
		t.Fatal("resource extension", err)
	}
	if _, err = backupOutputPath("/safe/archive.json", vaultwarden.MyGoResources); err == nil {
		t.Fatal("resource masquerades as official JSON")
	}
	dir := backupTestDirectory(t)
	target := filepath.Join(dir, "archive.mygoresources")
	chunk := bytes.Repeat([]byte{42}, 64<<10)
	stage, err := stageBackupStream(context.Background(), target, func(file *os.File) error {
		for i := 0; i < 129; i++ {
			if _, err := file.Write(chunk); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if _, err = os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("stream published early")
	}
	info, err := os.Stat(filepath.Join(dir, stage.temporary))
	if err != nil || info.Size() != 129*int64(len(chunk)) || info.Mode().Perm() != 0600 {
		t.Fatal("unbounded bridge used or unsafe stage", err)
	}
	if err = stage.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = stageBackupStream(context.Background(), target, func(file *os.File) error { t.Error("overwrite producer reached"); return nil }); err == nil {
		t.Fatal("resource overwritten")
	}
	denied := filepath.Join(dir, "denied.mygoresources")
	if stage, err = stageBackupStream(context.Background(), denied, func(*os.File) error { return vaultwarden.ErrPermission }); !errors.Is(err, vaultwarden.ErrPermission) || stage != nil {
		t.Fatal("source authorization error disguised as file error", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if stage, err = stageBackupStream(ctx, filepath.Join(dir, "cancelled.mygoresources"), func(file *os.File) error { file.Write(chunk); cancel(); return nil }); err != vaultwarden.ErrCancelled || stage != nil {
		t.Fatal("cancelled stream retained")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "archive.mygoresources" {
		t.Fatal("unpublished partial resource stage retained", err)
	}
}
