// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package fileio

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSelectedAccessThroughAncestorAlias(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	selected := filepath.Join(real, "selected")
	if err := os.MkdirAll(selected, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(alias, "selected", "backup")
	stage, err := StageBackupFile(context.Background(), target, []byte("synthetic fixture"))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if err := stage.Commit(); err != nil {
		t.Fatal(err)
	}
	data, err := ReadBackupFile(context.Background(), target)
	if err != nil || string(data) != "synthetic fixture" {
		t.Fatalf("read = %q, %v", data, err)
	}
	// An alias at the selected directory itself is not accepted for staging.
	if _, err := StageBackupFile(context.Background(), filepath.Join(alias, "reject"), nil); err == nil {
		t.Fatal("selected symlink directory accepted")
	}
}

func TestSelectedDirectoryReplacementCannotRedirectPublication(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected")
	if err := os.Mkdir(selected, 0700); err != nil {
		t.Fatal(err)
	}
	stage, err := StageBackupFile(context.Background(), filepath.Join(selected, "export"), []byte("synthetic fixture"))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	original := filepath.Join(root, "original")
	if err := os.Rename(selected, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(selected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := stage.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(selected, "export")); !os.IsNotExist(err) {
		t.Fatal("publication redirected", err)
	}
	data, err := os.ReadFile(filepath.Join(original, "export"))
	if err != nil || string(data) != "synthetic fixture" {
		t.Fatal("pinned publication failed", err)
	}
	entries, err := os.ReadDir(original)
	if err != nil || len(entries) != 1 {
		t.Fatal("stage not cleaned", err)
	}
}

func TestSelectedInputRejectsNonRegularAndNonCanonical(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, fifo, "relative", root + "/../ambiguous", root + "/bad\x00name"} {
		if f, err := OpenAttachmentInput(path); err == nil {
			f.Close()
			t.Fatalf("accepted %q", path)
		}
		if _, err := ReadBackupFile(context.Background(), path); err == nil {
			t.Fatalf("backup accepted %q", path)
		}
	}
}
