// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestAttachmentFilesStreamingAndNoReplace(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{0, 43, 255}, 2*1024*1024+1)
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := openAttachmentInput(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	target := filepath.Join(dir, "download")
	stage, err := stageAttachmentFile(context.Background(), target, file, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("plaintext prematurely published")
	}
	info, err := os.Stat(filepath.Join(dir, stage.temporary))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("stage permissions", err)
	}
	if err := stage.Commit(); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("streamed data mismatch", err)
	}
	file.Seek(0, 0)
	if result, err := stageAttachmentFile(context.Background(), target, file, int64(len(data))); err == nil || result != nil {
		t.Fatal("existing file accepted")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("saved file removed", err)
	}
}

func TestAttachmentFilesRejectLinksCancelAndReplacement(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "input")
	if err := os.WriteFile(input, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(input, link); err != nil {
		t.Fatal(err)
	}
	if file, err := openAttachmentInput(link); err == nil {
		file.Close()
		t.Fatal("symlink input opened")
	}
	parentLink := filepath.Join(dir, "parent-link")
	if err := os.Symlink(dir, parentLink); err != nil {
		t.Fatal(err)
	}
	if file, err := openAttachmentInput(filepath.Join(parentLink, "input")); err == nil {
		file.Close()
		t.Fatal("symlink ancestor opened")
	}
	file, err := openAttachmentInput(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(input, input+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	stage, err := stageAttachmentFile(context.Background(), target, file, 8)
	if err != nil {
		t.Fatal("pinned input", err)
	}
	defer stage.Close()
	if err := os.WriteFile(target, []byte("user-file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := stage.Commit(); err == nil {
		t.Fatal("no-replace publication overwritten file")
	}
	stage.Close()
	actual, _ := os.ReadFile(target)
	if string(actual) != "user-file" {
		t.Fatal("user file changed")
	}
	file.Seek(0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if stage, err := stageAttachmentFile(ctx, filepath.Join(dir, "cancelled"), file, 8); !errors.Is(err, vaultwarden.ErrCancelled) || stage != nil {
		t.Fatal("cancelled stage", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(".mygo-attachment-") && entry.Name()[:len(".mygo-attachment-")] == ".mygo-attachment-" {
			t.Fatal("unpublished stage leaked")
		}
	}
}
