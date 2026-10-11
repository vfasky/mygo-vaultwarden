// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package vaultwarden

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSendSelectedAccessAncestorAliasAndPinnedDirectory(t *testing.T) {
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
	source := filepath.Join(alias, "selected", "source")
	if err := os.WriteFile(source, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	r, size, name, err := OpenSendSource(source)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil || size != 7 || name != "source" || string(data) != "fixture" {
		t.Fatalf("selected file: size=%d name=%q err=%v", size, name, err)
	}

	d, err := newSendDestination(filepath.Join(alias, "selected", "saved"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	moved := filepath.Join(real, "moved")
	if err := os.Rename(selected, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(selected, 0700); err != nil {
		t.Fatal(err)
	}
	if err := d.publish(context.Background(), strings.NewReader("output"), 6, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(selected, "saved")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received output: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(moved, "saved"))
	if err != nil || string(data) != "output" {
		t.Fatalf("pinned output missing: %v", err)
	}
	info, err := os.Stat(filepath.Join(moved, "saved"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("output permissions: %v", err)
	}
}
