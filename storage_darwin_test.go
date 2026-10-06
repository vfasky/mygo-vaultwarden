// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKernelExecutablePath(t *testing.T) {
	got, err := nativeExecutablePath()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("kernel returned a relative executable path: %q", got)
	}
	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gotFile, err := os.Stat(got)
	if err != nil {
		t.Fatal(err)
	}
	wantFile, err := os.Stat(want)
	if err != nil || !os.SameFile(gotFile, wantFile) {
		t.Fatalf("resolved path does not identify this executable: %v", err)
	}
}
