// SPDX-License-Identifier: GPL-3.0-only
// Package toolchain locates the explicitly selected Go tool for test subprocesses.
package toolchain

import (
	"os"
	"os/exec"
	"testing"
)

func Go(t *testing.T) string {
	t.Helper()
	candidate := os.Getenv("GO_BIN")
	if candidate == "" {
		candidate = "go"
	}
	path, err := exec.LookPath(candidate)
	if err != nil {
		t.Fatalf("Go fixture compiler unavailable; set GO_BIN or PATH: %v", err)
	}
	return path
}
