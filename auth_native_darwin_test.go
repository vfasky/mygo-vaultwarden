// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin && !headless

package main

import (
	"os"
	"testing"

	"github.com/ebitengine/purego"
)

// Opt-in compile-product check. It never creates NSApplication/NSWindow or
// starts authentication; invalid sizes are rejected before AppKit access.
func TestAuthProductionABI(t *testing.T) {
	path := os.Getenv("MYGO_AUTH_TEST_LIBRARY")
	if path == "" {
		t.Skip("set MYGO_AUTH_TEST_LIBRARY to this build's bridge")
	}
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	defer purego.Dlclose(handle)
	var start func(uintptr, []byte, int) uint64
	var take func(uint64, []byte, int) int32
	var release func(uint64)
	for _, entry := range []struct {
		name   string
		target any
	}{
		{"mygo_auth_start", &start}, {"mygo_auth_take", &take}, {"mygo_auth_release", &release},
	} {
		symbol, e := purego.Dlsym(handle, entry.name)
		if e != nil {
			t.Fatal(e)
		}
		purego.RegisterFunc(entry.target, symbol)
	}
	if start(0, []byte{0}, 0) != 0 {
		t.Fatal("invalid start accepted")
	}
	if take(0, []byte{0}, 0) != -4 {
		t.Fatal("invalid output accepted")
	}
	release(0)
}
