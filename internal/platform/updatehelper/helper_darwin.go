// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin && !headless

package updatehelper

import (
	"path/filepath"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/vfasky/mygo-vaultwarden/internal/platform/nativelib"
)

var library struct {
	once   sync.Once
	ok     bool
	start  func()
	repair func(int32) int32
}

func load() bool {
	library.once.Do(func() {
		executable, err := nativelib.ExecutablePath()
		if err != nil {
			return
		}
		handle, err := purego.Dlopen(filepath.Join(filepath.Dir(executable), "..", "Frameworks", "libSnapshotBridge.dylib"), purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			return
		}
		start, err := purego.Dlsym(handle, "mygo_update_helper_start")
		if err != nil {
			return
		}
		repair, err := purego.Dlsym(handle, "mygo_update_helper_repair")
		if err != nil {
			return
		}
		purego.RegisterFunc(&library.start, start)
		purego.RegisterFunc(&library.repair, repair)
		// Process-lifetime library, two function registrations, no callbacks.
		library.ok = true
	})
	return library.ok
}

// Start launches the helper from the bundle the app runs from and keeps it
// running, so that it is there when an update has replaced the bundle.
func Start() {
	if load() {
		library.start()
	}
}

// RepairInstalled asks the helper to remove the quarantine of the installed
// bundle, which an update leaves; it does nothing to a bundle without one.
func RepairInstalled() Result {
	if !load() {
		return Unavailable
	}
	return Result(library.repair(int32(repairTimeout.Milliseconds())))
}
