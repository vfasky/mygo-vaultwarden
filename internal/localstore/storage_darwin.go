// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package localstore

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/vfasky/mygo-vaultwarden/internal/platform/nativelib"
)

var storageBridge struct {
	once sync.Once
	call func([]byte, int, []byte, int) int32
	err  error
}

func loadStorageBridge() error {
	storageBridge.once.Do(func() {
		executable, err := nativelib.ExecutablePath()
		if err != nil {
			storageBridge.err = err
			return
		}
		library := filepath.Join(filepath.Dir(executable), "..", "Frameworks", "libSnapshotBridge.dylib")
		handle, err := purego.Dlopen(library, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			storageBridge.err = err
			return
		}
		symbol, err := purego.Dlsym(handle, "mygo_snapshot_execute")
		if err != nil {
			storageBridge.err = err
			_ = purego.Dlclose(handle)
			return
		}
		// Keep the library loaded while asynchronous identity-store callbacks exist.
		purego.RegisterFunc(&storageBridge.call, symbol)
	})
	return storageBridge.err
}

func nativeStorageCall(input []byte) ([]byte, error) {
	return BoundedStorageCall(input, nativeStorageFrame)
}

func nativeStorageFrame(input []byte) ([]byte, error) {
	if err := loadStorageBridge(); err != nil {
		return nil, err
	}
	if len(input) == 0 || len(input) > 4*1024*1024 {
		return nil, errSnapshotTooLarge
	}
	capacity := 4 * 1024 * 1024
	var frame struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(input, &frame) == nil && frame.Operation == "__transfer_v1" {
		capacity = 512 * 1024
	}
	output := make([]byte, capacity)
	n := storageBridge.call(input, len(input), output, len(output))
	runtime.KeepAlive(input)
	runtime.KeepAlive(output)
	if n == -2 {
		return nil, errSnapshotTooLarge
	}
	if n <= 0 || int(n) > len(output) {
		return nil, errors.New("invalid bridge response length")
	}
	return output[:n], nil
}
