// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"

	"github.com/ebitengine/purego"
)

var storageBridge struct {
	once         sync.Once
	call         func([]byte, int, []byte, int) int32
	prompt       func(int32, string, []byte, int) int32
	cancelPrompt func()
	err          error
}

// App Sandbox can change cwd before Go main, while _NSGetExecutablePath still
// reports a relative launch path. Resolve our own executable through the kernel.
func nativeExecutablePath() (string, error) {
	handle, err := purego.Dlopen("/usr/lib/libproc.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return "", err
	}
	defer purego.Dlclose(handle)
	symbol, err := purego.Dlsym(handle, "proc_pidpath")
	if err != nil {
		return "", err
	}
	var pidpath func(int32, []byte, uint32) int32
	purego.RegisterFunc(&pidpath, symbol)
	buffer := make([]byte, 4096)
	n := pidpath(int32(os.Getpid()), buffer, uint32(len(buffer)))
	runtime.KeepAlive(buffer)
	if n <= 0 || int(n) > len(buffer) {
		return "", errors.New("cannot resolve process executable")
	}
	path := string(bytes.TrimRight(buffer[:n], "\x00"))
	if !filepath.IsAbs(path) {
		return "", errors.New("process executable path is not absolute")
	}
	return path, nil
}

func loadStorageBridge() error {
	storageBridge.once.Do(func() {
		executable, err := nativeExecutablePath()
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
		prompt, err := purego.Dlsym(handle, "mygo_secure_input")
		if err != nil {
			storageBridge.err = err
			return
		}
		cancel, err := purego.Dlsym(handle, "mygo_cancel_secure_input")
		if err != nil {
			storageBridge.err = err
			return
		}
		purego.RegisterFunc(&storageBridge.prompt, prompt)
		purego.RegisterFunc(&storageBridge.cancelPrompt, cancel)
	})
	return storageBridge.err
}

func nativeSecretInput(kind int32, detail string) ([]byte, error) {
	if err := loadStorageBridge(); err != nil {
		return nil, err
	}
	buffer := make([]byte, 8192)
	n := storageBridge.prompt(kind, detail, buffer, len(buffer))
	runtime.KeepAlive(buffer)
	if n <= 0 || int(n) > len(buffer) {
		clear(buffer)
		return nil, vaultwarden.ErrCancelled
	}
	value := append([]byte(nil), buffer[:n]...)
	clear(buffer)
	return value, nil
}

func nativeCancelSecretInput() {
	if loadStorageBridge() == nil {
		storageBridge.cancelPrompt()
	}
}

func nativeStorageCall(input []byte) ([]byte, error) {
	if err := loadStorageBridge(); err != nil {
		return nil, err
	}
	if len(input) == 0 || len(input) > 4*1024*1024 {
		return nil, errSnapshotTooLarge
	}
	output := make([]byte, 4*1024*1024)
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
