// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin && !headless

package app

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/egoist/mygo"
)

var authLibrary struct {
	once    sync.Once
	err     error
	start   func(uintptr, []byte, int) uint64
	take    func(uint64, []byte, int) int32
	release func(uint64)
}

func loadAuthentication() error {
	authLibrary.once.Do(func() {
		executable, err := nativeExecutablePath()
		if err != nil {
			authLibrary.err = errAuthUnavailable
			return
		}
		handle, err := purego.Dlopen(filepath.Join(filepath.Dir(executable), "..", "Frameworks", "libSnapshotBridge.dylib"), purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			authLibrary.err = errAuthUnavailable
			return
		}
		symbols := make([]uintptr, 3)
		for i, name := range []string{"mygo_auth_start", "mygo_auth_take", "mygo_auth_release"} {
			symbols[i], err = purego.Dlsym(handle, name)
			if err != nil {
				_ = purego.Dlclose(handle)
				authLibrary.err = errAuthUnavailable
				return
			}
		}
		purego.RegisterFunc(&authLibrary.start, symbols[0])
		purego.RegisterFunc(&authLibrary.take, symbols[1])
		purego.RegisterFunc(&authLibrary.release, symbols[2])
		// Process-lifetime library, only three function registrations, no callbacks.
	})
	return authLibrary.err
}

type windowAuthentication struct {
	window *mygo.Window
	ctx    context.Context
}

func (t windowAuthentication) start(input []byte) (id uint64) {
	mygo.RunOnMain(func() {
		if t.ctx.Err() != nil || t.window == nil || t.window.IsDestroyed() {
			return
		}
		id = authLibrary.start(t.window.NativeHandle(), input, len(input))
	})
	runtime.KeepAlive(input)
	return
}
func (t windowAuthentication) take(id uint64, output []byte) (n int32) {
	n = -2 // RunOnMain drops work after shutdown.
	mygo.RunOnMain(func() {
		if t.window == nil || t.window.IsDestroyed() {
			return
		}
		n = authLibrary.take(id, output, len(output))
	})
	runtime.KeepAlive(output)
	return
}
func (t windowAuthentication) release(id uint64) { mygo.RunOnMain(func() { authLibrary.release(id) }) }
func nativeAuthentication(ctx context.Context, window *mygo.Window, input []byte) ([]byte, error) {
	if err := loadAuthentication(); err != nil {
		return nil, err
	}
	return authExchange(ctx, input, windowAuthentication{window: window, ctx: ctx})
}
