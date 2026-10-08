// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin && !headless

package main

import (
	"github.com/ebitengine/purego"
	"github.com/egoist/mygo"
	"path/filepath"
	"runtime"
	"sync"
)

var runtimeSecretLibrary struct {
	once sync.Once
	err  error
	call func([]byte, int, []byte, int) int32
}

func nativeRuntimeSecretCall(input []byte) ([]byte, error) {
	runtimeSecretLibrary.once.Do(func() {
		executable, err := nativeExecutablePath()
		if err != nil {
			runtimeSecretLibrary.err = errRuntimeSecretUnavailable
			return
		}
		handle, err := purego.Dlopen(filepath.Join(filepath.Dir(executable), "..", "Frameworks", "libSnapshotBridge.dylib"), purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			runtimeSecretLibrary.err = errRuntimeSecretUnavailable
			return
		}
		symbol, err := purego.Dlsym(handle, "mygo_runtime_secret_execute")
		if err != nil {
			_ = purego.Dlclose(handle)
			runtimeSecretLibrary.err = errRuntimeSecretUnavailable
			return
		}
		purego.RegisterFunc(&runtimeSecretLibrary.call, symbol)
	})
	if runtimeSecretLibrary.err != nil {
		return nil, runtimeSecretLibrary.err
	}
	if len(input) == 0 || len(input) > 96*1024 {
		return nil, errRuntimeSecretUnavailable
	}
	output := make([]byte, 96*1024)
	defer clear(output)
	n := int32(-1)
	mygo.RunOnMain(func() { n = runtimeSecretLibrary.call(input, len(input), output, len(output)) })
	runtime.KeepAlive(input)
	runtime.KeepAlive(output)
	if n <= 0 || int(n) > len(output) {
		return nil, errRuntimeSecretUnavailable
	}
	return append([]byte(nil), output[:int(n)]...), nil
}
