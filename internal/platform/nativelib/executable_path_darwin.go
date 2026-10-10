// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package nativelib

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ebitengine/purego"
)

// App Sandbox can change cwd before Go main, while _NSGetExecutablePath still
// reports a relative launch path. Resolve our own executable through the kernel.
func ExecutablePath() (string, error) {
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
