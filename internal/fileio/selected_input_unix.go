// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package fileio

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openSelectedInput consumes access to the selected file itself. Opening its
// parent would require a separate sandbox extension not granted by NSOpenPanel.
// O_NONBLOCK prevents a substituted FIFO from blocking before the stat check.
func openSelectedInput(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return nil, errBackupFile
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errBackupFile
	}
	file := os.NewFile(uintptr(fd), "selected-input")
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errBackupFile
	}
	return file, nil
}
