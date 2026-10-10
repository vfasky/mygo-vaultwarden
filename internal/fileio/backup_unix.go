// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package fileio

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"golang.org/x/sys/unix"
)

var errBackupFile = i18n.Error("file.backup.err_unsafe_access")

// Open only the explicitly selected directory. A native file selection grants
// access to that file, not its parent; callers staging exports must separately
// obtain a directory selection. Resolving ancestors is left to the kernel (e.g.
// macOS /tmp -> /private/tmp); the selected directory itself must not be a link.
// All subsequent writes stay relative to this pinned descriptor.
func openBackupParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) || filepath.Clean(path) != path {
		return -1, "", errBackupFile
	}
	name := filepath.Base(path)
	if name == "/" || name == "." {
		return -1, "", errBackupFile
	}
	fd, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", errBackupFile
	}
	return fd, name, nil
}

func ReadBackupFile(ctx context.Context, path string) ([]byte, error) {
	file, err := openSelectedInput(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > vaultwarden.MaxBackupSize {
		return nil, errBackupFile
	}
	data, err := io.ReadAll(io.LimitReader(file, vaultwarden.MaxBackupSize+1))
	if err != nil || len(data) > vaultwarden.MaxBackupSize {
		clear(data)
		return nil, errBackupFile
	}
	if ctx.Err() != nil {
		clear(data)
		return nil, vaultwarden.ErrCancelled
	}
	return data, nil
}

type StagedFile struct {
	dir               int
	Temporary, target string
}

func (s *StagedFile) Close() {
	if s == nil || s.dir < 0 {
		return
	}
	unix.Unlinkat(s.dir, s.Temporary, 0)
	unix.Close(s.dir)
	s.dir = -1
}
func (s *StagedFile) Commit() error {
	if s == nil || s.dir < 0 {
		return errBackupFile
	}
	// linkat provides atomic no-replace publication, unlike check-then-rename.
	// Existing files (including symlinks/hardlinks) are never overwritten.
	if err := unix.Linkat(s.dir, s.Temporary, s.dir, s.target, 0); err != nil {
		return errBackupFile
	}
	err := unix.Fsync(s.dir)
	s.Close()
	if err != nil {
		return errBackupFile
	}
	return nil
}
func StageBackupFile(ctx context.Context, path string, data []byte) (*StagedFile, error) {
	if len(data) > vaultwarden.MaxBackupSize || ctx.Err() != nil {
		return nil, vaultwarden.ErrCancelled
	}
	return StageBackupStream(ctx, path, func(file *os.File) error { _, err := file.Write(data); return err })
}

func StageBackupStream(ctx context.Context, path string, produce func(*os.File) error) (*StagedFile, error) {
	if ctx.Err() != nil || produce == nil {
		return nil, vaultwarden.ErrCancelled
	}
	fd, name, err := openBackupParent(path)
	if err != nil {
		return nil, err
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		unix.Close(fd)
		return nil, errBackupFile
	}
	stage := &StagedFile{dir: fd, target: name, Temporary: ".mygo-backup-" + hex.EncodeToString(random)}
	var stat unix.Stat_t
	if err = unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		stage.Close()
		return nil, errBackupFile
	}
	raw, err := unix.Openat(fd, stage.Temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		stage.Close()
		return nil, errBackupFile
	}
	file := os.NewFile(uintptr(raw), "export")
	stopClosing := context.AfterFunc(ctx, func() { _ = file.Close() })
	defer stopClosing()
	productionErr := produce(file)
	err = productionErr
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil || ctx.Err() != nil {
		stage.Close()
		if ctx.Err() != nil {
			return nil, vaultwarden.ErrCancelled
		}
		if productionErr != nil {
			var pathErr *os.PathError
			if !errors.As(productionErr, &pathErr) {
				return nil, productionErr
			}
		}
		return nil, errBackupFile
	}
	return stage, nil
}
