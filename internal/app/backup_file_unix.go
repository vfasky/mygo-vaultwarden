// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"golang.org/x/sys/unix"
)

var errBackupFile = errors.New("无法安全访问文件。请选择本地普通文件和非符号链接目录；导出请使用尚不存在的新文件名。")

// Pin every parent component by descriptor, refusing symlinks. Path replacement
// after selection cannot redirect a secret write outside the selected directory.
func openBackupParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return -1, "", errBackupFile
	}
	path = filepath.Clean(path)
	name := filepath.Base(path)
	if name == "/" || name == "." {
		return -1, "", errBackupFile
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", errBackupFile
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, "", errBackupFile
		}
		fd = next
	}
	return fd, name, nil
}

func readBackupFile(ctx context.Context, path string) ([]byte, error) {
	fd, name, err := openBackupParent(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	raw, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errBackupFile
	}
	file := os.NewFile(uintptr(raw), "import")
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

type stagedBackup struct {
	dir               int
	temporary, target string
}

func (s *stagedBackup) Close() {
	if s == nil || s.dir < 0 {
		return
	}
	unix.Unlinkat(s.dir, s.temporary, 0)
	unix.Close(s.dir)
	s.dir = -1
}
func (s *stagedBackup) Commit() error {
	if s == nil || s.dir < 0 {
		return errBackupFile
	}
	// linkat provides atomic no-replace publication, unlike check-then-rename.
	// Existing files (including symlinks/hardlinks) are never overwritten.
	if err := unix.Linkat(s.dir, s.temporary, s.dir, s.target, 0); err != nil {
		return errBackupFile
	}
	err := unix.Fsync(s.dir)
	s.Close()
	if err != nil {
		return errBackupFile
	}
	return nil
}
func stageBackupFile(ctx context.Context, path string, data []byte) (*stagedBackup, error) {
	if len(data) > vaultwarden.MaxBackupSize || ctx.Err() != nil {
		return nil, vaultwarden.ErrCancelled
	}
	return stageBackupStream(ctx, path, func(file *os.File) error { _, err := file.Write(data); return err })
}

func stageBackupStream(ctx context.Context, path string, produce func(*os.File) error) (*stagedBackup, error) {
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
	stage := &stagedBackup{dir: fd, target: name, temporary: ".mygo-backup-" + hex.EncodeToString(random)}
	var stat unix.Stat_t
	if err = unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		stage.Close()
		return nil, errBackupFile
	}
	raw, err := unix.Openat(fd, stage.temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
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
