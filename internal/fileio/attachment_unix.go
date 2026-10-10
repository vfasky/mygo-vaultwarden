// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package fileio

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"golang.org/x/sys/unix"
)

func OpenAttachmentInput(path string) (*os.File, error) {
	file, err := openSelectedInput(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 512*1024*1024 {
		file.Close()
		return nil, errBackupFile
	}
	return file, nil
}

// Stage on the selected filesystem, using pinned directory descriptors. The
// final linkat is short and atomic and never overwrites an existing user file.
func StageAttachmentFile(ctx context.Context, path string, input *os.File, size int64) (*StagedFile, error) {
	if input == nil || size < 0 || size > 512*1024*1024 {
		return nil, vaultwarden.ErrValidation
	}
	dir, name, err := openBackupParent(path)
	if err != nil {
		return nil, err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		unix.Close(dir)
		return nil, errBackupFile
	}
	stage := &StagedFile{dir: dir, target: name, Temporary: ".mygo-attachment-" + hex.EncodeToString(random)}
	success := false
	defer func() {
		if !success {
			stage.Close()
		}
	}()
	var stat unix.Stat_t
	if unix.Fstatat(dir, name, &stat, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return nil, errBackupFile
	}
	raw, err := unix.Openat(dir, stage.Temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errBackupFile
	}
	file := os.NewFile(uintptr(raw), "attachment-output")
	defer file.Close()
	buffer := make([]byte, 64*1024)
	defer clear(buffer)
	remaining := size
	for remaining > 0 {
		if ctx.Err() != nil {
			return nil, vaultwarden.ErrCancelled
		}
		n, err := io.ReadFull(input, buffer[:min(int64(len(buffer)), remaining)])
		if err != nil {
			return nil, errBackupFile
		}
		if _, err := file.Write(buffer[:n]); err != nil {
			return nil, errBackupFile
		}
		remaining -= int64(n)
	}
	var extra [1]byte
	if n, err := input.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, errBackupFile
	}
	if ctx.Err() != nil {
		return nil, vaultwarden.ErrCancelled
	}
	if file.Sync() != nil || file.Close() != nil {
		return nil, errBackupFile
	}
	success = true
	return stage, nil
}
