// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin || linux

package vaultwarden

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"golang.org/x/sys/unix"
)

// Pin every parent directory using openat(O_NOFOLLOW). Publication is a linkat
// no-replace operation in that pinned directory; existing files are untouched.
type sendDestination struct {
	dir               int
	temporary, target string
}

func sendParent(path string) (int, string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) || filepath.Clean(path) != path {
		return -1, "", ErrValidation
	}
	target := filepath.Base(path)
	if target == "." || target == "/" {
		return -1, "", ErrValidation
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, "", ErrPermission
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if e != nil {
			return -1, "", ErrPermission
		}
		fd = next
	}
	return fd, target, nil
}

// OpenSendSource pins a regular local file without following symlinks. The
// caller owns the returned handle and closes it even on cancellation.
func OpenSendSource(path string) (io.ReadCloser, int64, string, error) {
	dir, name, e := sendParent(path)
	if e != nil {
		return nil, 0, "", e
	}
	defer unix.Close(dir)
	fd, e := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, 0, "", ErrPermission
	}
	f := os.NewFile(uintptr(fd), "send-source")
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > vaultcrypto.AttachmentPlaintextLimit {
		f.Close()
		return nil, 0, "", ErrValidation
	}
	return f, info.Size(), name, nil
}
func newSendDestination(path string) (*sendDestination, error) {
	fd, target, e := sendParent(path)
	if e != nil {
		return nil, e
	}
	var info unix.Stat_t
	if e = unix.Fstatat(fd, target, &info, unix.AT_SYMLINK_NOFOLLOW); e != unix.ENOENT {
		unix.Close(fd)
		return nil, ErrConflict
	}
	return &sendDestination{dir: fd, target: target}, nil
}
func (d *sendDestination) close() {
	if d.dir < 0 {
		return
	}
	if d.temporary != "" {
		_ = unix.Unlinkat(d.dir, d.temporary, 0)
	}
	_ = unix.Close(d.dir)
	d.dir = -1
}
func (d *sendDestination) publish(ctx context.Context, source io.Reader, size int64, guard func() error) error {
	var random [16]byte
	if _, e := rand.Read(random[:]); e != nil {
		return ErrEncryption
	}
	d.temporary = ".mygo-send-" + hex.EncodeToString(random[:])
	fd, e := unix.Openat(d.dir, d.temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrPermission
	}
	f := os.NewFile(uintptr(fd), "send-download")
	defer f.Close()
	b := make([]byte, vaultcrypto.AttachmentBufferSize)
	defer clear(b)
	for remaining := size; remaining > 0; {
		n := min(int64(len(b)), remaining)
		if e = vaultcrypto.AttachmentRead(ctx, source, b[:n]); e != nil {
			return e
		}
		if e = vaultcrypto.AttachmentWrite(ctx, f, b[:n]); e != nil {
			return e
		}
		remaining -= n
	}
	if e = vaultcrypto.AttachmentEOF(ctx, source); e != nil {
		return e
	}
	if f.Sync() != nil {
		return ErrPermission
	}
	if e = guard(); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if unix.Linkat(d.dir, d.temporary, d.dir, d.target, 0) != nil {
		return ErrConflict
	}
	_ = unix.Fsync(d.dir)
	return nil
}
