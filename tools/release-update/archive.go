// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// writeArchive uses the wire format of MyGo v0.3.7 WriteArchive: one bundle,
// relative names, original permissions, normalized ownership, best gzip compression.
func writeArchive(w io.Writer, app string) error {
	info, err := os.Lstat(app)
	if err != nil {
		return err
	}
	if !info.IsDir() || !strings.HasSuffix(filepath.Base(app), ".app") {
		return fmt.Errorf("input must be an .app directory, not a symlink")
	}
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()
	err = filepath.WalkDir(app, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() && info.Mode()&fs.ModeSymlink == 0 {
			return fmt.Errorf("unsupported archive entry: %s", name)
		}
		link := ""
		if info.Mode()&fs.ModeSymlink != 0 {
			link, err = os.Readlink(name)
			if err != nil {
				return err
			}
			if filepath.IsAbs(link) {
				return fmt.Errorf("absolute symlink: %s", name)
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(name), link))
			if !within(app, resolved) {
				return fmt.Errorf("symlink escapes bundle: %s", name)
			}
			// Also reject chains which lexically stay inside but resolve outside.
			resolved, err = filepath.EvalSymlinks(name)
			if err != nil {
				return fmt.Errorf("resolving symlink %s: %w", name, err)
			}
			if !within(app, resolved) {
				return fmt.Errorf("symlink chain escapes bundle: %s", name)
			}
		}
		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(filepath.Dir(app), name)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(relative)
		if info.IsDir() {
			header.Name += "/"
		}
		header.Uid, header.Gid, header.Uname, header.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, file)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func within(root, name string) bool {
	relative, err := filepath.Rel(root, name)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
