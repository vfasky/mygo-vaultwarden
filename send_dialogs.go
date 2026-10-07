// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// ConfigureSendDialogs installs actual MyGo native open/save sheets. The host
// still owns Dispatch, Check, Checkpoint, Copy and Changed. Dialog APIs may run
// on workers; cancellation is checked before and after the native sheet.
func ConfigureSendDialogs(parent *mygo.Window, host *SendHost) {
	host.ChooseSource = func(ctx context.Context) (io.ReadCloser, int64, string, error) {
		if ctx.Err() != nil {
			return nil, 0, "", vaultwarden.ErrCancelled
		}
		paths, e := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Title: "选择 Send 文件", Message: "文件将加密后上传；最多512 MiB。", Multiple: false})
		if ctx.Err() != nil || len(paths) != 1 {
			return nil, 0, "", vaultwarden.ErrCancelled
		}
		if e != nil {
			return nil, 0, "", vaultwarden.ErrPermission
		}
		return vaultwarden.OpenSendSource(paths[0])
	}
	host.ChooseDestination = func(ctx context.Context, name string) (string, error) {
		if ctx.Err() != nil {
			return "", vaultwarden.ErrCancelled
		}
		path, e := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent, Title: "保存 Send 文件", DefaultPath: sendSaveName(name), Message: "选择本地目录和未使用的文件名；已有文件不会被覆盖。"})
		if ctx.Err() != nil || path == "" {
			return "", vaultwarden.ErrCancelled
		}
		if e != nil {
			return "", vaultwarden.ErrPermission
		}
		return path, nil
	}
}
func sendSaveName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "." || name == ".." || name == "/" || len(name) > 240 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "Send 文件"
	}
	return name
}
