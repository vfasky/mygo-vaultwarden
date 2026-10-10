// SPDX-License-Identifier: GPL-3.0-only
package send

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// ConfigureSendDialogs installs actual MyGo native open/save sheets. The host
// still owns Dispatch, Check, Checkpoint, Copy and Changed. Dialog APIs may run
// on workers; cancellation is checked before and after the native sheet.
func ConfigureDialogs(parent *mygo.Window, host *Host) {
	host.ChooseSource = func(ctx context.Context) (io.ReadCloser, int64, string, error) {
		if ctx.Err() != nil {
			return nil, 0, "", vaultwarden.ErrCancelled
		}
		paths, e := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Title: i18n.T("send.file.choose_title"), Message: i18n.T("send.file.upload_hint"), Multiple: false})
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
		path, e := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent, Title: i18n.T("send.file.save_title"), DefaultPath: sendSaveName(name), Message: i18n.T("send.file.save_hint")})
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
		return i18n.T("send.file.default_name")
	}
	return name
}
