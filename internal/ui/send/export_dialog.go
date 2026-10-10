// SPDX-License-Identifier: GPL-3.0-only
package send

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// ChooseExportPath obtains a filename and an explicit directory grant. A save
// panel alone authorizes the destination file, not adjacent staging files.
// The directory selected in the second panel is the final export location.
// Callers must preserve their cancellation/lease check before publishing.
func ChooseExportPath(ctx context.Context, opts mygo.SaveDialogOptions) (string, error) {
	return chooseExportPath(ctx, opts, mygo.Dialog.Save, mygo.Dialog.Open)
}

func chooseExportPath(ctx context.Context, opts mygo.SaveDialogOptions, save func(mygo.SaveDialogOptions) (string, error), open func(mygo.OpenDialogOptions) ([]string, error)) (string, error) {
	if ctx.Err() != nil {
		return "", vaultwarden.ErrCancelled
	}
	path, err := save(opts)
	if ctx.Err() != nil {
		return "", vaultwarden.ErrCancelled
	}
	if err != nil {
		return "", vaultwarden.ErrPermission
	}
	if path == "" {
		return "", vaultwarden.ErrCancelled
	}
	if !validExportPath(path) {
		return "", vaultwarden.ErrValidation
	}
	dirs, err := open(mygo.OpenDialogOptions{
		Parent: opts.Parent, Title: opts.Title, DefaultPath: filepath.Dir(path),
		Directory: true, CreateDirectories: true,
		Message: i18n.T("send.file.save_hint") + "\n" + filepath.Base(path),
	})
	if ctx.Err() != nil {
		return "", vaultwarden.ErrCancelled
	}
	if err != nil {
		return "", vaultwarden.ErrPermission
	}
	if len(dirs) != 1 {
		return "", vaultwarden.ErrCancelled
	}
	if !filepath.IsAbs(dirs[0]) || filepath.Clean(dirs[0]) != dirs[0] || strings.ContainsRune(dirs[0], 0) {
		return "", vaultwarden.ErrValidation
	}
	return filepath.Join(dirs[0], filepath.Base(path)), nil
}

func validExportPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0) && filepath.Base(path) != "/" && filepath.Base(path) != "."
}
