// SPDX-License-Identifier: GPL-3.0-only
package fileio

import (
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"path/filepath"
	"strings"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func BackupOutputPath(path string, format vaultwarden.BackupFormat) (string, error) {
	if path == "" {
		return "", vaultwarden.ErrCancelled
	}
	extension := ".json"
	if format == vaultwarden.MyGoResources {
		extension = ".mygoresources"
	} else if format == vaultwarden.MyGoBackup {
		extension = ".mygovault"
	} else if format != vaultwarden.BitwardenJSON {
		return "", vaultwarden.ErrValidation
	}
	if filepath.Ext(path) == "" {
		return path + extension, nil
	}
	if strings.ToLower(filepath.Ext(path)) != extension {
		return "", fmt.Errorf(i18n.T("file.backup.err_extension"), extension)
	}
	return path, nil
}
