// SPDX-License-Identifier: GPL-3.0-only
package fileio

import (
	"fmt"
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
		return "", fmt.Errorf("此格式请使用 %s 文件扩展名，未写入文件。", extension)
	}
	return path, nil
}
