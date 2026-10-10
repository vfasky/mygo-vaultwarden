// SPDX-License-Identifier: GPL-3.0-only
package fileio

import (
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"strings"
	"testing"
)

func TestBackupPathPresentationKeepsSafeExtensionGuidance(t *testing.T) {
	defer i18n.Set(i18n.Current())
	_, err := BackupOutputPath("/private-secret-name/output.txt", vaultwarden.MyGoResources)
	if err == nil {
		t.Fatal("expected extension validation")
	}
	for _, lang := range []i18n.Lang{i18n.Chinese, i18n.English} {
		i18n.Set(lang)
		got := vaultwarden.ErrorMessage(fmt.Errorf("untrusted wrapper: %w", err))
		if got != i18n.Tf("file.backup.err_extension", ".mygoresources") || strings.Contains(got, "private-secret-name") || strings.Contains(got, "untrusted") {
			t.Fatal("extension guidance missing or untrusted text exposed")
		}
	}
}
