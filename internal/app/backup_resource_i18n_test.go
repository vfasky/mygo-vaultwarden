// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/organization"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestBackupResourceRestoreEnglishKeepsVerifiedState(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	resources := &backupResourceEditor{
		rows: []organization.ResourceRow{{
			Resource: vaultwarden.BackupResource{FileName: "example.txt", CipherID: "source", AttachmentID: "attachment"},
			Target:   "target", State: organization.ResourceVerified,
		}},
	}
	a := &app{backupEditor: &backupEditor{resources: resources}}
	view := ui.NewTester(func(c *ui.Context) { a.backupResourceRestoreView(c, a.backupEditor) }, 1200, 1600)
	view.Frame()
	if !view.HasText("example.txt · Source source/attachment · Verified") {
		t.Fatal("resource status was not rendered in English")
	}
	if !view.HasText("Confirm one upload to this target") {
		t.Fatal("resource action was not rendered in English")
	}
	if resources.rows[0].State != organization.ResourceVerified {
		t.Fatal("rendering changed the resource state")
	}
	if target, ready := resourceTrashTarget(resources, "source"); target != "target" || !ready {
		t.Fatalf("English locale changed verification eligibility: target=%q ready=%t", target, ready)
	}
}
