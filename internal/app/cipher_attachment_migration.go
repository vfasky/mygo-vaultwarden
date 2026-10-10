// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type cipherAttachmentMigrationEditor struct {
	rows                  []vaultwarden.CipherAttachmentMigrationInfo
	original, replacement string
	result                string
}

func (a *app) cipherAttachmentMigrationView(c *ui.Context, e *cipherEditor) {
	if e.fields.ID == "" || e.fields.OrganizationID != nil || !e.fields.Edit {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	busy := a.pending != 0
	if e.attachmentMigration == nil {
		if kit.Action(c, i18n.T("vault.attachment.migration.prepare"), "", false, busy || e.uncertain).Clicked() {
			rows, err := session.CipherAttachmentMigrationInfo(a.vault, e.fields.ID, e.authorization)
			if err != nil {
				a.status = err.Error()
				return
			}
			e.attachmentMigration = &cipherAttachmentMigrationEditor{rows: rows}
		}
		return
	}
	m := e.attachmentMigration
	ui.Text(c, i18n.T("vault.attachment.migration.description")).MaxLines(8)
	for _, row := range m.rows {
		label := row.FileName + " · " + row.ID
		if row.Legacy {
			label = i18n.Tf("vault.attachment.migration.original", label)
			if m.original == row.ID {
				label = "✓ " + label
			}
			if kit.Action(c, label, "", false, busy || e.uncertain).Clicked() {
				m.original = row.ID
			}
		} else {
			label = i18n.Tf("vault.attachment.migration.replacement", label)
			if m.replacement == row.ID {
				label = "✓ " + label
			}
			if kit.Action(c, label, "", false, busy || e.uncertain).Clicked() {
				m.replacement = row.ID
			}
		}
	}
	if kit.Action(c, i18n.T("vault.attachment.migration.confirm_copy"), "", false, busy || e.uncertain || m.original == "").Clicked() {
		a.runCipherAttachmentMigration(false)
	}
	if kit.Action(c, i18n.T("vault.attachment.migration.confirm_delete_original"), "", false, busy || e.uncertain || m.original == "" || m.replacement == "").Clicked() {
		a.runCipherAttachmentMigration(true)
	}
	if m.result != "" {
		ui.Text(c, m.result).MaxLines(8)
	}
	if e.uncertain && kit.Action(c, i18n.T("vault.attachment.migration.sync_reopen"), "sync", false, busy).Clicked() {
		a.syncVault(false)
	}
	if busy && kit.Action(c, i18n.T("vault.attachment.migration.cancel"), "", false, false).Clicked() {
		if a.cancel != nil {
			a.cancel()
		}
	}
}

func (a *app) runCipherAttachmentMigration(remove bool) {
	e := a.editor
	if e == nil || e.attachmentMigration == nil || a.pending != 0 || e.uncertain || !a.attachmentCurrent(e, a.epoch) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok || a.snapshot == nil {
		return
	}
	if err := attachmentDraftSaved(session, a.vault, e); err != nil {
		a.status = i18n.T("vault.attachment.migration.err_unsaved_draft")
		return
	}
	m := e.attachmentMigration
	oldID, newID := m.original, m.replacement
	if oldID == "" || (remove && newID == "") {
		return
	}
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	vault, id, grant, prior, scope, revision := a.vault, e.fields.ID, e.authorization, a.snapshot, *a.liveScope, e.revision
	go func() {
		var checkpoint *localstore.SnapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := localstore.SaveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		state := callStorage(localstore.Request{Operation: "status"})
		var result vaultwarden.CipherAttachmentMigrationResult
		var err error
		if !state.OK || !backupLease(state.State, scope, revision) {
			err = vaultwarden.ErrConflict
		} else if remove {
			result, err = session.VerifyAndDeleteLegacyCipherAttachment(ctx, vault, id, oldID, newID, true, grant, persist)
		} else {
			result, err = session.UpgradeLegacyCipherAttachment(ctx, vault, id, oldID, true, grant, persist)
		}
		a.postUI(func() {
			a.pending--
			defer cancel()
			if a.editor != e || a.epoch != epoch {
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			// Freeze even unknown outcomes; a new authenticated sync is required.
			e.uncertain = true
			m.result = i18n.Tf("vault.attachment.migration.result", result.OriginalID, result.ReplacementID, result.MetadataCreated, result.Uploaded, result.Reconciled, result.ContentVerified, result.OriginalDeleted)
			a.status = m.result
			if err != nil {
				a.status = err.Error() + " " + m.result
			}
		})
	}()
}
