// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func cipherHasAttachments(document vaultwarden.CipherDocument) bool {
	var meta struct{ Attachments []json.RawMessage }
	return json.Unmarshal(document.JSON, &meta) == nil && len(meta.Attachments) > 0
}
func (a *app) startResourceCipherCopy(session *vaultwarden.Session, e *cipherEditor) {
	a.startResourceCipherCopyWith(session, e, a.window.Update, localstore.Call, func() { a.syncVault(false) })
}

func (a *app) startResourceCipherCopyWith(session *vaultwarden.Session, e *cipherEditor, dispatch func(func()), storage func(localstore.Request) localstore.Reply, refresh func()) {
	if err := attachmentDraftSaved(session, a.vault, e); err != nil {
		a.status = i18n.T("vault.copy.err_unsaved_draft")
		return
	}
	a.advanceEpoch()
	epoch := a.epoch
	storage = a.routeStorage(storage, epoch)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	vault, scope, revision, prior, grant, id := a.vault, *a.liveScope, e.revision, a.snapshot, e.authorization, e.fields.ID
	go func() {
		var checkpoint *localstore.SnapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := localstore.SaveSessionCheckpoint(prior, cp, storage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		var plan *vaultwarden.ResourceImportPlan
		var created vaultwarden.CipherDocument
		var err error
		state := storage(localstore.Request{Operation: localstore.OperationStatus})
		if !state.OK || !backupLease(state.State, scope, revision) {
			err = vaultwarden.ErrConflict
		}
		var file *os.File
		if err == nil {
			file, err = os.CreateTemp("", "mygo-resource-copy-*")
		}
		if file != nil {
			defer func() { file.Close(); os.Remove(file.Name()) }()
		}
		grants := map[string]*vaultwarden.ItemAuthorization{id: grant}
		var proof *vaultwarden.ResourceBackupPublication
		if err == nil {
			proof, err = session.WriteResourceBackup(ctx, vault, []string{id}, "", grants, true, file, persist)
		}
		if err == nil {
			err = session.PublishResourceBackup(ctx, proof, grants, func() error { return nil })
		}
		if err == nil {
			_, err = file.Seek(0, io.SeekStart)
		}
		if err == nil {
			plan, err = vaultwarden.ParseResourceImport(ctx, file)
		}
		attempted := false
		if err == nil {
			state := storage(localstore.Request{Operation: localstore.OperationStatus})
			if !state.OK || !backupLease(state.State, scope, revision) {
				err = vaultwarden.ErrConflict
			}
		}
		if err == nil {
			attempted = true
			created, err = session.CopyPersonalResourceMetadata(ctx, vault, plan, grant, persist)
		}
		dispatch(func() {
			a.pending--
			defer cancel()
			if a.editor != e || a.epoch != epoch {
				plan.Clear()
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				plan.Clear()
				a.stopNetwork()
				a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
				return
			}
			if !attempted {
				plan.Clear()
				if err != nil {
					a.status = vaultwarden.ErrorMessage(err)
				}
				return
			}
			resources := resourceEditor(plan)
			// Copy resets lifecycle; it must not re-trash the new target later.
			resources.trash = nil
			resources.copyOnly = true
			editor := &backupEditor{revision: a.sessionRevision, format: vaultwarden.MyGoResources, importing: true, submitted: true, resources: resources}
			var metadata struct{ ID string }
			json.Unmarshal(created.JSON, &metadata)
			if metadata.ID != "" {
				resources.targets[id] = metadata.ID
				editor.results = []vaultwarden.ImportEntry{{Kind: vaultwarden.ImportKindItem, Name: e.fields.Name, ID: metadata.ID, SourceID: id, State: vaultwarden.ImportStateMetadataCopied}}
			}
			a.editor = nil
			a.backupEditor = editor
			a.status = i18n.T("vault.copy.status_incomplete")
			if err != nil {
				a.status = vaultwarden.ErrorMessage(err) + " " + a.status
			}
			if a.sessionOwnsSnapshot() {
				refresh()
			}
		})
	}()
}
