// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func cipherHasAttachments(document vaultwarden.CipherDocument) bool {
	var meta struct{ Attachments []json.RawMessage }
	return json.Unmarshal(document.JSON, &meta) == nil && len(meta.Attachments) > 0
}
func (a *app) startResourceCipherCopy(session *vaultwarden.Session, e *cipherEditor) {
	a.startResourceCipherCopyWith(session, e, a.window.Update, callStorage, func() { a.syncVault(false) })
}

func (a *app) startResourceCipherCopyWith(session *vaultwarden.Session, e *cipherEditor, dispatch func(func()), storage func(storageRequest) storageReply, refresh func()) {
	if err := attachmentDraftSaved(session, a.vault, e); err != nil {
		a.status = "复制含附件项目之前，请先保存草稿；完整复制使用已保存版本。"
		return
	}
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	vault, scope, revision, prior, grant, id := a.vault, *a.liveScope, e.revision, a.snapshot, e.authorization, e.fields.ID
	go func() {
		var checkpoint *snapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := saveSessionCheckpoint(prior, cp, storage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		var plan *vaultwarden.ResourceImportPlan
		var created vaultwarden.CipherDocument
		var err error
		state := storage(storageRequest{Operation: "status"})
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
			state := storage(storageRequest{Operation: "status"})
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
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			if !attempted {
				plan.Clear()
				if err != nil {
					a.status = err.Error()
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
				editor.results = []vaultwarden.ImportEntry{{Kind: "项目", Name: e.fields.Name, ID: metadata.ID, SourceID: id, State: "副本元数据已创建，附件待恢复核验"}}
			}
			a.editor = nil
			a.backupEditor = editor
			a.status = "副本尚未完成：请逐文件恢复并核验。源项目及其附件保留；创建结果未知时先同步核对目标编号，勿再次创建。"
			if err != nil {
				a.status = err.Error() + " " + a.status
			}
			if a.sessionOwnsSnapshot() {
				refresh()
			}
		})
	}()
}
