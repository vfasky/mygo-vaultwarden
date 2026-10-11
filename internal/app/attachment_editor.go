// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/fileio"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) attachmentView(c *ui.Context, e *cipherEditor) {
	if e.fields.ID == "" {
		return
	}
	busy := a.pending != 0
	ui.Text(c, i18n.T("vault.attachment.title")).FontSize(16)
	ui.Text(c, i18n.T("vault.attachment.description")).FontSize(12).MaxLines(4)
	if kit.Action(c, i18n.T("vault.attachment.refresh"), "", false, busy || e.uncertain).Clicked() {
		a.runAttachmentOperation("list", vaultwarden.AttachmentInfo{})
	}
	if e.fields.Edit && kit.Action(c, i18n.T("vault.attachment.upload"), "", false, busy || e.uncertain || e.fields.DeletedDate != nil).Clicked() {
		a.runAttachmentOperation("upload", vaultwarden.AttachmentInfo{})
	}
	if e.attachmentsLoaded && len(e.attachments) == 0 {
		ui.Text(c, i18n.T("vault.attachment.empty")).FontSize(12)
	}
	for _, attachment := range e.attachments {
		ui.Column(c).Gap(6).Children(func() {
			ui.Text(c, attachment.FileName).MaxLines(2)
			ui.Text(c, i18n.Tf("vault.attachment.encrypted_size", attachment.CiphertextSize)).FontSize(11)
			if kit.Action(c, i18n.T("vault.attachment.download"), "", false, busy || e.uncertain).Clicked() {
				a.runAttachmentOperation("download", attachment)
			}
			if e.fields.Edit {
				if e.attachmentDelete == attachment.ID {
					ui.Text(c, i18n.T("vault.attachment.confirm_delete_hint")).FontSize(12)
					if kit.Action(c, i18n.T("vault.attachment.confirm_delete"), "", true, busy || e.uncertain).Clicked() {
						a.runAttachmentOperation("delete", attachment)
					}
					if kit.Action(c, i18n.T("vault.attachment.keep"), "", false, busy).Clicked() {
						e.attachmentDelete = ""
					}
				} else if kit.Action(c, i18n.T("vault.attachment.delete"), "", false, busy || e.uncertain).Clicked() {
					e.attachmentDelete = attachment.ID
				}
			}
		})
	}
	if e.attachmentBusy {
		ui.Text(c, i18n.T("vault.attachment.status_transferring")).FontSize(12)
		if kit.Action(c, i18n.T("vault.attachment.cancel"), "", false, false).Clicked() {
			if a.cancel != nil {
				a.cancel()
			}
			a.status = i18n.T("vault.attachment.status_cancel_requested")
		}
	}
}

// Mutations trigger a normal sync that may close the editor. Never silently
// discard a draft: compare a detached copy of all controls with saved content.
func attachmentDraftSaved(session *vaultwarden.Session, vault *vaultwarden.VaultData, e *cipherEditor) error {
	var saved vaultwarden.CipherFields
	var err error
	if e.fields.OrganizationID == nil {
		_, saved, err = session.ReadPersonalCipherAuthorized(vault, e.fields.ID, e.authorization)
	} else {
		_, saved, err = session.ReadOrganizationCipher(vault, e.fields.ID, e.authorization)
	}
	if err != nil {
		return err
	}
	copy := *e
	encoded, err := json.Marshal(e.fields)
	if err != nil {
		return vaultwarden.ErrProtocol
	}
	copy.fields = vaultwarden.CipherFields{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&copy.fields) != nil {
		return vaultwarden.ErrProtocol
	}
	copy.applyInputs()
	current, err := json.Marshal(copy.fields)
	if err != nil {
		return vaultwarden.ErrProtocol
	}
	original, err := json.Marshal(saved)
	if err != nil || !bytes.Equal(current, original) {
		return vaultwarden.ErrConflict
	}
	return nil
}

func (a *app) attachmentCurrent(e *cipherEditor, epoch uint64) bool {
	return e != nil && a.editor == e && a.epoch == epoch && a.sessionOwnsSnapshot() && e.revision == a.sessionRevision
}

func (a *app) runAttachmentOperation(operation string, attachment vaultwarden.AttachmentInfo) {
	e := a.editor
	if a.pending != 0 || e == nil || e.uncertain || !a.attachmentCurrent(e, a.epoch) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok || a.snapshot == nil || a.vault == nil {
		return
	}
	if operation != "list" && operation != "upload" && operation != "download" && operation != "delete" {
		return
	}
	if operation == "upload" || operation == "delete" {
		if !e.fields.Edit {
			return
		}
		if err := attachmentDraftSaved(session, a.vault, e); err != nil {
			a.status = i18n.T("vault.attachment.err_unsaved_draft")
			return
		}
	}
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	e.attachmentBusy = true
	id, grant, vault, parent, scope, revision, prior := e.fields.ID, e.authorization, a.vault, a.mainWindow, *a.liveScope, e.revision, a.snapshot
	go func() {
		var checkpoint *localstore.SnapshotStatus
		var storage localstore.Reply
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			storage, err = localstore.SaveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior, checkpoint = storage.State, storage.State
			}
			return err
		}
		lease := func() error {
			if ctx.Err() != nil {
				return vaultwarden.ErrCancelled
			}
			status := callStorage(localstore.Request{Operation: localstore.OperationStatus})
			if !status.OK || !backupLease(status.State, scope, revision) {
				return vaultwarden.ErrConflict
			}
			return nil
		}
		err := lease()
		var rows []vaultwarden.AttachmentInfo
		var stage *fileio.StagedFile
		var proof *vaultwarden.AttachmentPublication
		var upload vaultwarden.AttachmentUploadResult
		submitted := false
		if err == nil {
			switch operation {
			case "list":
				rows, err = session.Attachments(ctx, vault, id, grant, persist)
			case "upload":
				var paths []string
				paths, err = mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent})
				if err == nil && len(paths) != 1 {
					err = vaultwarden.ErrCancelled
				}
				if err == nil {
					err = lease()
				}
				if err == nil {
					var file *os.File
					file, err = fileio.OpenAttachmentInput(paths[0])
					if err == nil {
						submitted = true
						upload, err = session.UploadAttachment(ctx, vault, id, filepath.Base(paths[0]), file, grant, persist)
					}
				}
			case "download":
				var path string
				path, err = send.ChooseExportPath(ctx, mygo.SaveDialogOptions{Parent: parent})
				if err == nil && path == "" {
					err = vaultwarden.ErrCancelled
				}
				if err == nil {
					err = lease()
				}
				if err == nil {
					proof, err = session.DownloadAttachment(ctx, vault, id, attachment.ID, grant, persist, func(file *os.File, size int64) error {
						var err error
						stage, err = fileio.StageAttachmentFile(ctx, path, file, size)
						return err
					})
				}
			case "delete":
				submitted = true
				err = session.DeleteAttachment(ctx, vault, id, attachment.ID, grant, persist)
			}
		}
		a.dispatchUI(func() {
			a.pending--
			defer cancel()
			defer stage.Close()
			if a.editor != e || a.epoch != epoch {
				return
			}
			e.attachmentBusy = false
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
				return
			}
			if !a.attachmentCurrent(e, epoch) {
				return
			}
			if err != nil || ctx.Err() != nil {
				if err == nil {
					err = vaultwarden.ErrCancelled
				}
				a.status = vaultwarden.ErrorMessage(err)
				if submitted {
					e.uncertain = true
					a.status = i18n.Tf("vault.attachment.err_verify_list", a.status)
					if upload.AttachmentID != "" {
						a.status = i18n.Tf("vault.attachment.result_id", a.status, upload.AttachmentID)
					}
				}
				return
			}
			if err := lease(); err != nil {
				a.status = vaultwarden.ErrorMessage(err)
				return
			}
			switch operation {
			case "list":
				e.attachments, e.attachmentsLoaded = rows, true
				a.status = i18n.T("vault.attachment.status_list_verified")
			case "download":
				if stage == nil {
					a.status = vaultwarden.ErrorMessage(vaultwarden.ErrProtocol)
					return
				}
				if err := session.PublishAttachment(ctx, proof, grant, stage.Commit); err != nil {
					a.status = vaultwarden.ErrorMessage(err)
					return
				}
				a.status = i18n.T("vault.attachment.status_downloaded")
			case "upload", "delete":
				a.editor = nil
				a.status = i18n.T("vault.attachment.status_confirmed")
				a.syncVault(false)
			}
		})
	}()
}
