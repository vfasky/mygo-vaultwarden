// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"os"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/fileio"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/organization"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type backupResourceEditor struct {
	plan         *vaultwarden.ResourceImportPlan
	rows         []organization.ResourceRow
	targets      map[string]string
	trash        []string
	finalized    map[string]bool
	trashPending map[string]bool
	password     string
	copyOnly     bool
}

func resourceEditor(plan *vaultwarden.ResourceImportPlan) *backupResourceEditor {
	e := &backupResourceEditor{plan: plan, targets: map[string]string{}, finalized: map[string]bool{}, trashPending: map[string]bool{}, trash: plan.DeferredTrashIDs()}
	for _, resource := range plan.Resources() {
		e.rows = append(e.rows, organization.ResourceRow{Resource: resource, State: organization.ResourceNotStarted})
	}
	return e
}
func (a *app) backupResourcePreview(c *ui.Context, e *backupEditor) {
	if e.resources == nil {
		return
	}
	ui.Text(c, i18n.T("backup.resource.restore_hint")).MaxLines(7)
	for _, row := range e.resources.rows {
		ui.Text(c, i18n.Tf("backup.resource.file_summary", row.Resource.FileName, row.Resource.CipherID, row.Resource.AttachmentID, row.Resource.Size)).FontSize(12)
	}
	if kit.Action(c, i18n.T("backup.resource.continue_attachments"), "", false, a.pending != 0).Clicked() {
		e.plan.Clear()
		e.plan = nil
		e.submitted = true
	}
}
func (a *app) chooseResourceImportFile() {
	e := a.backupEditor
	if e == nil || a.pending != 0 || !e.importing || e.plan != nil || !a.backupCurrent(e, a.epoch) {
		return
	}
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	scope, revision, parent := *a.liveScope, e.revision, a.backupParent()
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(vaultwarden.MyGoResources)}})
		var resources *vaultwarden.ResourceImportPlan
		var metadata *vaultwarden.ImportPlan
		if err == nil && len(paths) == 1 && ctx.Err() == nil {
			state := callStorage(localstore.Request{Operation: localstore.OperationStatus})
			if !state.OK || !backupLease(state.State, scope, revision) {
				err = vaultwarden.ErrConflict
			} else {
				var file *os.File
				file, err = fileio.OpenAttachmentInput(paths[0])
				if err == nil {
					resources, err = vaultwarden.ParseResourceImport(ctx, file)
				}
				if err == nil {
					metadata, err = resources.PersonalRestoreMetadata()
				}
			}
		}
		a.postUI(func() {
			a.pending--
			defer cancel()
			if !a.backupCurrent(e, epoch) || ctx.Err() != nil || err != nil {
				resources.Clear()
				metadata.Clear()
				if a.backupEditor == e && err != nil {
					a.status = vaultwarden.ErrorMessage(err)
				}
				return
			}
			a.cancel = nil
			if resources != nil {
				e.resources = resourceEditor(resources)
				e.plan = metadata
				a.status = i18n.T("backup.resource.status_preflight_passed")
			}
		})
	}()
}
func (a *app) chooseResourceExportFile() {
	e := a.backupEditor
	if e == nil || a.pending != 0 || e.importing || !e.confirm || !a.backupCurrent(e, a.epoch) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	ids := []string{}
	for _, item := range e.candidates {
		if e.selected[item.ID] {
			ids = append(ids, item.ID)
		}
	}
	if len(ids) == 0 {
		a.status = i18n.T("backup.export.err_no_selection")
		return
	}
	password := []byte(e.exportPassword)
	e.exportPassword = ""
	if backupSelectionRequiresPassword(e) && len(password) == 0 {
		a.status = i18n.T("backup.export.err_password_required")
		return
	}
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	scope, revision, vault, parent, prior := *a.liveScope, e.revision, a.vault, a.backupParent(), a.snapshot
	go func() {
		defer clear(password)
		var checkpoint *localstore.SnapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := localstore.SaveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		path, err := send.ChooseExportPath(ctx, mygo.SaveDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(vaultwarden.MyGoResources)}})
		var stage *fileio.StagedFile
		var proof *vaultwarden.ResourceBackupPublication
		grants := map[string]*vaultwarden.ItemAuthorization{}
		if err == nil && path != "" && ctx.Err() == nil {
			path, err = fileio.BackupOutputPath(path, vaultwarden.MyGoResources)
			state := callStorage(localstore.Request{Operation: localstore.OperationStatus})
			if err == nil && (!state.OK || !backupLease(state.State, scope, revision)) {
				err = vaultwarden.ErrConflict
			}
			if err == nil {
				for _, id := range ids {
					if session.PersonalItemRequiresPassword(vault, id) {
						grants[id], err = session.AuthorizePersonalItem(ctx, vault, revision, id, password)
						if err != nil {
							break
						}
					}
				}
				clear(password)
			}
			if err == nil {
				stage, err = fileio.StageBackupStream(ctx, path, func(file *os.File) error {
					var err error
					proof, err = session.WriteResourceBackup(ctx, vault, ids, "", grants, true, file, persist)
					return err
				})
			}
		}
		a.postUI(func() {
			a.pending--
			defer cancel()
			defer stage.Close()
			if a.backupEditor != e || a.epoch != epoch {
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
				return
			}
			if !a.backupCurrent(e, epoch) || ctx.Err() != nil {
				return
			}
			if err != nil {
				a.status = vaultwarden.ErrorMessage(err)
				return
			}
			if stage == nil {
				a.status = i18n.T("backup.export.status_cancelled")
				return
			}
			state := callStorage(localstore.Request{Operation: localstore.OperationStatus})
			if !state.OK || !backupLease(state.State, scope, revision) {
				a.status = vaultwarden.ErrorMessage(vaultwarden.ErrConflict)
				return
			}
			if err = session.PublishResourceBackup(ctx, proof, grants, stage.Commit); err != nil {
				a.status = vaultwarden.ErrorMessage(err)
				return
			}
			e.confirm = false
			a.status = i18n.T("backup.resource.status_saved")
		})
	}()
}
func (a *app) backupResourceRestoreView(c *ui.Context, e *backupEditor) {
	m := e.resources
	if m == nil {
		return
	}
	if m.copyOnly {
		ui.Text(c, i18n.T("backup.resource.copy_resume_hint")).MaxLines(5)
	}
	busy := a.pending != 0
	ui.Text(c, i18n.T("backup.resource.attachment_restore_hint")).MaxLines(5)
	ui.TextInput(c, &m.password).Label(i18n.T("backup.resource.master_password")).Password().Disabled(busy)
	for i := range m.rows {
		row := &m.rows[i]
		if row.Target == "" {
			row.Target = m.targets[row.Resource.CipherID]
		}
		ui.Text(c, i18n.Tf("backup.resource.source_status", row.Resource.FileName, row.Resource.CipherID, row.Resource.AttachmentID, organization.ResourceStateText(row.State))).MaxLines(3)
		if row.Problem != "" {
			ui.Text(c, row.Problem).MaxLines(3)
		}
		ui.TextInput(c, &row.Target).Label(i18n.T("backup.resource.target_item_id")).Disabled(busy || row.State == organization.ResourceVerified)
		ui.TextInput(c, &row.AttachmentID).Label(i18n.T("backup.resource.target_attachment_id")).Disabled(busy || row.State == organization.ResourceVerified)
		if kit.Action(c, i18n.T("backup.resource.confirm_upload"), "", false, busy || row.Target == "" || row.State != organization.ResourceNotStarted).Clicked() {
			a.runResourceRestore(i, false, "")
		}
		if kit.Action(c, i18n.T("backup.resource.verify_attachment"), "", false, busy || row.Target == "" || row.AttachmentID == "" || row.State == organization.ResourceVerified).Clicked() {
			a.runResourceRestore(i, true, "")
		}
	}
	for _, source := range m.trash {
		target, ready := resourceTrashTarget(m, source)
		if m.finalized[source] {
			ui.Text(c, i18n.Tf("backup.resource.status_trashed", target))
			continue
		}
		if m.trashPending[source] {
			if a.itemsRevision == a.sessionRevision {
				for _, item := range a.items {
					if item.ID == target && item.OrganizationID == "" && item.Deleted {
						m.finalized[source] = true
					}
				}
			}
			ui.Text(c, i18n.Tf("backup.resource.status_trash_pending", target))
			continue
		}
		if kit.Action(c, i18n.Tf("backup.resource.confirm_trash", target), "", false, busy || !ready).Clicked() {
			a.runResourceRestore(0, false, source)
		}
	}
}
func resourceTrashTarget(m *backupResourceEditor, source string) (string, bool) {
	target := ""
	for _, row := range m.rows {
		if row.Resource.CipherID == source {
			if row.State != organization.ResourceVerified || (target != "" && target != row.Target) {
				return "", false
			}
			target = row.Target
		}
	}
	return target, target != ""
}
func (a *app) runResourceRestore(index int, verify bool, trashSource string) {
	a.runResourceRestoreWith(index, verify, trashSource, a.postUI, localstore.Call, func() { a.syncVault(false) })
}

// Explicit side effects keep the native form controller testable with a queued
// UI dispatcher and an in-memory bridge, while retaining real Session checks.
func (a *app) runResourceRestoreWith(index int, verify bool, trashSource string, dispatch func(func()), storage func(localstore.Request) localstore.Reply, refresh func()) {
	e := a.backupEditor
	if e == nil || e.resources == nil || a.pending != 0 || !a.backupCurrent(e, a.epoch) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	m := e.resources
	if m.plan == nil || index < 0 || index >= len(m.rows) {
		return
	}
	target, attachment := m.rows[index].Target, m.rows[index].AttachmentID
	if trashSource != "" {
		var ready bool
		target, ready = resourceTrashTarget(m, trashSource)
		if !ready {
			return
		}
	}
	if target == "" || (verify && attachment == "") {
		a.status = i18n.T("backup.resource.err_target_required")
		return
	}
	if trashSource == "" && ((!verify && m.rows[index].State != organization.ResourceNotStarted) || m.rows[index].State == organization.ResourceVerified) {
		a.status = i18n.T("backup.resource.err_already_attempted")
		return
	}
	if trashSource != "" && (m.trashPending[trashSource] || m.finalized[trashSource]) {
		return
	}
	password := []byte(m.password)
	finalFiles := []struct {
		index      int
		attachment string
	}{}
	if trashSource != "" {
		for i, row := range m.rows {
			if row.Resource.CipherID == trashSource {
				finalFiles = append(finalFiles, struct {
					index      int
					attachment string
				}{i, row.AttachmentID})
			}
		}
	}
	m.password = ""
	plan := m.plan
	m.plan = nil // worker owns the descriptor until callback; Close cannot race it
	a.advanceEpoch()
	epoch := a.epoch
	storage = a.routeStorage(storage, epoch)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	vault, scope, revision, prior := a.vault, *a.liveScope, e.revision, a.snapshot
	go func() {
		defer clear(password)
		var checkpoint *localstore.SnapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := localstore.SaveSessionCheckpoint(prior, cp, storage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		var grant *vaultwarden.ItemAuthorization
		var result vaultwarden.AttachmentUploadResult
		var trashResult vaultwarden.CipherStateResult
		var err error
		state := storage(localstore.Request{Operation: localstore.OperationStatus})
		if !state.OK || !backupLease(state.State, scope, revision) {
			err = vaultwarden.ErrConflict
		}
		if err == nil && session.PersonalItemRequiresPassword(vault, target) {
			grant, err = session.AuthorizePersonalItem(ctx, vault, revision, target, password)
		}
		clear(password)
		if err == nil {
			_, _, err = session.ReadPersonalCipherAuthorized(vault, target, grant)
		}
		attempted := false
		if err == nil {
			if trashSource != "" {
				for _, file := range finalFiles {
					if err = session.VerifyRestoredResource(ctx, vault, target, file.attachment, plan, file.index, grant, persist); err != nil {
						break
					}
				}
				var doc vaultwarden.CipherDocument
				if err == nil {
					doc, _, err = session.ReadPersonalCipherAuthorized(vault, target, grant)
				}
				if err == nil {
					trashResult, err = session.ChangePersonalCipherStateAuthorizedResult(ctx, scope, doc, vaultwarden.CipherTrash, grant, persist)
				}
			} else if verify {
				err = session.VerifyRestoredResource(ctx, vault, target, attachment, plan, index, grant, persist)
			} else {
				attempted = true
				result, err = session.UploadResource(ctx, vault, target, plan, index, true, grant, persist)
			}
		}
		dispatch(func() {
			a.pending--
			defer cancel()
			if a.backupEditor != e || a.epoch != epoch {
				plan.Clear()
				return
			}
			m.plan = plan
			a.cancel = nil
			if checkpoint != nil && !a.adoptBackupCheckpoint(e, checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
				return
			}
			if trashSource != "" {
				m.trashPending[trashSource] = trashResult.Dispatched
				m.finalized[trashSource] = false // acknowledgement alone is not reconciliation
			} else if verify {
				if err == nil {
					m.rows[index].State = organization.ResourceVerified
				}
			} else if attempted {
				m.rows[index].State = organization.ResourcePendingSync
				m.rows[index].AttachmentID = result.AttachmentID
			}
			a.status = i18n.T("backup.resource.status_operation_finished")
			if trashSource != "" && !trashResult.Dispatched {
				a.status = i18n.T("backup.resource.status_trash_not_submitted")
			}
			m.rows[index].Problem = ""
			if err != nil {
				m.rows[index].Problem = vaultwarden.ErrorMessage(err)
				a.status = vaultwarden.ErrorMessage(err) + " " + a.status
			}
			if !verify && (attempted || trashResult.Dispatched) && a.sessionOwnsSnapshot() {
				refresh()
			}
		})
	}()
}
