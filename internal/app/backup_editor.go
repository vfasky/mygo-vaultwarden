// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/fileio"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type backupEditor struct {
	revision                      string
	format                        vaultwarden.BackupFormat
	candidates                    []localstore.DisplayCredential
	selected                      map[string]bool
	importing, confirm, submitted bool
	plan                          *vaultwarden.ImportPlan
	results                       []vaultwarden.ImportEntry
	exportPassword                string
	exportIDs                     []string
	exportGrants                  map[string]*vaultwarden.ItemAuthorization
	resources                     *backupResourceEditor
	recovery                      *cipherShareRecoveryEditor
}

func backupSelectionRequiresPassword(e *backupEditor) bool {
	for _, item := range e.candidates {
		if e.selected[item.ID] && item.RequiresPassword {
			return true
		}
	}
	return false
}

func (a *app) clearBackupEditor() {
	if a.backupEditor != nil {
		a.backupEditor.plan.Clear()
		if a.backupEditor.resources != nil {
			a.backupEditor.resources.plan.Clear()
			a.backupEditor.resources.password = ""
		}
		if a.backupEditor.recovery != nil {
			clear(a.backupEditor.recovery.file)
			a.backupEditor.recovery.password = ""
		}
		a.backupEditor.exportPassword = ""
		a.backupEditor.exportGrants = nil
		a.backupEditor = nil
	}
}
func (a *app) openBackupEditor() {
	if a.pending != 0 || !a.sessionOwnsSnapshot() || a.vault == nil || a.editor != nil || a.organizationEditor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil {
		return
	}
	e := &backupEditor{revision: a.sessionRevision, format: vaultwarden.BitwardenJSON, selected: map[string]bool{}}
	for _, item := range a.items {
		if item.OrganizationID == "" {
			e.candidates = append(e.candidates, item)
		}
	}
	for _, item := range a.filteredItems() {
		if item.OrganizationID == "" {
			e.selected[item.ID] = true
		}
	}
	a.backupEditor = e
}
func (a *app) backupEditorView(c *ui.Context) {
	e := a.backupEditor
	if e.recovery != nil {
		a.cipherShareRecoveryView(c, e)
		return
	}
	busy := a.pending != 0
	ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Padding(18).Gap(10).Children(func() {
			ui.Text(c, i18n.T("backup.editor.title")).FontSize(23)
			if organizationUIEnabled && !e.submitted && kit.Action(c, i18n.T("backup.import.open_share_recovery"), "", false, busy).Clicked() {
				a.chooseCipherShareRecovery()
			}
			ui.Text(c, i18n.T("backup.editor.plaintext_hint")).MaxLines(5).FontSize(12)
			if e.format == vaultwarden.MyGoResources {
				ui.Text(c, i18n.T("backup.resource.limits_hint")).FontSize(12).MaxLines(3)
			}
			if !e.submitted {
				if !e.confirm && e.plan == nil {
					for _, format := range []struct {
						id    vaultwarden.BackupFormat
						label string
					}{{vaultwarden.BitwardenJSON, i18n.T("backup.format.bitwarden_json")}, {vaultwarden.MyGoBackup, i18n.T("backup.format.mygo_backup")}, {vaultwarden.MyGoResources, i18n.T("backup.format.mygo_resources")}} {
						if kit.NavItem(c, format.label, "vault", "", e.format == format.id, busy).Clicked() {
							e.format = format.id
						}
					}
					if kit.Action(c, i18n.T("backup.import.switch_mode"), "", false, busy || e.importing).Clicked() {
						e.importing = true
					}
					if kit.Action(c, i18n.T("backup.export.switch_mode"), "", false, busy || !e.importing).Clicked() {
						e.importing = false
					}
				}
				if e.importing {
					if e.plan == nil {
						ui.Text(c, i18n.T("backup.import.format_hint")).MaxLines(3)
						if kit.Action(c, i18n.T("backup.import.choose_file"), "", true, busy).Clicked() {
							a.chooseImportFile()
						}
					} else {
						ui.Text(c, i18n.Tf("backup.import.preview_summary", e.plan.Items, e.plan.Folders, e.plan.Archived, e.plan.Deleted)).MaxLines(3)
						ui.Text(c, i18n.T("backup.import.confirm_create_hint")).MaxLines(6)
						for _, item := range e.plan.PreviewItems() {
							label := []string{"", i18n.T("itemtype.login"), i18n.T("itemtype.note"), i18n.T("itemtype.card"), i18n.T("itemtype.identity"), i18n.T("itemtype.ssh_key"), i18n.T("itemtype.bank"), i18n.T("itemtype.license"), i18n.T("itemtype.passport")}[item.Type] + " · " + item.Name
							if item.Archived {
								label = i18n.Tf("backup.item.archived", label)
							}
							if item.Deleted {
								label = i18n.Tf("backup.item.trashed", label)
							}
							ui.Text(c, label).MaxLines(2).FontSize(12)
						}
						a.backupResourcePreview(c, e)
						if kit.Action(c, i18n.T("backup.import.confirm_create"), "", true, busy).Clicked() {
							a.importBackup()
						}
					}
				} else {
					ui.Text(c, i18n.T("backup.export.selection_hint")).MaxLines(5)
					for _, item := range e.candidates {
						label := "□ " + item.Title
						if e.selected[item.ID] {
							label = "✓ " + item.Title
						}
						if item.Archived {
							label = i18n.Tf("backup.item.archived", label)
						}
						if item.Deleted {
							label = i18n.Tf("backup.item.trashed", label)
						}
						if kit.Action(c, label, "", false, busy || e.confirm).Clicked() {
							e.selected[item.ID] = !e.selected[item.ID]
						}
					}
					if e.confirm {
						if backupSelectionRequiresPassword(e) {
							ui.Text(c, i18n.T("backup.export.reprompt_hint"))
							ui.TextInput(c, &e.exportPassword).Label(i18n.T("backup.export.master_password")).Password().Disabled(busy)
						}
						ui.Text(c, i18n.T("backup.export.confirm_plaintext")).MaxLines(4)
						if kit.Action(c, i18n.T("backup.export.choose_destination"), "", true, busy).Clicked() {
							a.chooseExportFile()
						}
					} else if kit.Action(c, i18n.T("backup.export.continue"), "", true, busy).Clicked() {
						e.confirm = true
					}
				}
			} else {
				ui.Text(c, i18n.T("backup.import.submitted_hint")).MaxLines(4)
				for _, r := range e.results {
					ui.Text(c, vaultwarden.ImportKindText(r.Kind)+" · "+r.Name+"："+vaultwarden.ImportStateText(r.State)).MaxLines(3).FontSize(12)
				}
				a.backupResourceRestoreView(c, e)
				if kit.Action(c, i18n.T("backup.import.sync_results"), "sync", false, busy).Clicked() {
					a.syncVault(false)
				}
			}
			if kit.Action(c, i18n.T("backup.editor.cancel_close"), "", false, false).Clicked() {
				if a.cancel != nil {
					a.cancel()
					a.cancel = nil
				}
				a.advanceEpoch()
				a.clearBackupEditor()
				a.status = i18n.T("backup.import.status_cancelled")
			}
		})
	})
}
func (a *app) backupCurrent(e *backupEditor, epoch uint64) bool {
	return a.epoch == epoch && a.backupEditor == e && a.sessionOwnsSnapshot() && e.revision == a.sessionRevision
}
func backupLease(state *localstore.SnapshotStatus, scope vaultwarden.Scope, revision string) bool {
	return state != nil && state.Available && state.Scope != nil && *state.Scope == scope && state.Revision == revision
}
func backupDialogFilter(format vaultwarden.BackupFormat) mygo.FileFilter {
	if format == vaultwarden.MyGoResources {
		return mygo.FileFilter{Name: i18n.T("backup.format.resources_name"), Extensions: []string{"mygoresources"}}
	}
	if format == vaultwarden.MyGoBackup {
		return mygo.FileFilter{Name: i18n.T("backup.format.backup_name"), Extensions: []string{"mygovault"}}
	}
	return mygo.FileFilter{Name: "Bitwarden JSON", Extensions: []string{"json"}}
}
func (a *app) chooseImportFile() {
	if a.backupEditor != nil && a.backupEditor.format == vaultwarden.MyGoResources {
		a.chooseResourceImportFile()
		return
	}
	e := a.backupEditor
	if a.pending != 0 || e == nil || e.plan != nil || !e.importing || !a.backupCurrent(e, a.epoch) {
		return
	}
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.pending++
	format, scope, revision := e.format, *a.liveScope, e.revision
	parent := a.mainWindow
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(format)}})
		var plan *vaultwarden.ImportPlan
		if err == nil && len(paths) == 1 && ctx.Err() == nil {
			status := callStorage(localstore.Request{Operation: "status"})
			if !status.OK || !backupLease(status.State, scope, revision) {
				err = vaultwarden.ErrConflict
			} else {
				var data []byte
				data, err = fileio.ReadBackupFile(ctx, paths[0])
				if err == nil {
					plan, err = vaultwarden.ParseImport(data, format)
				}
				clear(data)
			}
		}
		a.postUI(func() {
			a.pending--
			defer cancel()
			if !a.backupCurrent(e, epoch) || ctx.Err() != nil {
				plan.Clear()
				return
			}
			a.cancel = nil
			if err != nil {
				a.status = err.Error()
				plan.Clear()
				return
			}
			e.plan = plan
			if plan != nil {
				a.status = i18n.T("backup.import.status_preflight_passed")
			}
		})
	}()
}
func (a *app) chooseExportFile() {
	if a.backupEditor != nil && a.backupEditor.format == vaultwarden.MyGoResources {
		a.chooseResourceExportFile()
		return
	}
	e := a.backupEditor
	if a.pending != 0 || e == nil || e.importing || !e.confirm || !a.backupCurrent(e, a.epoch) {
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
	e.exportIDs = append([]string(nil), ids...)
	e.exportGrants = make(map[string]*vaultwarden.ItemAuthorization)
	grants := e.exportGrants
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.pending++
	format, scope, revision, vault, parent := e.format, *a.liveScope, e.revision, a.vault, a.mainWindow
	go func() {
		defer clear(password)
		// Preflight before showing Save or touching any target file.
		status := callStorage(localstore.Request{Operation: "status"})
		var data []byte
		var err error
		var stage *fileio.StagedFile
		if !status.OK || !backupLease(status.State, scope, revision) {
			err = vaultwarden.ErrConflict
		} else {
			for _, id := range ids {
				if session.PersonalItemRequiresPassword(vault, id) {
					grants[id], err = session.AuthorizePersonalItem(ctx, vault, revision, id, password)
					if err != nil {
						break
					}
				}
			}
			clear(password)
			if err == nil {
				data, err = session.ExportPersonalBackupAuthorized(ctx, vault, ids, format, grants)
			}
		}
		clear(data)
		data = nil // Never retain plaintext while the native Save panel waits.
		if err == nil && ctx.Err() == nil {
			var path string
			path, err = mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(format)}})
			if err == nil && path != "" && ctx.Err() == nil {
				path, err = fileio.BackupOutputPath(path, format)
				if err != nil {
					a.postUI(func() { a.completeBackupExport(e, epoch, ctx, nil, err, cancel) })
					return
				}
				status = callStorage(localstore.Request{Operation: "status"})
				if !status.OK || !backupLease(status.State, scope, revision) {
					err = vaultwarden.ErrConflict
				} else {
					data, err = session.ExportPersonalBackupAuthorized(ctx, vault, ids, format, grants)
					if err == nil {
						stage, err = fileio.StageBackupFile(ctx, path, data)
					}
					clear(data)
					data = nil
				}
			}
		}
		a.postUI(func() { a.completeBackupExport(e, epoch, ctx, stage, err, cancel) })
	}()
}
func (a *app) completeBackupExport(e *backupEditor, epoch uint64, ctx context.Context, stage *fileio.StagedFile, err error, cancel context.CancelFunc) {
	callStorage := a.vaultStorage()
	a.pending--
	defer cancel()
	defer stage.Close()
	if !a.backupCurrent(e, epoch) || ctx.Err() != nil {
		return
	}
	a.cancel = nil
	if err != nil {
		a.status = err.Error()
		return
	}
	if stage == nil {
		a.status = i18n.T("backup.export.status_cancelled")
		return
	}
	// Publication stays on the UI thread so a processed lock/cancel cannot race
	// a later callback writing the final plaintext file. Recheck the storage lease.
	status := callStorage(localstore.Request{Operation: "status"})
	if !status.OK || !backupLease(status.State, *a.liveScope, e.revision) {
		a.status = vaultwarden.ErrConflict.Error()
		return
	}
	if session, ok := a.session.(*vaultwarden.Session); ok {
		err = session.PublishPersonalBackup(ctx, a.vault, e.exportIDs, e.exportGrants, stage.Commit)
	} else {
		err = vaultwarden.ErrPermission
	}
	if err != nil {
		a.status = err.Error()
		return
	}
	e.exportGrants = nil
	e.confirm = false
	a.status = i18n.T("backup.export.status_saved")
}
func (a *app) importBackup() {
	a.importBackupWith(a.postUI, localstore.Call, func() { a.syncVault(false) })
}

func (a *app) importBackupWith(dispatch func(func()), storage func(localstore.Request) localstore.Reply, refresh func()) {
	e := a.backupEditor
	if a.pending != 0 || e == nil || !e.importing || e.plan == nil || e.submitted || !a.backupCurrent(e, a.epoch) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	plan := e.plan
	e.plan = nil
	e.submitted = true
	scope, prior := *a.liveScope, a.snapshot
	a.advanceEpoch()
	epoch := a.epoch
	storage = a.routeStorage(storage, epoch)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	go func() {
		defer plan.Clear()
		var reply localstore.Reply
		var checkpoint *localstore.SnapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			reply, err = localstore.SaveSessionCheckpoint(prior, cp, storage)
			if err == nil {
				prior = reply.State
				checkpoint = reply.State
			}
			return err
		}
		state := storage(localstore.Request{Operation: "status"})
		var result vaultwarden.ImportResult
		var err error
		if !state.OK || !backupLease(state.State, scope, prior.Revision) || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else {
			result, err = session.ImportPersonalBackup(ctx, scope, plan, persist)
		}
		dispatch(func() {
			a.pending--
			defer cancel()
			if a.epoch != epoch || a.backupEditor != e {
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptBackupCheckpoint(e, checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			e.results = result.Entries
			if e.resources != nil {
				for _, entry := range result.Entries {
					if entry.SourceID != "" && entry.ID != "" {
						e.resources.targets[entry.SourceID] = entry.ID
					}
				}
			}
			if err != nil {
				e.results = append(e.results, vaultwarden.ImportEntry{Kind: i18n.T("backup.import.status_stopped"), State: err.Error()})
				a.syncFailed(reply, err)
			}
			if a.backupEditor == e && a.sessionOwnsSnapshot() {
				a.status = i18n.T("backup.import.status_syncing")
				refresh()
			}
		})
	}()
}
func (a *app) reconcileImport(continuations ...*backupContinuation) {
	e := a.backupEditor
	if len(continuations) == 1 {
		continuations[0].resume(a)
	}
	if e != nil && e.recovery != nil && a.sessionOwnsSnapshot() {
		e.revision = a.sessionRevision
		return
	}
	if e == nil || !e.submitted {
		return
	}
	ids := map[string]bool{}
	for _, item := range a.items {
		ids[item.ID] = true
	}
	folders := map[string]bool{}
	for _, folder := range a.folders {
		folders[folder.ID] = true
	}
	for i := range e.results {
		r := &e.results[i]
		if r.ID == "" {
			continue
		}
		found := ids[r.ID]
		if r.Kind == vaultwarden.ImportKindFolder {
			found = folders[r.ID]
		}
		if found {
			r.State = i18n.T("backup.import.status_item_found")
		} else {
			r.State = i18n.T("backup.import.status_item_missing")
		}
	}
}
