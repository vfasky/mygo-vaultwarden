// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/fileio"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type backupEditor struct {
	revision                      string
	format                        vaultwarden.BackupFormat
	candidates                    []localstore.DisplayCredential
	selected                      map[string]bool
	importing, confirm, submitted bool
	importRun                     *backupImportController
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
		if a.backupEditor.importRun != nil {
			a.backupEditor.importRun.Close()
		}
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
	if a.backupEditor != nil {
		a.showBackupWindow()
		return
	}
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
	a.showBackupWindow()
}
func (a *app) backupEditorView(c *ui.Context) {
	e := a.backupEditor
	if e == nil || !a.unlocked() || a.showLogin {
		kit.EmptyState(c, "lock", i18n.T("app.list.status_locked"), "")
		return
	}
	if e.recovery != nil {
		a.cipherShareRecoveryView(c, e)
		return
	}
	busy := a.pending != 0
	root := ui.Column(c).Grow(1).MinHeight(0).Gap(16)
	mode := ui.Local(root, e, func() int {
		if e.importing {
			return 1
		}
		return 0
	})
	root.Children(func() {
		kit.PageHeader(c, i18n.T("backup.editor.title"), i18n.T("backup.editor.description"), func() {
			if !e.confirm && e.plan == nil && !e.submitted && !busy {
				kit.Segmented(c.Key("backup-mode"), mode, i18n.T("backup.export.switch_mode"), i18n.T("backup.import.switch_mode")).Width(180)
				e.importing = *mode == 1
			} else {
				step := i18n.T("backup.export.switch_mode")
				if e.importing {
					step = i18n.T("backup.import.switch_mode")
				}
				if e.confirm || e.plan != nil {
					step = i18n.T("backup.editor.step_confirmation")
				}
				if e.submitted {
					step = i18n.T("backup.editor.step_results")
				}
				kit.Pill(c, step, kit.White, kit.Purple)
			}
		})
		ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).Gap(16).Children(func() {
				if !e.submitted {
					// Import and export use Bitwarden's JSON only: the app defines no
					// file format of its own for users.
					kit.Notice(c, kit.ToneWarning, i18n.T("backup.editor.plaintext_hint"))
					if e.importing {
						a.backupImportPreviewView(c, e, busy)
					} else {
						if e.confirm {
							kit.Notice(c, kit.ToneWarning, i18n.T("backup.export.confirm_plaintext"))
							if backupSelectionRequiresPassword(e) {
								kit.Field(c, i18n.T("backup.export.master_password"), i18n.T("backup.export.reprompt_hint"), func() {
									kit.Input(ui.TextInput(c, &e.exportPassword).Label(i18n.T("backup.export.master_password"))).Password().Disabled(busy)
								})
							}
						}
						kit.Notice(c, kit.ToneInfo, i18n.T("backup.export.selection_hint"))
						a.backupSelectionView(c, e, busy || e.confirm)
					}
				} else {
					kit.Notice(c, kit.ToneWarning, i18n.T("backup.import.submitted_hint"))
					if len(e.results) > 0 {
						kit.Section(c, i18n.T("backup.editor.step_results"), func() {
							for _, r := range e.results {
								ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
									ui.Column(c).Grow(1).MinWidth(0).Gap(4).Children(func() {
										ui.Text(c, r.Name).FontSize(13).SingleLine()
										ui.Text(c, vaultwarden.ImportKindText(r.Kind)).FontSize(11).TextColor(kit.Muted)
									})
									kit.Pill(c, vaultwarden.ImportStateText(r.State), kit.Panel, kit.Purple)
								})
							}
						})
					} else if e.resources == nil {
						kit.EmptyState(c, "sync", i18n.T("backup.import.no_receipts"), "")
					}
					a.backupResourceRestoreView(c, e)
				}
			})
		})
		kit.ActionBar(c, func() {
			status := a.status
			if status == "" && !e.importing {
				status = backupSelectionSummary(e)
			}
			ui.Text(c, status).FontSize(11.5).TextColor(kit.Muted).Grow(1).MinWidth(0).MaxLines(2).Tooltip(status)
			ui.Spacer(c)
			if kit.Button(c, i18n.T("backup.editor.cancel_close"), "", kit.ButtonSecondary, false).Clicked() {
				a.closeBackupWindow()
				return
			}
			switch {
			case e.submitted:
				if kit.Button(c, i18n.T("backup.import.sync_results"), "sync", kit.ButtonSecondary, busy).Clicked() {
					a.syncVault(false)
				}
			case e.importing && e.plan != nil:
				if kit.Button(c, i18n.T("backup.import.confirm_create"), "", kit.ButtonPrimary, busy).Clicked() {
					a.importBackup()
				}
			case !e.importing && e.confirm:
				if kit.Button(c, i18n.T("backup.export.choose_destination"), "", kit.ButtonPrimary, busy).Clicked() {
					a.chooseExportFile()
				}
			case !e.importing:
				if kit.Button(c, i18n.T("backup.export.continue"), "", kit.ButtonPrimary, busy).Clicked() {
					e.confirm = true
				}
			}
		})
	})
}

func backupSelectionSummary(e *backupEditor) string {
	selected := 0
	for _, item := range e.candidates {
		if e.selected[item.ID] {
			selected++
		}
	}
	return i18n.Tf("backup.export.selection_count", selected, len(e.candidates))
}

func (a *app) backupSelectionView(c *ui.Context, e *backupEditor, disabled bool) {
	section := ui.Column(c.Key("backup-selection")).Gap(8)
	query := ui.Local(section, e, func() string { return "" })
	list := ui.Local(section, "list", func() ui.ListState { return ui.ListState{} })
	section.Children(func() {
		kit.Section(c, i18n.T("backup.export.items_title"), func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				kit.Input(ui.TextInput(c, query).Label(i18n.T("backup.export.search")).Placeholder(i18n.T("backup.export.search"))).Grow(1).MinWidth(100)
				if kit.Button(c, i18n.T("backup.export.select_all"), "", kit.ButtonQuiet, disabled).Clicked() {
					for _, item := range e.candidates {
						e.selected[item.ID] = true
					}
				}
				if kit.Button(c, i18n.T("backup.export.select_none"), "", kit.ButtonQuiet, disabled).Clicked() {
					clear(e.selected)
				}
				if kit.Button(c, i18n.T("backup.export.select_current"), "", kit.ButtonQuiet, disabled).Clicked() {
					clear(e.selected)
					for _, item := range a.filteredItems() {
						if item.OrganizationID == "" {
							e.selected[item.ID] = true
						}
					}
				}
			})
			ui.Text(c, backupSelectionSummary(e)).FontSize(11.5).TextColor(kit.Muted)
			var visible []localstore.DisplayCredential
			search := strings.ToLower(strings.TrimSpace(*query))
			for _, item := range e.candidates {
				if search == "" || strings.Contains(strings.ToLower(item.Title), search) || strings.Contains(strings.ToLower(item.Username), search) {
					visible = append(visible, item)
				}
			}
			if len(visible) == 0 {
				kit.EmptyState(c, "search", i18n.T("backup.export.empty_selection"), "").Height(160)
				return
			}
			list.Key = func(i int) any { return visible[i].ID }
			_, windowHeight := c.Size()
			// Keep the list usable in small windows; taller windows give the
			// virtual list the additional room instead of adding blank space.
			listHeight := max(float32(120), windowHeight-470)
			ui.List(c, list, len(visible), func(i int) {
				item := visible[i]
				title := item.Title
				if item.Archived {
					title = i18n.Tf("backup.item.archived", title)
				}
				if item.Deleted {
					title = i18n.Tf("backup.item.trashed", title)
				}
				detail := item.Username
				if detail == "" {
					detail = websiteHost(item.URL)
				}
				checked := e.selected[item.ID]
				if kit.CheckRow(c.Key(item.ID), &checked, title, detail, disabled).Changed() {
					e.selected[item.ID] = checked
				}
			}).Height(listHeight)
		})
	})
}

func (a *app) backupImportPreviewView(c *ui.Context, e *backupEditor, busy bool) {
	if e.plan == nil {
		ui.Column(c).Padding(24).Gap(16).AlignItems(ui.Center).Children(func() {
			kit.Icon(c, "file", 36).TextColor(kit.Purple)
			ui.Text(c, i18n.T("backup.import.format_hint")).TextAlign(ui.Center).FontSize(13).MaxLines(3)
			if kit.Button(c, i18n.T("backup.import.choose_file"), "", kit.ButtonPrimary, busy).Clicked() {
				a.chooseImportFile()
			}
			if organizationUIEnabled && kit.Button(c, i18n.T("backup.import.open_share_recovery"), "", kit.ButtonQuiet, busy).Clicked() {
				a.chooseCipherShareRecovery()
			}
		})
		return
	}
	ui.Row(c).Gap(12).Children(func() {
		for _, stat := range []struct {
			label string
			n     int
		}{
			{i18n.T("backup.import.items_count"), e.plan.Items}, {i18n.T("backup.import.folders_count"), e.plan.Folders},
			{i18n.T("backup.import.archived_count"), e.plan.Archived}, {i18n.T("backup.import.trashed_count"), e.plan.Deleted},
		} {
			ui.Column(c).Grow(1).Basis(0).Padding(14).Gap(6).Background(kit.White).Radius(kit.CardRadius).Children(func() {
				ui.Text(c, i18n.Tf("backup.import.stat_value", stat.n)).FontSize(22).FontWeight(650)
				ui.Text(c, stat.label).FontSize(12).TextColor(kit.Muted)
			})
		}
	})
	kit.Notice(c, kit.ToneWarning, i18n.T("backup.import.confirm_create_hint"))
	kit.Section(c, i18n.T("backup.import.preview_title"), func() {
		for _, item := range e.plan.PreviewItems() {
			label := item.Name
			if item.Archived {
				label = i18n.Tf("backup.item.archived", label)
			}
			if item.Deleted {
				label = i18n.Tf("backup.item.trashed", label)
			}
			typeName := []string{"", i18n.T("itemtype.login"), i18n.T("itemtype.note"), i18n.T("itemtype.card"), i18n.T("itemtype.identity"), i18n.T("itemtype.ssh_key"), i18n.T("itemtype.bank"), i18n.T("itemtype.license"), i18n.T("itemtype.passport")}[item.Type]
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Text(c, label).FontSize(13).MaxLines(2).Grow(1).MinWidth(0)
				kit.Pill(c, typeName, kit.Panel, kit.Muted)
			})
		}
	})
	a.backupResourcePreview(c, e)
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
	parent := a.backupParent()
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(format)}})
		var plan *vaultwarden.ImportPlan
		if err == nil && len(paths) == 1 && ctx.Err() == nil {
			status := callStorage(localstore.Request{Operation: localstore.OperationStatus})
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
				a.status = vaultwarden.ErrorMessage(err)
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
	format, scope, revision, vault, parent := e.format, *a.liveScope, e.revision, a.vault, a.backupParent()
	go func() {
		defer clear(password)
		// Preflight before showing Save or touching any target file.
		status := callStorage(localstore.Request{Operation: localstore.OperationStatus})
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
			path, err = send.ChooseExportPath(ctx, mygo.SaveDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(format)}})
			if err == nil && path != "" && ctx.Err() == nil {
				path, err = fileio.BackupOutputPath(path, format)
				if err != nil {
					a.postUI(func() { a.completeBackupExport(e, epoch, ctx, nil, err, cancel) })
					return
				}
				status = callStorage(localstore.Request{Operation: localstore.OperationStatus})
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
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	if stage == nil {
		a.status = i18n.T("backup.export.status_cancelled")
		return
	}
	// Publication stays on the UI thread so a processed lock/cancel cannot race
	// a later callback writing the final plaintext file. Recheck the storage lease.
	status := callStorage(localstore.Request{Operation: localstore.OperationStatus})
	if !status.OK || !backupLease(status.State, *a.liveScope, e.revision) {
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrConflict)
		return
	}
	if session, ok := a.session.(*vaultwarden.Session); ok {
		err = session.PublishPersonalBackup(ctx, a.vault, e.exportIDs, e.exportGrants, stage.Commit)
	} else {
		err = vaultwarden.ErrPermission
	}
	if err != nil {
		a.status = vaultwarden.ErrorMessage(err)
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
	host := appBackupImportHost{app: a, editor: e, epoch: epoch, refresh: refresh}
	e.importRun = newBackupImportController(session, host, storage, dispatch, scope, prior, plan)
	a.cancel = e.importRun.Close
	a.pending++
	e.importRun.Start()
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
