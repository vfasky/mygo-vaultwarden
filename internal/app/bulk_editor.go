// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"time"
)

type bulkEditor struct {
	revision           string
	candidates         []localstore.DisplayCredential
	selected           map[string]bool
	folderID           *string
	action             vaultwarden.CipherAction
	confirm, submitted bool
	results            []string
}

func (a *app) openBulkEditor(emptyTrash bool) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() || a.vault == nil || a.editor != nil || a.organizationEditor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil {
		return
	}
	e := &bulkEditor{revision: a.sessionRevision, selected: map[string]bool{}}
	if emptyTrash {
		for _, item := range a.items {
			if item.Deleted && item.OrganizationID == "" {
				e.candidates = append(e.candidates, item)
				e.selected[item.ID] = true
			}
		}
		e.action = vaultwarden.CipherDeletePermanently
	} else {
		for _, item := range a.filteredItems() {
			if item.OrganizationID == "" {
				e.candidates = append(e.candidates, item)
			}
		}
		e.action = vaultwarden.CipherMove
	}
	a.bulkEditor = e
	a.showSettings = false
}

var bulkActions = []struct {
	action vaultwarden.CipherAction
	label  string
}{
	{vaultwarden.CipherMove, "vault.bulk.move_to_folder"},
	{vaultwarden.CipherTrash, "vault.editor.move_to_trash"},
	{vaultwarden.CipherRestore, "common.restore"},
	{vaultwarden.CipherArchive, "common.archive"},
	{vaultwarden.CipherUnarchive, "common.unarchive"},
	{vaultwarden.CipherDeletePermanently, "common.delete_permanently"},
}

func (a *app) bulkEditorView(c *ui.Context) {
	e := a.bulkEditor
	ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Padding(18).Gap(10).Children(func() {
			ui.Text(c, i18n.T("vault.bulk.title")).FontSize(23)
			if e.submitted {
				ui.Text(c, i18n.T("vault.bulk.submitted_hint")).MaxLines(3)
				for _, result := range e.results {
					ui.Text(c, result).MaxLines(2).FontSize(12)
				}
				if kit.Action(c, i18n.T("vault.bulk.sync_verify"), "sync", false, a.pending != 0).Clicked() {
					a.syncVault(false)
				}
			} else {
				ui.Text(c, i18n.T("vault.bulk.description")).MaxLines(3).FontSize(12)
				for _, item := range e.candidates {
					label := "□ " + item.Title
					if e.selected[item.ID] {
						label = "✓ " + item.Title
					}
					if kit.Action(c, label, "", false, a.pending != 0 || e.confirm).Clicked() {
						e.selected[item.ID] = !e.selected[item.ID]
					}
				}
				for _, op := range bulkActions {
					if kit.NavItem(c, i18n.T(op.label), "vault", "", e.action == op.action, a.pending != 0 || e.confirm).Clicked() {
						e.action = op.action
					}
				}
				if e.action == vaultwarden.CipherMove {
					a.folderPicker(c, &e.folderID, a.pending != 0 || e.confirm)
				}
				if e.confirm {
					message := i18n.T("vault.bulk.confirm_action_hint")
					if e.action == vaultwarden.CipherDeletePermanently {
						message = i18n.T("vault.bulk.confirm_delete_hint")
					}
					ui.Text(c, message).MaxLines(3)
					if kit.Action(c, i18n.T("vault.bulk.confirm_action"), "", true, a.pending != 0).Clicked() {
						a.mutateBulk()
					}
					if kit.Action(c, i18n.T("vault.bulk.cancel_confirmation"), "", false, a.pending != 0).Clicked() {
						e.confirm = false
					}
				} else if kit.Action(c, i18n.T("vault.bulk.continue"), "", true, a.pending != 0).Clicked() {
					e.confirm = true
				}
			}
			if kit.Action(c, i18n.T("vault.bulk.close"), "", false, a.pending != 0).Clicked() {
				a.bulkEditor = nil
			}
		})
	})
}

func (a *app) mutateBulk() {
	e := a.bulkEditor
	if a.pending != 0 || e == nil || !e.confirm || e.submitted || !a.sessionOwnsSnapshot() {
		return
	}
	if e.revision != a.sessionRevision {
		a.status = i18n.T("vault.bulk.err_revision_changed")
		return
	}
	ids := []string{}
	for _, item := range e.candidates {
		if !e.selected[item.ID] {
			continue
		}
		if item.RequiresPassword {
			a.status = i18n.T("vault.bulk.err_reprompt_required")
			return
		}
		if e.action == vaultwarden.CipherDeletePermanently && !item.Deleted {
			a.status = i18n.T("vault.bulk.err_trash_required")
			return
		}
		ids = append(ids, item.ID)
	}
	if len(ids) == 0 {
		a.status = i18n.T("vault.bulk.err_selection_required")
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	scope, prior, vault := *a.liveScope, a.snapshot, a.vault
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	a.cancel = cancel
	a.pending++
	e.submitted = true
	a.status = i18n.T("vault.bulk.status_applying")
	go func() {
		var reply localstore.Reply
		var checkpoint *localstore.SnapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			reply, err = localstore.SaveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior = reply.State
				checkpoint = reply.State
			}
			return err
		}
		current := callStorage(localstore.Request{Operation: localstore.OperationStatus})
		var err error
		if !current.OK || current.State == nil || current.State.Revision != prior.Revision || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else {
			err = session.ChangePersonalCiphers(ctx, scope, vault, ids, e.action, e.folderID, persist)
		}
		a.dispatchUI(func() { a.completeBulkMutation(epoch, e, checkpoint, reply, err, cancel) })
	}()
}

func (a *app) completeBulkMutation(epoch uint64, e *bulkEditor, checkpoint *localstore.SnapshotStatus, reply localstore.Reply, err error, cancel context.CancelFunc) {
	defer cancel()
	a.pending--
	if a.epoch != epoch {
		*e = bulkEditor{}
		return
	}
	a.cancel = nil
	if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
		a.stopNetwork()
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
		return
	}
	if err != nil {
		a.syncFailed(reply, err)
	}
	if a.bulkEditor != e || !a.sessionOwnsSnapshot() {
		return
	}
	e.results = nil
	for _, item := range e.candidates {
		if e.selected[item.ID] {
			e.results = append(e.results, i18n.Tf("vault.bulk.status_item_unverified", item.Title))
		}
	}
	a.status = i18n.T("vault.bulk.status_syncing")
	a.syncVault(false)
}

// This reports observed state, not a claim that the batch was atomic or that
// an error proves no changes. It is only called after authenticated publication.
func (a *app) reconcileBulk() {
	e := a.bulkEditor
	if e == nil || !e.submitted {
		return
	}
	current := map[string]localstore.DisplayCredential{}
	for _, item := range a.items {
		current[item.ID] = item
	}
	e.results = nil
	matched, total := 0, 0
	for _, item := range e.candidates {
		if !e.selected[item.ID] {
			continue
		}
		total++
		actual, exists := current[item.ID]
		ok := false
		switch e.action {
		case vaultwarden.CipherMove:
			folder := ""
			if e.folderID != nil {
				folder = *e.folderID
			}
			ok = exists && actual.FolderID == folder
		case vaultwarden.CipherTrash:
			ok = exists && actual.Deleted
		case vaultwarden.CipherRestore:
			ok = exists && !actual.Deleted
		case vaultwarden.CipherArchive:
			ok = exists && actual.Archived
		case vaultwarden.CipherUnarchive:
			ok = exists && !actual.Archived
		case vaultwarden.CipherDeletePermanently:
			ok = !exists
		}
		result := i18n.T("vault.bulk.status_item_unmatched")
		if ok {
			matched++
			result = i18n.T("vault.bulk.status_item_matched")
		}
		e.results = append(e.results, item.Title+"："+result)
	}
	a.status = i18n.Tf("vault.bulk.status_verified", total, matched)
}
