// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"errors"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"time"
)

type folderEditor struct {
	id, name, revision        string
	confirm, uncertain, saved bool
}

func (a *app) openFolderEditor(id string) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() || a.vault == nil || a.editor != nil || a.organizationEditor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil {
		return
	}
	e := &folderEditor{id: id, revision: a.sessionRevision}
	if id != "" {
		found := false
		for _, f := range a.folders {
			if f.ID == id {
				e.name = f.Name
				found = true
				break
			}
		}
		if !found {
			return
		}
	}
	a.folderEditor = e
	a.showSettings = false
	a.secretInputVersion++
}

func (a *app) folderPicker(c *ui.Context, selected **string, disabled bool) {
	ui.Text(c, i18n.T("common.folder")).FontSize(12)
	ui.Scroll(c).Height(110).Children(func() {
		ui.Column(c).Gap(4).Children(func() {
			if kit.NavItem(c, i18n.T("common.no_folder"), "vault", "", *selected == nil, disabled).Clicked() {
				*selected = nil
			}
			for _, f := range a.folders {
				if kit.NavItem(c, f.Name, "vault", "", *selected != nil && **selected == f.ID, disabled).Clicked() {
					id := f.ID
					*selected = &id
				}
			}
		})
	})
}

func (a *app) folderEditorView(c *ui.Context) {
	e := a.folderEditor
	ui.Column(c.Key("folder-editor")).Padding(18).Gap(12).Children(func() {
		title := i18n.T("vault.folder.add_title")
		if e.id != "" {
			title = i18n.T("vault.folder.manage_title")
		}
		ui.Text(c, title).FontSize(23)
		ui.TextInput(c, &e.name).Label(i18n.T("vault.folder.name")).Disabled(a.pending != 0 || e.uncertain)
		if e.confirm {
			ui.Text(c, i18n.T("vault.folder.confirm_delete_hint")).MaxLines(3)
			if kit.Action(c, i18n.T("vault.folder.confirm_delete"), "", true, a.pending != 0 || e.uncertain).Clicked() {
				a.mutateFolder(true)
			}
			if kit.Action(c, i18n.T("vault.folder.cancel_delete"), "", false, a.pending != 0).Clicked() {
				e.confirm = false
			}
		} else {
			if kit.Action(c, i18n.T("vault.folder.save"), "", true, a.pending != 0 || e.uncertain || e.name == "").Clicked() {
				a.mutateFolder(false)
			}
			if e.id != "" && kit.Action(c, i18n.T("vault.folder.delete"), "", false, a.pending != 0 || e.uncertain).Clicked() {
				e.confirm = true
			}
		}
		if e.uncertain {
			ui.Text(c, i18n.T("vault.folder.uncertain_hint")).FontSize(12)
			if kit.Action(c, i18n.T("vault.editor.sync_verify"), "sync", false, a.pending != 0).Clicked() {
				a.syncVault(false)
			}
		}
		if kit.Action(c, i18n.T("vault.folder.close"), "", false, a.pending != 0).Clicked() {
			a.folderEditor = nil
		}
	})
}

func (a *app) mutateFolder(remove bool) {
	e := a.folderEditor
	if a.pending != 0 || e == nil || e.uncertain || !a.sessionOwnsSnapshot() {
		return
	}
	if e.revision != a.sessionRevision {
		a.status = i18n.T("vault.folder.err_revision_changed")
		return
	}
	if remove && (!e.confirm || e.id == "") {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	scope, prior := *a.liveScope, a.snapshot
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	a.cancel = cancel
	a.pending++
	a.status = i18n.T("vault.folder.status_saving")
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
		current := callStorage(localstore.Request{Operation: "status"})
		var err error
		if !current.OK || current.State == nil || current.State.Revision != prior.Revision || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else if remove {
			err = session.DeleteFolder(ctx, scope, e.id, persist)
		} else {
			_, err = session.SaveFolder(ctx, scope, e.id, e.name, persist)
		}
		a.dispatchUI(func() { a.completeFolderMutation(epoch, e, checkpoint, reply, err, cancel) })
	}()
}

func (a *app) completeFolderMutation(epoch uint64, e *folderEditor, checkpoint *localstore.SnapshotStatus, reply localstore.Reply, err error, cancel context.CancelFunc) {
	defer cancel()
	a.pending--
	if a.epoch != epoch {
		*e = folderEditor{}
		return
	}
	a.cancel = nil
	if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
		a.stopNetwork()
		a.status = vaultwarden.ErrIdentity.Error()
		return
	}
	if err != nil {
		var unknown *vaultwarden.MutationUncertainError
		e.uncertain = errors.As(err, &unknown)
		a.syncFailed(reply, err)
		return
	}
	e.uncertain, e.saved = true, true
	a.status = i18n.T("vault.folder.status_submitted")
	a.syncVault(false)
}
