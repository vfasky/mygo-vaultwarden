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
	a.secretInputVersion++
}

type editorOption struct{ value, label string }

// editorSelect keeps stable IDs separate from translated or duplicate display names.
func editorSelect(c *ui.Context, label string, selected *string, options []editorOption, disabled bool) ui.Element {
	text := *selected
	for _, option := range options {
		if option.value == *selected {
			text = option.label
			break
		}
	}
	sel := ui.SelectBase(c, selected)
	kit.Input(sel.Trigger).Label(label).Disabled(disabled).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, text).Grow(1).MinWidth(0).SingleLine()
		kit.Icon(c, "chevron", 12).TextColor(kit.Muted)
	})
	sel.Popup(func(panel ui.Element) {
		panel.Padding(4).Background(kit.White).Border(1, kit.ControlBorder).Radius(kit.ControlRadius)
		for _, option := range options {
			item := sel.Item(option.value).Label(option.label).Padding(8, 12).Radius(6).Disabled(disabled)
			if item.Highlighted() {
				item.Background(kit.Selected).TextColor(kit.Purple)
			}
			item.Children(func() { ui.Text(c, option.label).FontSize(13).SingleLine() })
		}
	})
	return sel.Trigger
}

func (a *app) folderPicker(c *ui.Context, selected **string, disabled bool) {
	kit.Field(c, i18n.T("common.folder"), "", func() {
		id := ""
		if *selected != nil {
			id = **selected
		}
		options := []editorOption{{"", i18n.T("common.no_folder")}}
		for _, folder := range a.folders {
			options = append(options, editorOption{folder.ID, folder.Name})
		}
		if editorSelect(c, i18n.T("common.folder"), &id, options, disabled).Changed() {
			if id == "" {
				*selected = nil
			} else {
				*selected = &id
			}
		}
	})
}

func (a *app) folderEditorView(c *ui.Context) {
	e := a.folderEditor
	ui.Column(c.Key("folder-editor")).Grow(1).MinHeight(0).Children(func() {
		title := i18n.T("vault.folder.add_title")
		if e.id != "" {
			title = i18n.T("vault.folder.manage_title")
		}
		if a.drawerHeader(c, title, i18n.T("vault.folder.description")) {
			return
		}
		ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).Padding(20).Gap(16).Children(func() {
				kit.Section(c, i18n.T("vault.editor.basic_information"), func() {
					kit.Field(c, i18n.T("vault.folder.name"), "", func() {
						kit.Input(ui.TextInput(c, &e.name).Label(i18n.T("vault.folder.name")).Disabled(a.pending != 0 || e.uncertain))
					})
				})
				if e.uncertain {
					kit.Notice(c, kit.ToneWarning, i18n.T("vault.folder.uncertain_hint"))
					if kit.Action(c, i18n.T("vault.editor.sync_verify"), "sync", false, a.pending != 0).Clicked() {
						a.syncVault(false)
					}
				}
			})
		})
		kit.ActionBar(c, func() {
			if e.id != "" && kit.Button(c, i18n.T("vault.folder.delete"), "", kit.ButtonDanger, a.pending != 0 || e.uncertain).Clicked() {
				e.confirm = true
			}
			ui.Spacer(c)
			if !e.confirm && kit.Action(c, i18n.T("vault.folder.save"), "", true, a.pending != 0 || e.uncertain || e.name == "").Clicked() {
				a.mutateFolder(false)
			}
		}).Margin(0, 20) // in line with the padded content above
	})
	if e.confirm {
		kit.ConfirmDialog(c, "folder-delete", i18n.T("vault.folder.delete"), e.name+"\n\n"+i18n.T("vault.folder.confirm_delete_hint"), i18n.T("vault.folder.confirm_delete"), i18n.T("vault.folder.cancel_delete"), a.pending != 0 || e.uncertain,
			func() { a.mutateFolder(true) }, func() {
				if a.pending == 0 {
					e.confirm = false
				}
			})
	}
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
		current := callStorage(localstore.Request{Operation: localstore.OperationStatus})
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
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
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
