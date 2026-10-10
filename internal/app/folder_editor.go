// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"errors"
	"github.com/egoist/mygo/ui"
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
	ui.Text(c, "文件夹").FontSize(12)
	ui.Scroll(c).Height(110).Children(func() {
		ui.Column(c).Gap(4).Children(func() {
			if kit.NavItem(c, "无文件夹", "vault", "", *selected == nil, disabled).Clicked() {
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
		title := "新建文件夹"
		if e.id != "" {
			title = "管理文件夹"
		}
		ui.Text(c, title).FontSize(23)
		ui.TextInput(c, &e.name).Label("文件夹名称").Disabled(a.pending != 0 || e.uncertain)
		if e.confirm {
			ui.Text(c, "删除文件夹后，项目会变为无文件夹，项目本身不会删除。确认继续？").MaxLines(3)
			if kit.Action(c, "确认删除文件夹", "", true, a.pending != 0 || e.uncertain).Clicked() {
				a.mutateFolder(true)
			}
			if kit.Action(c, "取消删除", "", false, a.pending != 0).Clicked() {
				e.confirm = false
			}
		} else {
			if kit.Action(c, "保存文件夹", "", true, a.pending != 0 || e.uncertain || e.name == "").Clicked() {
				a.mutateFolder(false)
			}
			if e.id != "" && kit.Action(c, "删除文件夹", "", false, a.pending != 0 || e.uncertain).Clicked() {
				e.confirm = true
			}
		}
		if e.uncertain {
			ui.Text(c, "请先同步核对结果。此表单不会再次提交。").FontSize(12)
			if kit.Action(c, "同步核对", "sync", false, a.pending != 0).Clicked() {
				a.syncVault(false)
			}
		}
		if kit.Action(c, "关闭文件夹编辑", "", false, a.pending != 0).Clicked() {
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
		a.status = "密码库版本已变化，文件夹表单已保留。请核对最新状态后重新编辑。"
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
	a.status = "正在保存文件夹…"
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
	a.status = "文件夹修改已提交，正在同步核对…"
	a.syncVault(false)
}
