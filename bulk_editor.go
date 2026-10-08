// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"time"
)

type bulkEditor struct {
	revision           string
	candidates         []displayCredential
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
	{vaultwarden.CipherMove, "移动到文件夹"}, {vaultwarden.CipherTrash, "移入回收站"}, {vaultwarden.CipherRestore, "恢复"}, {vaultwarden.CipherArchive, "归档"}, {vaultwarden.CipherUnarchive, "取消归档"}, {vaultwarden.CipherDeletePermanently, "永久删除"},
}

func (a *app) bulkEditorView(c *ui.Context) {
	e := a.bulkEditor
	ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Padding(18).Gap(10).Children(func() {
			ui.Text(c, "批量管理").FontSize(23)
			if e.submitted {
				ui.Text(c, "本批操作不会再次提交。以下为同步后的逐项状态；若尚未核对，请同步后查看。").MaxLines(3)
				for _, result := range e.results {
					ui.Text(c, result).MaxLines(2).FontSize(12)
				}
				if action(c, "同步核对批量结果", "sync", false, a.pending != 0).Clicked() {
					a.syncVault(false)
				}
			} else {
				ui.Text(c, "当前仅管理个人项目。请选择项目及操作；永久删除仅允许个人回收站中的项目，需要再次验证的项目请单独处理。").MaxLines(3).FontSize(12)
				for _, item := range e.candidates {
					label := "□ " + item.Title
					if e.selected[item.ID] {
						label = "✓ " + item.Title
					}
					if action(c, label, "", false, a.pending != 0 || e.confirm).Clicked() {
						e.selected[item.ID] = !e.selected[item.ID]
					}
				}
				for _, op := range bulkActions {
					if navItem(c, op.label, "vault", "", e.action == op.action, a.pending != 0 || e.confirm).Clicked() {
						e.action = op.action
					}
				}
				if e.action == vaultwarden.CipherMove {
					a.folderPicker(c, &e.folderID, a.pending != 0 || e.confirm)
				}
				if e.confirm {
					message := "确认对选中的项目执行操作？"
					if e.action == vaultwarden.CipherDeletePermanently {
						message = "永久删除选中的回收站项目及其附件，无法恢复。确认继续？"
					}
					ui.Text(c, message).MaxLines(3)
					if action(c, "确认执行批量操作", "", true, a.pending != 0).Clicked() {
						a.mutateBulk()
					}
					if action(c, "取消批量确认", "", false, a.pending != 0).Clicked() {
						e.confirm = false
					}
				} else if action(c, "继续批量操作", "", true, a.pending != 0).Clicked() {
					e.confirm = true
				}
			}
			if action(c, "关闭批量管理", "", false, a.pending != 0).Clicked() {
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
		a.status = "密码库版本已变化，请重新选择项目。"
		return
	}
	ids := []string{}
	for _, item := range e.candidates {
		if !e.selected[item.ID] {
			continue
		}
		if item.RequiresPassword {
			a.status = "所选项目需要再次验证主密码，请在单项编辑中完成操作。未发送批量请求。"
			return
		}
		if e.action == vaultwarden.CipherDeletePermanently && !item.Deleted {
			a.status = "永久删除仅允许回收站中的项目。"
			return
		}
		ids = append(ids, item.ID)
	}
	if len(ids) == 0 {
		a.status = "请先选择项目。"
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
	a.status = "正在执行批量操作…"
	go func() {
		var reply storageReply
		var checkpoint *snapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			reply, err = saveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior = reply.State
				checkpoint = reply.State
			}
			return err
		}
		current := callStorage(storageRequest{Operation: "status"})
		var err error
		if !current.OK || current.State == nil || current.State.Revision != prior.Revision || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else {
			err = session.ChangePersonalCiphers(ctx, scope, vault, ids, e.action, e.folderID, persist)
		}
		a.window.Update(func() { a.completeBulkMutation(epoch, e, checkpoint, reply, err, cancel) })
	}()
}

func (a *app) completeBulkMutation(epoch uint64, e *bulkEditor, checkpoint *snapshotStatus, reply storageReply, err error, cancel context.CancelFunc) {
	defer cancel()
	a.pending--
	if a.epoch != epoch {
		*e = bulkEditor{}
		return
	}
	a.cancel = nil
	if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
		a.stopNetwork()
		a.status = vaultwarden.ErrIdentity.Error()
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
			e.results = append(e.results, item.Title+"：尚未核对")
		}
	}
	a.status = "批量操作已结束，正在同步逐项核对（服务器可能只完成部分项目）…"
	a.syncVault(false)
}

// This reports observed state, not a claim that the batch was atomic or that
// an error proves no changes. It is only called after authenticated publication.
func (a *app) reconcileBulk() {
	e := a.bulkEditor
	if e == nil || !e.submitted {
		return
	}
	current := map[string]displayCredential{}
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
		result := "当前状态未符合目标，请检查后重新选择操作"
		if ok {
			matched++
			result = "当前状态已符合目标"
		}
		e.results = append(e.results, item.Title+"："+result)
	}
	a.status = fmt.Sprintf("已同步核对 %d 项，其中 %d 项当前状态符合目标。", total, matched)
}
