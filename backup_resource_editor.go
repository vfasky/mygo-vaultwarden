// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type backupResourceRow struct {
	resource                    vaultwarden.BackupResource
	target, attachmentID, state string
	problem                     string
}
type backupResourceEditor struct {
	plan         *vaultwarden.ResourceImportPlan
	rows         []backupResourceRow
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
		e.rows = append(e.rows, backupResourceRow{resource: resource, state: "未执行"})
	}
	return e
}
func (a *app) backupResourcePreview(c *ui.Context, e *backupEditor) {
	if e.resources == nil {
		return
	}
	ui.Text(c, "此自有资源格式保留每个文件的来源编号、文件名及校验值。先创建元数据，再按明确目标编号逐文件上传、同步和下载核验；这是多请求操作。含附件的回收站项目先保持活动，文件全部核验后再明确移入回收站。中途停止不会自动删除或重试。").MaxLines(7)
	for _, row := range e.resources.rows {
		ui.Text(c, fmt.Sprintf("%s · %s/%s · %d 字节", row.resource.FileName, row.resource.CipherID, row.resource.AttachmentID, row.resource.Size)).FontSize(12)
	}
	if action(c, "仅继续附件恢复，使用已存在的明确目标编号（不创建项目）", "", false, a.pending != 0).Clicked() {
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
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	scope, revision, parent := *a.liveScope, e.revision, a.window
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(vaultwarden.MyGoResources)}})
		var resources *vaultwarden.ResourceImportPlan
		var metadata *vaultwarden.ImportPlan
		if err == nil && len(paths) == 1 && ctx.Err() == nil {
			state := callStorage(storageRequest{Operation: "status"})
			if !state.OK || !backupLease(state.State, scope, revision) {
				err = vaultwarden.ErrConflict
			} else {
				var file *os.File
				file, err = openAttachmentInput(paths[0])
				if err == nil {
					resources, err = vaultwarden.ParseResourceImport(ctx, file)
				}
				if err == nil {
					metadata, err = resources.PersonalRestoreMetadata()
				}
			}
		}
		a.window.Update(func() {
			a.pending--
			defer cancel()
			if !a.backupCurrent(e, epoch) || ctx.Err() != nil || err != nil {
				resources.Clear()
				metadata.Clear()
				if a.backupEditor == e && err != nil {
					a.status = err.Error()
				}
				return
			}
			a.cancel = nil
			if resources != nil {
				e.resources = resourceEditor(resources)
				e.plan = metadata
				a.status = "资源与全部文件哈希已预检，请核对创建或继续恢复范围。"
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
		a.status = "请先勾选导出的项目。"
		return
	}
	password := []byte(e.exportPassword)
	e.exportPassword = ""
	if backupSelectionRequiresPassword(e) && len(password) == 0 {
		a.status = "请提供主密码以授权所选受保护项目。"
		return
	}
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	scope, revision, vault, parent, prior := *a.liveScope, e.revision, a.vault, a.window, a.snapshot
	go func() {
		defer clear(password)
		var checkpoint *snapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := saveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(vaultwarden.MyGoResources)}})
		var stage *stagedBackup
		var proof *vaultwarden.ResourceBackupPublication
		grants := map[string]*vaultwarden.ItemAuthorization{}
		if err == nil && path != "" && ctx.Err() == nil {
			path, err = backupOutputPath(path, vaultwarden.MyGoResources)
			state := callStorage(storageRequest{Operation: "status"})
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
				stage, err = stageBackupStream(ctx, path, func(file *os.File) error {
					var err error
					proof, err = session.WriteResourceBackup(ctx, vault, ids, "", grants, true, file, persist)
					return err
				})
			}
		}
		a.window.Update(func() {
			a.pending--
			defer cancel()
			defer stage.Close()
			if a.backupEditor != e || a.epoch != epoch {
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			if !a.backupCurrent(e, epoch) || ctx.Err() != nil {
				return
			}
			if err != nil {
				a.status = err.Error()
				return
			}
			if stage == nil {
				a.status = "已取消保存。"
				return
			}
			state := callStorage(storageRequest{Operation: "status"})
			if !state.OK || !backupLease(state.State, scope, revision) {
				a.status = vaultwarden.ErrConflict.Error()
				return
			}
			if err = session.PublishResourceBackup(ctx, proof, grants, stage.Commit); err != nil {
				a.status = err.Error()
				return
			}
			e.confirm = false
			a.status = "完整资源备份已写入新文件；其中元数据和附件均为明文，请妥善保管。"
		})
	}()
}
func (a *app) backupResourceRestoreView(c *ui.Context, e *backupEditor) {
	m := e.resources
	if m == nil {
		return
	}
	if m.copyOnly {
		ui.Text(c, "此复制保留源项目，临时计划在关闭后清理。中断后请从源项目导出完整资源备份，再选“仅继续附件恢复”并填写本次已创建的目标编号；不要重新创建副本。").MaxLines(5)
	}
	busy := a.pending != 0
	ui.Text(c, "附件恢复：目标编号来自已确认创建回执，也可为继续恢复明确填写。上传仅发一次；结果未知时同步检查真实附件编号后点击核验。文件名不能作为身份。文件导入关闭后可重新打开原资源文件并选择仅继续附件恢复；复制的中断恢复见上方说明。").MaxLines(5)
	ui.TextInput(c, &m.password).Label("目标要求再次验证时输入主密码（每次操作后清除）").Password().Disabled(busy)
	for i := range m.rows {
		row := &m.rows[i]
		if row.target == "" {
			row.target = m.targets[row.resource.CipherID]
		}
		ui.Text(c, fmt.Sprintf("%s · 来源 %s/%s · %s", row.resource.FileName, row.resource.CipherID, row.resource.AttachmentID, row.state)).MaxLines(3)
		if row.problem != "" {
			ui.Text(c, row.problem).MaxLines(3)
		}
		ui.TextInput(c, &row.target).Label("明确选择的目标项目编号").Disabled(busy || row.state == "已核验")
		ui.TextInput(c, &row.attachmentID).Label("核对的目标附件编号（上传回执或同步后填写）").Disabled(busy || row.state == "已核验")
		if action(c, "确认向此目标上传一次", "", false, busy || row.target == "" || row.state != "未执行").Clicked() {
			a.runResourceRestore(i, false, "")
		}
		if action(c, "下载并核验此附件的文件名、长度和完整内容", "", false, busy || row.target == "" || row.attachmentID == "" || row.state == "已核验").Clicked() {
			a.runResourceRestore(i, true, "")
		}
	}
	for _, source := range m.trash {
		target, ready := resourceTrashTarget(m, source)
		if m.finalized[source] {
			ui.Text(c, "已确认移入回收站："+target)
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
			ui.Text(c, "回收站状态待同步核对，不自动再次提交："+target)
			continue
		}
		if action(c, "全部文件核验后，确认将目标移入原计划的回收站："+target, "", false, busy || !ready).Clicked() {
			a.runResourceRestore(0, false, source)
		}
	}
}
func resourceTrashTarget(m *backupResourceEditor, source string) (string, bool) {
	target := ""
	for _, row := range m.rows {
		if row.resource.CipherID == source {
			if row.state != "已核验" || (target != "" && target != row.target) {
				return "", false
			}
			target = row.target
		}
	}
	return target, target != ""
}
func (a *app) runResourceRestore(index int, verify bool, trashSource string) {
	a.runResourceRestoreWith(index, verify, trashSource, a.window.Update, callStorage, func() { a.syncVault(false) })
}

// Explicit side effects keep the native form controller testable with a queued
// UI dispatcher and an in-memory bridge, while retaining real Session checks.
func (a *app) runResourceRestoreWith(index int, verify bool, trashSource string, dispatch func(func()), storage func(storageRequest) storageReply, refresh func()) {
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
	target, attachment := m.rows[index].target, m.rows[index].attachmentID
	if trashSource != "" {
		var ready bool
		target, ready = resourceTrashTarget(m, trashSource)
		if !ready {
			return
		}
	}
	if target == "" || (verify && attachment == "") {
		a.status = "请先明确目标项目及待核验的附件编号；不会自动重发上传。"
		return
	}
	if trashSource == "" && ((!verify && m.rows[index].state != "未执行") || m.rows[index].state == "已核验") {
		a.status = "此文件已执行过操作，请同步后按明确附件编号核验；不会重复上传。"
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
			if row.resource.CipherID == trashSource {
				finalFiles = append(finalFiles, struct {
					index      int
					attachment string
				}{i, row.attachmentID})
			}
		}
	}
	m.password = ""
	plan := m.plan
	m.plan = nil // worker owns the descriptor until callback; Close cannot race it
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	vault, scope, revision, prior := a.vault, *a.liveScope, e.revision, a.snapshot
	go func() {
		defer clear(password)
		var checkpoint *snapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := saveSessionCheckpoint(prior, cp, storage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		var grant *vaultwarden.ItemAuthorization
		var result vaultwarden.AttachmentUploadResult
		var trashResult vaultwarden.CipherStateResult
		var err error
		state := storage(storageRequest{Operation: "status"})
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
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			if trashSource != "" {
				m.trashPending[trashSource] = trashResult.Dispatched
				m.finalized[trashSource] = false // acknowledgement alone is not reconciliation
			} else if verify {
				if err == nil {
					m.rows[index].state = "已核验"
				}
			} else if attempted {
				m.rows[index].state = "待同步核对"
				m.rows[index].attachmentID = result.AttachmentID
			}
			a.status = "附件操作结束；请同步核对，未知结果不会自动重发。"
			if trashSource != "" && !trashResult.Dispatched {
				a.status = "尚未提交回收站变更；修正问题后请重新明确确认。"
			}
			m.rows[index].problem = ""
			if err != nil {
				m.rows[index].problem = err.Error()
				a.status = err.Error() + " " + a.status
			}
			if !verify && (attempted || trashResult.Dispatched) && a.sessionOwnsSnapshot() {
				refresh()
			}
		})
	}()
}
