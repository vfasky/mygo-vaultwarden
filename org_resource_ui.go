// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// A host binds each callback to its current authenticated snapshot, obtains any
// fresh reprompt grant, persists checkpoints, and performs normal authenticated
// sync/publication in refresh. No callback may use the file as write authority.
type orgResourceCallbacks struct {
	file     func(context.Context, *vaultwarden.ResourceImportPlan, int, string, string, bool) (vaultwarden.AttachmentUploadResult, error)
	state    func(context.Context, vaultwarden.ResourceItemState, string, string, string) error
	refresh  func(context.Context) error
	dispatch func(func())
}
type orgResourceStateRow struct {
	source         vaultwarden.ResourceItemState
	target, folder string
	steps          map[string]string
}
type orgResourceRestorePanel struct {
	plan                          *vaultwarden.ResourceImportPlan
	rows                          []backupResourceRow
	states                        []orgResourceStateRow
	callbacks                     orgResourceCallbacks
	running, closed, needsRefresh bool
	cancel                        context.CancelFunc
	status                        string
}

func newOrgResourceRestorePanel(plan *vaultwarden.ResourceImportPlan, targets map[string]string, copyOnly bool, callbacks orgResourceCallbacks) *orgResourceRestorePanel {
	panel := &orgResourceRestorePanel{plan: plan, callbacks: callbacks}
	for _, resource := range plan.Resources() {
		panel.rows = append(panel.rows, backupResourceRow{resource: resource, target: targets[resource.CipherID], state: "未执行"})
	}
	if !copyOnly {
		for _, state := range plan.ItemStates() {
			if state.FolderID != nil || state.Archived || state.Deleted {
				row := orgResourceStateRow{source: state, target: targets[state.SourceID], steps: map[string]string{}}
				if state.FolderID != nil {
					row.folder = *state.FolderID
				}
				panel.states = append(panel.states, row)
			}
		}
	}
	return panel
}
func (p *orgResourceRestorePanel) Close() {
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	if !p.running {
		p.plan.Clear()
		p.plan = nil
	}
	p.status = ""
}
func (p *orgResourceRestorePanel) run(work func(context.Context) (func(), error)) {
	if p.closed || p.running || p.callbacks.dispatch == nil || work == nil {
		return
	}
	p.running = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	p.cancel = cancel
	go func() {
		apply, err := work(ctx)
		cancel()
		p.callbacks.dispatch(func() {
			p.running = false
			p.cancel = nil
			if p.closed {
				p.plan.Clear()
				p.plan = nil
				return
			}
			if apply != nil {
				apply()
			}
			p.status = "本步骤结束；每次写入后必须同步并按真实编号核对。"
			if err != nil {
				p.status = err.Error() + "；未确认步骤保持待核对，不会自动重发。"
			}
		})
	}()
}
func (p *orgResourceRestorePanel) filesVerified(source, target string) bool {
	for _, row := range p.rows {
		if row.resource.CipherID == source && (row.state != "已核验" || row.target != target) {
			return false
		}
	}
	return target != ""
}
func (p *orgResourceRestorePanel) View(c *ui.Context) {
	if p.closed {
		return
	}
	ui.Text(c, "组织完整资源恢复与核验").FontSize(22)
	ui.Text(c, "元数据导入与复制不是完整附件恢复。按来源编号明确映射目标；每个上传只发一次，再同步并下载核验名称、长度和完整内容。结果未知时填写新同步确认的附件编号后核验，不能按重复文件名猜测。归档、回收站及文件夹在文件全部核验后按明确映射恢复。").MaxLines(7)
	busy := p.running
	for i := range p.rows {
		row := &p.rows[i]
		ui.Text(c, fmt.Sprintf("%s · 来源 %s/%s · %s", row.resource.FileName, row.resource.CipherID, row.resource.AttachmentID, row.state)).MaxLines(3)
		ui.TextInput(c, &row.target).Label("已创建或明确选择的目标项目编号").Disabled(busy || row.state == "已核验")
		ui.TextInput(c, &row.attachmentID).Label("待核对的目标附件编号").Disabled(busy || row.state == "已核验")
		if action(c, "确认向目标上传一次（保留源文件）", "", false, busy || p.needsRefresh || row.target == "" || row.state != "未执行" || p.callbacks.file == nil).Key(fmt.Sprintf("org-resource-upload-%d", i)).Clicked() {
			index, target := i, row.target
			plan, execute := p.plan, p.callbacks.file
			p.run(func(ctx context.Context) (func(), error) {
				result, err := execute(ctx, plan, index, target, "", false)
				return func() {
					p.rows[index].attachmentID = result.AttachmentID
					p.rows[index].state = "待核对"
					p.needsRefresh = true
				}, err
			})
		}
		if action(c, "下载并核验所选附件", "", false, busy || p.needsRefresh || row.target == "" || row.attachmentID == "" || row.state == "已核验" || p.callbacks.file == nil).Key(fmt.Sprintf("org-resource-verify-%d", i)).Clicked() {
			index, target, id := i, row.target, row.attachmentID
			plan, execute := p.plan, p.callbacks.file
			p.run(func(ctx context.Context) (func(), error) {
				_, err := execute(ctx, plan, index, target, id, true)
				return func() {
					if err == nil {
						p.rows[index].state = "已核验"
					}
				}, err
			})
		}
	}
	for i := range p.states {
		row := &p.states[i]
		ui.Text(c, "原状态恢复 · 来源 "+row.source.SourceID)
		ui.TextInput(c, &row.target).Label("对应目标项目编号").Disabled(busy)
		if row.source.FolderID != nil {
			ui.Text(c, "原文件夹引用："+*row.source.FolderID+"；请明确映射到当前账户的已有文件夹编号。").MaxLines(3)
			ui.TextInput(c, &row.folder).Label("目标文件夹编号（不可默默忽略原引用）").Disabled(busy)
		}
		for _, step := range []string{"folder", "archive", "trash"} {
			needed := (step == "folder" && row.source.FolderID != nil) || (step == "archive" && row.source.Archived) || (step == "trash" && row.source.Deleted)
			if !needed {
				continue
			}
			labels := map[string]string{"folder": "文件夹映射", "archive": "归档状态", "trash": "回收站状态"}
			ui.Text(c, labels[step]+"："+row.steps[step])
			disabled := busy || p.needsRefresh || !p.filesVerified(row.source.SourceID, row.target) || p.callbacks.state == nil || (step == "folder" && row.folder == "")
			if action(c, "确认恢复"+labels[step], "", false, disabled || row.steps[step] != "").Clicked() {
				index, source, target, folder, operation := i, row.source, row.target, row.folder, step
				execute, fileExecute, plan := p.callbacks.state, p.callbacks.file, p.plan
				files := []struct {
					index int
					id    string
				}{}
				for j, file := range p.rows {
					if file.resource.CipherID == source.SourceID {
						files = append(files, struct {
							index int
							id    string
						}{j, file.attachmentID})
					}
				}
				p.run(func(ctx context.Context) (func(), error) {
					var err error
					for _, file := range files {
						if fileExecute == nil {
							err = vaultwarden.ErrPermission
							break
						}
						if _, err = fileExecute(ctx, plan, file.index, target, file.id, true); err != nil {
							break
						}
					}
					if err == nil {
						err = execute(ctx, source, target, folder, operation)
					}
					return func() { p.states[index].steps[operation] = "待同步核对"; p.needsRefresh = true }, err
				})
			}
			if action(c, "核对"+labels[step], "", false, disabled || row.steps[step] == "已核验").Clicked() {
				index, source, target, folder, operation := i, row.source, row.target, row.folder, step
				execute := p.callbacks.state
				p.run(func(ctx context.Context) (func(), error) {
					err := execute(ctx, source, target, folder, "check-"+operation)
					return func() {
						if err == nil {
							p.states[index].steps[operation] = "已核验"
						}
					}, err
				})
			}
		}
	}
	if action(c, "同步并刷新权限后继续", "sync", false, busy || p.callbacks.refresh == nil).Key("org-resource-refresh").Clicked() {
		execute := p.callbacks.refresh
		p.run(func(ctx context.Context) (func(), error) {
			err := execute(ctx)
			return func() {
				if err == nil {
					p.needsRefresh = false
				}
			}, err
		})
	}
	if p.running && action(c, "取消本步骤并核对", "", false, false).Clicked() {
		p.cancel()
	}
	if p.status != "" {
		ui.Text(c, p.status).MaxLines(6)
	}
}

func executeOrgResourceFile(ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData, plan *vaultwarden.ResourceImportPlan, index int, targetOrgID, target, attachment string, verify bool, grant *vaultwarden.ItemAuthorization, persist func(vaultwarden.SessionCheckpoint) error) (vaultwarden.AttachmentUploadResult, error) {
	if session == nil {
		return vaultwarden.AttachmentUploadResult{}, vaultwarden.ErrExpired
	}
	_, fields, err := session.ReadOrganizationCipher(vault, target, grant)
	if err != nil {
		return vaultwarden.AttachmentUploadResult{}, err
	}
	if targetOrgID == "" || fields.OrganizationID == nil || *fields.OrganizationID != targetOrgID {
		return vaultwarden.AttachmentUploadResult{}, vaultwarden.ErrPermission
	}
	if verify {
		return vaultwarden.AttachmentUploadResult{}, session.VerifyRestoredResource(ctx, vault, target, attachment, plan, index, grant, persist)
	}
	return session.UploadResource(ctx, vault, target, plan, index, true, grant, persist)
}
func executeOrgResourceState(ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData, source vaultwarden.ResourceItemState, targetOrgID, target, folder, operation string, grant *vaultwarden.ItemAuthorization, persist func(vaultwarden.SessionCheckpoint) error) error {
	if session == nil {
		return vaultwarden.ErrExpired
	}
	document, fields, err := session.ReadOrganizationCipher(vault, target, grant)
	if err != nil {
		return err
	}
	if targetOrgID == "" || fields.OrganizationID == nil || *fields.OrganizationID != targetOrgID {
		return vaultwarden.ErrIdentity
	}
	switch operation {
	case "check-folder":
		if source.FolderID == nil || fields.FolderID == nil || *fields.FolderID != folder {
			return vaultwarden.ErrConflict
		}
		return nil
	case "check-archive":
		if !source.Archived || fields.ArchivedDate == nil {
			return vaultwarden.ErrConflict
		}
		return nil
	case "check-trash":
		if !source.Deleted || fields.DeletedDate == nil {
			return vaultwarden.ErrConflict
		}
		return nil
	case "folder":
		if source.FolderID == nil || folder == "" {
			return vaultwarden.ErrValidation
		}
		fields.FolderID = &folder
		_, err = session.UpdateOrganizationCipher(ctx, vault, document, fields, grant, persist)
		return err
	case "archive", "trash":
		action := vaultwarden.CipherArchive
		if operation == "trash" {
			if !source.Deleted {
				return vaultwarden.ErrValidation
			}
			action = vaultwarden.CipherTrash
		} else if !source.Archived {
			return vaultwarden.ErrValidation
		}
		_, err = session.ChangeOrganizationCiphers(ctx, vault, *fields.OrganizationID, []string{target}, action, map[string]*vaultwarden.ItemAuthorization{target: grant}, persist)
		return err
	default:
		return vaultwarden.ErrValidation
	}
}
