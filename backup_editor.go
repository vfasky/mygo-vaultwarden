// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type backupEditor struct {
	revision                      string
	format                        vaultwarden.BackupFormat
	candidates                    []displayCredential
	selected                      map[string]bool
	importing, confirm, submitted bool
	plan                          *vaultwarden.ImportPlan
	results                       []vaultwarden.ImportEntry
}

func (a *app) clearBackupEditor() {
	if a.backupEditor != nil {
		a.backupEditor.plan.Clear()
		a.backupEditor = nil
	}
}
func (a *app) openBackupEditor() {
	if a.pending != 0 || !a.sessionOwnsSnapshot() || a.vault == nil || a.editor != nil || a.folderEditor != nil || a.bulkEditor != nil || a.backupEditor != nil {
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
	a.showSettings = false
}
func (a *app) backupEditorView(c *ui.Context) {
	e := a.backupEditor
	busy := a.pending != 0
	ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Padding(18).Gap(10).Children(func() {
			ui.Text(c, "导入与导出").FontSize(23)
			ui.Text(c, "文件包含未加密的密码和其他秘密，请仅保存在可信本地位置。附件、通行密钥及未知扩展尚不支持，发现后会整体拒绝。当前仅导入导出个人密码库，组织导入导出尚未实现。").MaxLines(5).FontSize(12)
			if !e.submitted {
				if !e.confirm && e.plan == nil {
					for _, format := range []struct {
						id    vaultwarden.BackupFormat
						label string
					}{{vaultwarden.BitwardenJSON, "Bitwarden 兼容 JSON（1–7 类）"}, {vaultwarden.MyGoBackup, "MyGo 备份（八类，.mygovault）"}} {
						if navItem(c, format.label, "vault", "", e.format == format.id, busy).Clicked() {
							e.format = format.id
						}
					}
					if action(c, "切换到导入文件", "", false, busy || e.importing).Clicked() {
						e.importing = true
					}
					if action(c, "切换到导出所选", "", false, busy || !e.importing).Clicked() {
						e.importing = false
					}
				}
				if e.importing {
					if e.plan == nil {
						ui.Text(c, "只接受所选格式的明文文件；加密导出、其他应用备份及不支持的数据会拒绝。").MaxLines(3)
						if action(c, "选择导入文件…", "", true, busy).Clicked() {
							a.chooseImportFile()
						}
					} else {
						ui.Text(c, fmt.Sprintf("已检查：%d 个项目、%d 个文件夹；其中归档 %d、回收站 %d。", e.plan.Items, e.plan.Folders, e.plan.Archived, e.plan.Deleted)).MaxLines(3)
						ui.Text(c, "确认后创建独立副本及新的文件夹，不覆盖现有项目。历史内容保留；服务器创建、修订及删除时间重新生成。回收站项目先创建再移入回收站。中途失败可能只完成部分，不会自动重试。").MaxLines(6)
						for _, item := range e.plan.PreviewItems() {
							label := []string{"", "登录", "安全笔记", "支付卡", "身份", "SSH 密钥", "银行账户", "驾驶证", "护照"}[item.Type] + " · " + item.Name
							if item.Archived {
								label += "（归档）"
							}
							if item.Deleted {
								label += "（回收站）"
							}
							ui.Text(c, label).MaxLines(2).FontSize(12)
						}
						if action(c, "确认创建这些项目", "", true, busy).Clicked() {
							a.importBackup()
						}
					}
				} else {
					ui.Text(c, "默认勾选当前列表；可逐项选择整个个人库，包括归档和回收站，同时导出全部个人文件夹（含空文件夹）。兼容 JSON 不支持护照、回收站、超过五条历史及额外登录设置，请改用 MyGo 备份。").MaxLines(5)
					for _, item := range e.candidates {
						label := "□ " + item.Title
						if e.selected[item.ID] {
							label = "✓ " + item.Title
						}
						if item.Archived {
							label += "（归档）"
						}
						if item.Deleted {
							label += "（回收站）"
						}
						if action(c, label, "", false, busy || e.confirm).Clicked() {
							e.selected[item.ID] = !e.selected[item.ID]
						}
					}
					if e.confirm {
						ui.Text(c, "确认将勾选项目中的密码、TOTP 秘钥、备注及历史以明文导出？请使用新的文件名；为保护原文件，本应用不会覆盖已有文件。").MaxLines(4)
						if action(c, "确认并选择保存位置…", "", true, busy).Clicked() {
							a.chooseExportFile()
						}
					} else if action(c, "继续导出…", "", true, busy).Clicked() {
						e.confirm = true
					}
				}
			} else {
				ui.Text(c, "本次导入已提交，不可再次提交。请按下面的结果核对密码库；结果未知的项目需人工核对，勿重复导入。").MaxLines(4)
				for _, r := range e.results {
					ui.Text(c, r.Kind+" · "+r.Name+"："+r.State).MaxLines(3).FontSize(12)
				}
				if action(c, "同步核对导入结果", "sync", false, busy).Clicked() {
					a.syncVault(false)
				}
			}
			if action(c, "取消并关闭导入导出", "", false, false).Clicked() {
				if a.cancel != nil {
					a.cancel()
					a.cancel = nil
				}
				a.epoch++
				a.clearBackupEditor()
				a.status = "已取消；如导入已发出，请同步核对部分结果。"
			}
		})
	})
}
func (a *app) backupCurrent(e *backupEditor, epoch uint64) bool {
	return a.epoch == epoch && a.backupEditor == e && a.sessionOwnsSnapshot() && e.revision == a.sessionRevision
}
func backupLease(state *snapshotStatus, scope vaultwarden.Scope, revision string) bool {
	return state != nil && state.Available && state.Scope != nil && *state.Scope == scope && state.Revision == revision
}
func backupDialogFilter(format vaultwarden.BackupFormat) mygo.FileFilter {
	if format == vaultwarden.MyGoBackup {
		return mygo.FileFilter{Name: "MyGo 备份", Extensions: []string{"mygovault"}}
	}
	return mygo.FileFilter{Name: "Bitwarden JSON", Extensions: []string{"json"}}
}
func backupOutputPath(path string, format vaultwarden.BackupFormat) (string, error) {
	if path == "" {
		return "", vaultwarden.ErrCancelled
	}
	extension := ".json"
	if format == vaultwarden.MyGoBackup {
		extension = ".mygovault"
	} else if format != vaultwarden.BitwardenJSON {
		return "", vaultwarden.ErrValidation
	}
	if filepath.Ext(path) == "" {
		return path + extension, nil
	}
	if strings.ToLower(filepath.Ext(path)) != extension {
		return "", fmt.Errorf("此格式请使用 %s 文件扩展名，未写入文件。", extension)
	}
	return path, nil
}

func (a *app) chooseImportFile() {
	e := a.backupEditor
	if a.pending != 0 || e == nil || e.plan != nil || !e.importing || !a.backupCurrent(e, a.epoch) {
		return
	}
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.pending++
	format, scope, revision := e.format, *a.liveScope, e.revision
	parent := a.window
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(format)}})
		var plan *vaultwarden.ImportPlan
		if err == nil && len(paths) == 1 && ctx.Err() == nil {
			status := callStorage(storageRequest{Operation: "status"})
			if !status.OK || !backupLease(status.State, scope, revision) {
				err = vaultwarden.ErrConflict
			} else {
				var data []byte
				data, err = readBackupFile(ctx, paths[0])
				if err == nil {
					plan, err = vaultwarden.ParseImport(data, format)
				}
				clear(data)
			}
		}
		a.window.Update(func() {
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
				a.status = "文件预检通过，请核对导入范围后确认。"
			}
		})
	}()
}
func (a *app) chooseExportFile() {
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
		a.status = "请先勾选导出的项目。"
		return
	}
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.pending++
	format, scope, revision, vault, parent := e.format, *a.liveScope, e.revision, a.vault, a.window
	go func() {
		// Preflight before showing Save or touching any target file.
		status := callStorage(storageRequest{Operation: "status"})
		var data []byte
		var err error
		var stage *stagedBackup
		if !status.OK || !backupLease(status.State, scope, revision) {
			err = vaultwarden.ErrConflict
		} else {
			data, err = session.ExportPersonalBackup(ctx, vault, ids, format)
		}
		clear(data)
		data = nil // Never retain plaintext while the native Save panel waits.
		if err == nil && ctx.Err() == nil {
			var path string
			path, err = mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent, Filters: []mygo.FileFilter{backupDialogFilter(format)}})
			if err == nil && path != "" && ctx.Err() == nil {
				path, err = backupOutputPath(path, format)
				if err != nil {
					a.window.Update(func() { a.completeBackupExport(e, epoch, ctx, nil, err, cancel) })
					return
				}
				status = callStorage(storageRequest{Operation: "status"})
				if !status.OK || !backupLease(status.State, scope, revision) {
					err = vaultwarden.ErrConflict
				} else {
					data, err = session.ExportPersonalBackup(ctx, vault, ids, format)
					if err == nil {
						stage, err = stageBackupFile(ctx, path, data)
					}
					clear(data)
					data = nil
				}
			}
		}
		a.window.Update(func() { a.completeBackupExport(e, epoch, ctx, stage, err, cancel) })
	}()
}
func (a *app) completeBackupExport(e *backupEditor, epoch uint64, ctx context.Context, stage *stagedBackup, err error, cancel context.CancelFunc) {
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
		a.status = "已取消保存。"
		return
	}
	// Publication stays on the UI thread so a processed lock/cancel cannot race
	// a later callback writing the final plaintext file. Recheck the storage lease.
	status := callStorage(storageRequest{Operation: "status"})
	if !status.OK || !backupLease(status.State, *a.liveScope, e.revision) {
		a.status = vaultwarden.ErrConflict.Error()
		return
	}
	if err = stage.Commit(); err != nil {
		a.status = err.Error()
		return
	}
	e.confirm = false
	a.status = "明文备份已安全写入新文件，请妥善保管并在不再需要时删除。"
}
func (a *app) importBackup() {
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
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	go func() {
		defer plan.Clear()
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
		state := callStorage(storageRequest{Operation: "status"})
		var result vaultwarden.ImportResult
		var err error
		if !state.OK || !backupLease(state.State, scope, prior.Revision) || ctx.Err() != nil {
			err = vaultwarden.ErrConflict
		} else {
			result, err = session.ImportPersonalBackup(ctx, scope, plan, persist)
		}
		a.window.Update(func() {
			a.pending--
			defer cancel()
			if a.epoch != epoch || a.backupEditor != e {
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			e.results = result.Entries
			if err != nil {
				e.results = append(e.results, vaultwarden.ImportEntry{Kind: "导入已停止", State: err.Error()})
				a.syncFailed(reply, err)
			}
			if a.backupEditor == e && a.sessionOwnsSnapshot() {
				a.status = "导入操作已结束，正在同步核对已知项目；结果未知时请人工核对。"
				a.syncVault(false)
			}
		})
	}()
}
func (a *app) reconcileImport() {
	e := a.backupEditor
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
		if r.Kind == "文件夹" {
			found = folders[r.ID]
		}
		if found {
			r.State = "同步已找到新建项目；请核对内容及归档、回收站状态"
		} else {
			r.State = "同步未找到此标识，请人工核对；不要重复导入"
		}
	}
}
