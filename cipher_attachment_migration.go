// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type cipherAttachmentMigrationEditor struct {
	rows                  []vaultwarden.CipherAttachmentMigrationInfo
	original, replacement string
	result                string
}

func (a *app) cipherAttachmentMigrationView(c *ui.Context, e *cipherEditor) {
	if e.fields.ID == "" || e.fields.OrganizationID != nil || !e.fields.Edit {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	busy := a.pending != 0
	if e.attachmentMigration == nil {
		if action(c, "准备旧附件的安全共享迁移", "", false, busy || e.uncertain).Clicked() {
			rows, err := session.CipherAttachmentMigrationInfo(a.vault, e.fields.ID, e.authorization)
			if err != nil {
				a.status = err.Error()
				return
			}
			e.attachmentMigration = &cipherAttachmentMigrationEditor{rows: rows}
		}
		return
	}
	m := e.attachmentMigration
	ui.Text(c, "旧附件迁移：先创建独立加密副本，同步后重新打开此处；明确选中旧、新两个编号，服务器下载校验内容一致后才删除旧件。项目编号保留，附件编号改变。全部完成后再共享。取消、失败及重开后请先同步核对，不要重复创建。临时文件受权限保护，磁盘不承诺安全擦除。").MaxLines(8)
	for _, row := range m.rows {
		label := row.FileName + " · " + row.ID
		if row.Legacy {
			label = "原附件 · " + label
			if m.original == row.ID {
				label = "✓ " + label
			}
			if action(c, label, "", false, busy || e.uncertain).Clicked() {
				m.original = row.ID
			}
		} else {
			label = "独立加密附件 · " + label
			if m.replacement == row.ID {
				label = "✓ " + label
			}
			if action(c, label, "", false, busy || e.uncertain).Clicked() {
				m.replacement = row.ID
			}
		}
	}
	if action(c, "确认创建所选旧附件的独立加密副本（保留原件）", "", false, busy || e.uncertain || m.original == "").Clicked() {
		a.runCipherAttachmentMigration(false)
	}
	if action(c, "确认核验所选两个编号并永久删除旧附件", "", false, busy || e.uncertain || m.original == "" || m.replacement == "").Clicked() {
		a.runCipherAttachmentMigration(true)
	}
	if m.result != "" {
		ui.Text(c, m.result).MaxLines(8)
	}
	if e.uncertain && action(c, "同步核对，然后重新打开项目", "sync", false, busy).Clicked() {
		a.syncVault(false)
	}
	if busy && action(c, "取消附件迁移", "", false, false).Clicked() {
		if a.cancel != nil {
			a.cancel()
		}
	}
}

func (a *app) runCipherAttachmentMigration(remove bool) {
	e := a.editor
	if e == nil || e.attachmentMigration == nil || a.pending != 0 || e.uncertain || !a.attachmentCurrent(e, a.epoch) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok || a.snapshot == nil {
		return
	}
	if err := attachmentDraftSaved(session, a.vault, e); err != nil {
		a.status = "请先保存项目更改，再迁移附件。"
		return
	}
	m := e.attachmentMigration
	oldID, newID := m.original, m.replacement
	if oldID == "" || (remove && newID == "") {
		return
	}
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	vault, id, grant, prior, scope, revision := a.vault, e.fields.ID, e.authorization, a.snapshot, *a.liveScope, e.revision
	go func() {
		var checkpoint *snapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := saveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		state := callStorage(storageRequest{Operation: "status"})
		var result vaultwarden.CipherAttachmentMigrationResult
		var err error
		if !state.OK || !backupLease(state.State, scope, revision) {
			err = vaultwarden.ErrConflict
		} else if remove {
			result, err = session.VerifyAndDeleteLegacyCipherAttachment(ctx, vault, id, oldID, newID, true, grant, persist)
		} else {
			result, err = session.UpgradeLegacyCipherAttachment(ctx, vault, id, oldID, true, grant, persist)
		}
		a.window.Update(func() {
			a.pending--
			defer cancel()
			if a.editor != e || a.epoch != epoch {
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			// Freeze even unknown outcomes; a new authenticated sync is required.
			e.uncertain = true
			m.result = fmt.Sprintf("原编号 %s；替代编号 %s；已确认元数据=%t、上传=%t、核对=%t、内容一致=%t、删除回执=%t。请同步核对后再继续。", result.OriginalID, result.ReplacementID, result.MetadataCreated, result.Uploaded, result.Reconciled, result.ContentVerified, result.OriginalDeleted)
			a.status = m.result
			if err != nil {
				a.status = err.Error() + " " + m.result
			}
		})
	}()
}
