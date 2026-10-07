// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) attachmentView(c *ui.Context, e *cipherEditor) {
	if e.fields.ID == "" {
		return
	}
	busy := a.pending != 0
	ui.Text(c, "附件").FontSize(16)
	ui.Text(c, "文件单独加密传输，最大 512 MiB。下载会保存为新的明文文件，不覆盖已有文件；当前需要联网。上传和删除前请先保存项目草稿。").FontSize(12).MaxLines(4)
	if action(c, "加载或刷新附件列表", "", false, busy || e.uncertain).Clicked() {
		a.runAttachmentOperation("list", vaultwarden.AttachmentInfo{})
	}
	if e.fields.Edit && action(c, "选择并上传文件…", "", false, busy || e.uncertain || e.fields.DeletedDate != nil).Clicked() {
		a.runAttachmentOperation("upload", vaultwarden.AttachmentInfo{})
	}
	if e.attachmentsLoaded && len(e.attachments) == 0 {
		ui.Text(c, "此项目没有附件。").FontSize(12)
	}
	for _, attachment := range e.attachments {
		ui.Column(c).Gap(6).Children(func() {
			ui.Text(c, attachment.FileName).MaxLines(2)
			ui.Text(c, fmt.Sprintf("加密大小：%d 字节", attachment.CiphertextSize)).FontSize(11)
			if action(c, "下载并另存为…", "", false, busy || e.uncertain).Clicked() {
				a.runAttachmentOperation("download", attachment)
			}
			if e.fields.Edit {
				if e.attachmentDelete == attachment.ID {
					ui.Text(c, "永久删除此附件？此操作无法撤销。").FontSize(12)
					if action(c, "确认永久删除附件", "", true, busy || e.uncertain).Clicked() {
						a.runAttachmentOperation("delete", attachment)
					}
					if action(c, "保留附件", "", false, busy).Clicked() {
						e.attachmentDelete = ""
					}
				} else if action(c, "删除附件…", "", false, busy || e.uncertain).Clicked() {
					e.attachmentDelete = attachment.ID
				}
			}
		})
	}
	if e.attachmentBusy {
		ui.Text(c, "正在验证权限并传输附件，请稍候…").FontSize(12)
		if action(c, "取消附件操作", "", false, false).Clicked() {
			if a.cancel != nil {
				a.cancel()
			}
			a.status = "已请求取消；已经发出的上传或删除仍需同步核对。"
		}
	}
}

// Mutations trigger a normal sync that may close the editor. Never silently
// discard a draft: compare a detached copy of all controls with saved content.
func attachmentDraftSaved(session *vaultwarden.Session, vault *vaultwarden.VaultData, e *cipherEditor) error {
	var saved vaultwarden.CipherFields
	var err error
	if e.fields.OrganizationID == nil {
		_, saved, err = session.ReadPersonalCipherAuthorized(vault, e.fields.ID, e.authorization)
	} else {
		_, saved, err = session.ReadOrganizationCipher(vault, e.fields.ID, e.authorization)
	}
	if err != nil {
		return err
	}
	copy := *e
	encoded, err := json.Marshal(e.fields)
	if err != nil {
		return vaultwarden.ErrProtocol
	}
	copy.fields = vaultwarden.CipherFields{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&copy.fields) != nil {
		return vaultwarden.ErrProtocol
	}
	copy.applyInputs()
	current, err := json.Marshal(copy.fields)
	if err != nil {
		return vaultwarden.ErrProtocol
	}
	original, err := json.Marshal(saved)
	if err != nil || !bytes.Equal(current, original) {
		return vaultwarden.ErrConflict
	}
	return nil
}

func (a *app) attachmentCurrent(e *cipherEditor, epoch uint64) bool {
	return e != nil && a.editor == e && a.epoch == epoch && a.sessionOwnsSnapshot() && e.revision == a.sessionRevision
}

func (a *app) runAttachmentOperation(operation string, attachment vaultwarden.AttachmentInfo) {
	e := a.editor
	if a.pending != 0 || e == nil || e.uncertain || !a.attachmentCurrent(e, a.epoch) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok || a.snapshot == nil || a.vault == nil {
		return
	}
	if operation != "list" && operation != "upload" && operation != "download" && operation != "delete" {
		return
	}
	if operation == "upload" || operation == "delete" {
		if !e.fields.Edit {
			return
		}
		if err := attachmentDraftSaved(session, a.vault, e); err != nil {
			a.status = "请先保存项目更改，再上传或删除附件。"
			return
		}
	}
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	e.attachmentBusy = true
	id, grant, vault, parent, scope, revision, prior := e.fields.ID, e.authorization, a.vault, a.window, *a.liveScope, e.revision, a.snapshot
	go func() {
		var checkpoint *snapshotStatus
		var storage storageReply
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			var err error
			storage, err = saveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior, checkpoint = storage.State, storage.State
			}
			return err
		}
		lease := func() error {
			if ctx.Err() != nil {
				return vaultwarden.ErrCancelled
			}
			status := callStorage(storageRequest{Operation: "status"})
			if !status.OK || !backupLease(status.State, scope, revision) {
				return vaultwarden.ErrConflict
			}
			return nil
		}
		err := lease()
		var rows []vaultwarden.AttachmentInfo
		var stage *stagedBackup
		var proof *vaultwarden.AttachmentPublication
		var upload vaultwarden.AttachmentUploadResult
		submitted := false
		if err == nil {
			switch operation {
			case "list":
				rows, err = session.Attachments(ctx, vault, id, grant, persist)
			case "upload":
				var paths []string
				paths, err = mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent})
				if err == nil && len(paths) != 1 {
					err = vaultwarden.ErrCancelled
				}
				if err == nil {
					err = lease()
				}
				if err == nil {
					var file *os.File
					file, err = openAttachmentInput(paths[0])
					if err == nil {
						submitted = true
						upload, err = session.UploadAttachment(ctx, vault, id, filepath.Base(paths[0]), file, grant, persist)
					}
				}
			case "download":
				var path string
				path, err = mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent})
				if err == nil && path == "" {
					err = vaultwarden.ErrCancelled
				}
				if err == nil {
					err = lease()
				}
				if err == nil {
					proof, err = session.DownloadAttachment(ctx, vault, id, attachment.ID, grant, persist, func(file *os.File, size int64) error {
						var err error
						stage, err = stageAttachmentFile(ctx, path, file, size)
						return err
					})
				}
			case "delete":
				submitted = true
				err = session.DeleteAttachment(ctx, vault, id, attachment.ID, grant, persist)
			}
		}
		a.window.Update(func() {
			a.pending--
			defer cancel()
			defer stage.Close()
			if a.editor != e || a.epoch != epoch {
				return
			}
			e.attachmentBusy = false
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			if !a.attachmentCurrent(e, epoch) {
				return
			}
			if err != nil || ctx.Err() != nil {
				if err == nil {
					err = vaultwarden.ErrCancelled
				}
				a.status = err.Error()
				if submitted {
					e.uncertain = true
					a.status += " 请同步核对附件列表，不要重复提交。"
					if upload.AttachmentID != "" {
						a.status += " 附件编号：" + upload.AttachmentID
					}
				}
				return
			}
			if err := lease(); err != nil {
				a.status = err.Error()
				return
			}
			switch operation {
			case "list":
				e.attachments, e.attachmentsLoaded = rows, true
				a.status = "附件列表已验证。"
			case "download":
				if stage == nil {
					a.status = vaultwarden.ErrProtocol.Error()
					return
				}
				if err := session.PublishAttachment(ctx, proof, grant, stage.Commit); err != nil {
					a.status = err.Error()
					return
				}
				a.status = "附件已校验并保存为新的明文文件。"
			case "upload", "delete":
				a.editor = nil
				a.status = "附件操作已确认，正在同步更新密码库。"
				a.syncVault(false)
			}
		})
	}()
}
