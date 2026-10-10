// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/fileio"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func shareCipherWithRecovery(ctx context.Context, parent *mygo.Window, session *vaultwarden.Session, vault *vaultwarden.VaultData, e *cipherEditor, scope vaultwarden.Scope, revision string, persist func(vaultwarden.SessionCheckpoint) error, stores ...func(storageRequest) storageReply) (vaultwarden.CipherDocument, error) {
	storage := callStorage
	if len(stores) > 0 {
		storage = stores[0]
	}
	if !vaultwarden.CipherShareRequiresRecovery(e.document) {
		return session.SharePersonalCipher(ctx, vault, e.shareOrganizationID, e.shareCollectionID, e.document, e.fields, e.authorization, persist)
	}
	path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: parent, Filters: []mygo.FileFilter{{Name: "MyGo 加密共享迁移恢复文件", Extensions: []string{"mygoshare-recovery"}}}})
	if err != nil {
		return vaultwarden.CipherDocument{}, err
	}
	if path == "" || ctx.Err() != nil {
		return vaultwarden.CipherDocument{}, vaultwarden.ErrCancelled
	}
	if filepath.Ext(path) == "" {
		path += ".mygoshare-recovery"
	} else if strings.ToLower(filepath.Ext(path)) != ".mygoshare-recovery" {
		return vaultwarden.CipherDocument{}, vaultwarden.ErrValidation
	}
	return session.SharePersonalCipherWithRecovery(ctx, vault, e.shareOrganizationID, e.shareCollectionID, e.document, e.fields, e.authorization, persist, func(data []byte) error {
		state := storage(storageRequest{Operation: "status"})
		if !state.OK || !backupLease(state.State, scope, revision) {
			return vaultwarden.ErrConflict
		}
		stage, err := fileio.StageBackupFile(ctx, path, data)
		if err != nil {
			return err
		}
		defer stage.Close()
		if ctx.Err() != nil {
			return vaultwarden.ErrCancelled
		}
		if err = stage.Commit(); err != nil {
			return err
		}
		state = storage(storageRequest{Operation: "status"})
		if !state.OK || !backupLease(state.State, scope, revision) {
			return vaultwarden.ErrConflict
		}
		return nil
	})
}

type cipherShareRecoveryEditor struct {
	file                 []byte
	id, password         string
	inspection           vaultwarden.CipherShareRecoveryInspection
	inspected, attempted bool
}

func (a *app) chooseCipherShareRecovery() {
	e := a.backupEditor
	if e == nil || a.pending != 0 || !a.backupCurrent(e, a.epoch) {
		return
	}
	a.advanceEpoch()
	epoch := a.epoch
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.pending++
	parent := a.window
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Filters: []mygo.FileFilter{{Name: "MyGo 加密共享迁移恢复文件", Extensions: []string{"mygoshare-recovery"}}}})
		var data []byte
		var header struct {
			CipherID string `json:"cipherId"`
		}
		if err == nil && len(paths) == 1 {
			data, err = fileio.ReadBackupFile(ctx, paths[0])
			if err == nil && json.Unmarshal(data, &header) != nil {
				err = vaultwarden.ErrProtocol
			}
		}
		a.window.Update(func() {
			a.pending--
			defer cancel()
			if !a.backupCurrent(e, epoch) || ctx.Err() != nil {
				clear(data)
				return
			}
			a.cancel = nil
			if err != nil {
				clear(data)
				a.status = err.Error()
				return
			}
			if len(data) > 0 {
				e.recovery = &cipherShareRecoveryEditor{file: data, id: header.CipherID}
				a.status = "文件尚未认证；请先同步，再核对迁移状态。"
			}
		})
	}()
}
func (a *app) cipherShareRecoveryView(c *ui.Context, e *backupEditor) {
	r := e.recovery
	busy := a.pending != 0
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).Padding(18).Gap(10).Children(func() {
			ui.Text(c, "共享迁移恢复核对").FontSize(23)
			ui.Text(c, "恢复文件绑定原服务器、账户和当时的账户密钥。它不能替代当前权限，也不能在账户密钥轮换/删除后保证解锁。只修复与记录一致的旧个人或新组织条目的附件包装；不会抢回组织所有权、覆盖外部修改或删除文件。未决文件不会自动移除。").MaxLines(7)
			ui.Text(c, "文件声明的项目编号（认证前不可信）："+r.id).MaxLines(2)
			ui.TextInput(c, &r.password).Label("受保护项目的主密码（操作后清除）").Password().Disabled(busy)
			if kit.Action(c, "先同步当前密码库", "sync", false, busy).Clicked() {
				a.syncVault(false)
			}
			if kit.Action(c, "认证恢复文件并新读取核对", "", false, busy).Clicked() {
				a.runCipherShareRecovery(false)
			}
			if r.inspected {
				ui.Text(c, "当前项目："+r.inspection.CipherState+" · "+r.inspection.CipherID)
				for _, attachment := range r.inspection.Attachments {
					ui.Text(c, attachment.ID+"："+attachment.State).FontSize(12)
				}
				if r.attempted {
					ui.Text(c, "本轮修复已尝试，请同步并再次核对。结果未知时不重复发请求；继续修复需重新打开文件、认证和确认。")
				}
				if kit.Action(c, "确认仅把附件包装修复为当前项目密钥对应的版本", "", true, busy || !r.inspection.CanRepair || r.attempted).Clicked() {
					a.runCipherShareRecovery(true)
				}
			}
			if kit.Action(c, "取消并关闭恢复核对", "", false, false).Clicked() {
				if a.cancel != nil {
					a.cancel()
					a.cancel = nil
				}
				a.advanceEpoch()
				clear(r.file)
				r.password = ""
				e.recovery = nil
			}
		})
	})
}
func (a *app) runCipherShareRecovery(repair bool) {
	e := a.backupEditor
	if e == nil || e.recovery == nil || a.pending != 0 || !a.backupCurrent(e, a.epoch) {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	r := e.recovery
	if repair && (!r.inspected || !r.inspection.CanRepair || r.attempted) {
		return
	}
	password := []byte(r.password)
	r.password = ""
	raw := append([]byte(nil), r.file...)
	protected, organization := false, false
	for _, item := range a.items {
		if item.ID == r.id {
			protected, organization = item.RequiresPassword, item.OrganizationID != ""
		}
	}
	a.advanceEpoch()
	epoch := a.epoch
	callStorage := a.vaultStorage()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	a.cancel = cancel
	a.pending++
	vault, revision, prior := a.vault, e.revision, a.snapshot
	if repair {
		r.attempted = true
	}
	go func() {
		defer clear(password)
		defer clear(raw)
		var checkpoint *snapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := saveSessionCheckpoint(prior, cp, callStorage)
			if err == nil {
				prior, checkpoint = reply.State, reply.State
			}
			return err
		}
		var grant *vaultwarden.ItemAuthorization
		var err error
		if protected {
			if organization {
				grant, err = session.AuthorizeOrganizationItem(ctx, vault, revision, r.id, password)
			} else {
				grant, err = session.AuthorizePersonalItem(ctx, vault, revision, r.id, password)
			}
		}
		clear(password)
		var inspection vaultwarden.CipherShareRecoveryInspection
		if err == nil {
			if repair {
				err = session.RepairCipherShareRecovery(ctx, vault, raw, true, grant, persist)
			} else {
				inspection, err = session.InspectCipherShareRecovery(ctx, vault, raw, grant, persist)
			}
		}
		a.window.Update(func() {
			a.pending--
			defer cancel()
			if a.backupEditor != e || e.recovery != r || a.epoch != epoch {
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrIdentity.Error()
				return
			}
			if err != nil {
				a.status = err.Error() + " 请保留恢复文件并同步核对。"
				return
			}
			if !repair {
				r.inspection, r.inspected = inspection, true
				a.status = "已依据认证文件和新服务器读取完成分类。"
			} else {
				a.status = "修复请求已确认；请同步后重新核对所有附件包装。"
			}
		})
	}()
}
