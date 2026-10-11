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
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func shareCipherWithRecovery(
	ctx context.Context, parent *mygo.Window, session *vaultwarden.Session, vault *vaultwarden.VaultData,
	e *cipherEditor, scope vaultwarden.Scope, revision string,
	persist func(vaultwarden.SessionCheckpoint) error, stores ...func(localstore.Request) localstore.Reply,
) (vaultwarden.CipherDocument, error) {
	storage := localstore.Call
	if len(stores) > 0 {
		storage = stores[0]
	}
	if !vaultwarden.CipherShareRequiresRecovery(e.document) {
		return session.SharePersonalCipher(ctx, vault, e.shareOrganizationID, e.shareCollectionID, e.document, e.fields, e.authorization, persist)
	}
	path, err := send.ChooseExportPath(ctx, mygo.SaveDialogOptions{Parent: parent, Filters: []mygo.FileFilter{{Name: i18n.T("vault.share_recovery.file_type"), Extensions: []string{"mygoshare-recovery"}}}})
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
		state := storage(localstore.Request{Operation: localstore.OperationStatus})
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
		state = storage(localstore.Request{Operation: localstore.OperationStatus})
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
	parent := a.backupParent()
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: parent, Filters: []mygo.FileFilter{{Name: i18n.T("vault.share_recovery.file_type"), Extensions: []string{"mygoshare-recovery"}}}})
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
		a.postUI(func() {
			a.pending--
			defer cancel()
			if !a.backupCurrent(e, epoch) || ctx.Err() != nil {
				clear(data)
				return
			}
			a.cancel = nil
			if err != nil {
				clear(data)
				a.status = vaultwarden.ErrorMessage(err)
				return
			}
			if len(data) > 0 {
				e.recovery = &cipherShareRecoveryEditor{file: data, id: header.CipherID}
				a.status = i18n.T("vault.share_recovery.status_unauthenticated")
			}
		})
	}()
}
func (a *app) cipherShareRecoveryView(c *ui.Context, e *backupEditor) {
	r := e.recovery
	busy := a.pending != 0
	kit.PageHeader(c, i18n.T("vault.share_recovery.title"), "", nil).Margin(0, 0, 16, 0)
	ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
		ui.Column(c).Padding(0, 0, 16, 0).Gap(16).Children(func() {
			kit.Notice(c, kit.ToneInfo, i18n.T("vault.share_recovery.description"))
			kit.DetailCard(c, i18n.T("backup.recovery.file_title"), func() {
				ui.Text(c, i18n.Tf("vault.share_recovery.declared_item_id", r.id)).Padding(14).MaxLines(2)
			})
			kit.Field(c, i18n.T("vault.share_recovery.master_password"), "", func() {
				kit.Input(ui.TextInput(c, &r.password).Label(i18n.T("vault.share_recovery.master_password"))).Password().Disabled(busy)
			})
			ui.Row(c).Gap(8).Children(func() {
				if kit.Action(c, i18n.T("vault.share_recovery.sync_first"), "sync", false, busy).Clicked() {
					a.syncVault(false)
				}
				if kit.Action(c, i18n.T("vault.share_recovery.authenticate_verify"), "", false, busy).Clicked() {
					a.runCipherShareRecovery(false)
				}
			})
			if r.inspected {
				kit.Notice(c, kit.ToneWarning, i18n.T("vault.share_recovery.confirm_repair"))
				ui.Text(c, i18n.Tf("vault.share_recovery.current_item", vaultwarden.ShareRecoveryStateText(r.inspection.CipherState), r.inspection.CipherID))
				for _, attachment := range r.inspection.Attachments {
					ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
						ui.Text(c, attachment.ID).FontSize(12).Grow(1).MinWidth(0).SingleLine()
						kit.Pill(c, vaultwarden.ShareRecoveryStateText(attachment.State), kit.White, kit.Purple)
					})
				}
				if r.attempted {
					kit.Notice(c, kit.ToneWarning, i18n.T("vault.share_recovery.attempted_hint"))
				}
			}
		})
	})
	kit.ActionBar(c, func() {
		ui.Text(c, a.status).FontSize(11.5).TextColor(kit.Muted).Grow(1).MinWidth(0).MaxLines(2).Tooltip(a.status)
		ui.Spacer(c)
		if kit.Button(c, i18n.T("backup.editor.cancel_close"), "", kit.ButtonSecondary, false).Tooltip(i18n.T("vault.share_recovery.cancel_close")).Clicked() {
			a.closeBackupWindow()
			return
		}
		if r.inspected && kit.Button(c, i18n.T("backup.recovery.confirm_repair"), "", kit.ButtonPrimary, busy || !r.inspection.CanRepair || r.attempted).Clicked() {
			a.runCipherShareRecovery(true)
		}
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
		var checkpoint *localstore.SnapshotStatus
		persist := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := localstore.SaveSessionCheckpoint(prior, cp, callStorage)
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
		a.postUI(func() {
			a.pending--
			defer cancel()
			if a.backupEditor != e || e.recovery != r || a.epoch != epoch {
				return
			}
			a.cancel = nil
			if checkpoint != nil && !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
				return
			}
			if err != nil {
				a.status = i18n.Tf("vault.share_recovery.err_keep_file", vaultwarden.ErrorMessage(err))
				return
			}
			if !repair {
				r.inspection, r.inspected = inspection, true
				a.status = i18n.T("vault.share_recovery.status_classified")
			} else {
				a.status = i18n.T("vault.share_recovery.status_repaired")
			}
		})
	}()
}
