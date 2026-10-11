// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/platform/sysauth"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type accountRecoveryForm struct {
	oldPassword, currentPassword, email, status string
	confirmed, deleteConfirmed, busy, closed    bool
	cancel                                      context.CancelFunc
}

func (f *accountRecoveryForm) Close() {
	if f == nil {
		return
	}
	if f.cancel != nil {
		f.cancel()
	}
	f.oldPassword = ""
	f.currentPassword = ""
	f.closed = true
}
func (a *app) openAccountRecovery() {
	if a.pending != 0 || a.snapshot == nil || !a.snapshot.RecoveryPending || a.snapshot.Scope == nil || a.snapshot.PasswordUnlock == nil {
		return
	}
	a.stopNetwork()
	a.showLogin = true
	a.recoveryForm = &accountRecoveryForm{email: a.snapshot.PasswordUnlock.Email, status: i18n.T("account.recovery.verification_hint")}
}
func (a *app) accountRecoveryView(c *ui.Context) {
	f := a.recoveryForm
	if f == nil || f.closed {
		return
	}
	ui.Text(c, i18n.T("account.recovery.verification_title")).FontSize(20)
	ui.Text(c, i18n.T("account.recovery.barrier_hint")).MaxLines(5)
	ui.TextInput(c, &f.oldPassword).Label(i18n.T("account.recovery.original_password")).Password().Disabled(f.busy)
	ui.TextInput(c, &f.email).Label(i18n.T("account.recovery.current_email")).Disabled(f.busy)
	ui.TextInput(c, &f.currentPassword).Label(i18n.T("account.recovery.current_password")).Password().Disabled(f.busy)
	label := i18n.T("account.recovery.confirm_full_verification")
	if f.confirmed {
		label = i18n.T("account.recovery.revoke_verification_confirmation")
	}
	if ui.Button(c, label).Disabled(f.busy).Clicked() {
		f.confirmed = !f.confirmed
	}
	if ui.Button(c, i18n.T("account.recovery.login_verify")).Disabled(f.busy || !f.confirmed || f.oldPassword == "" || f.currentPassword == "").Clicked() {
		a.resolveAccountRecoveryWith(false, a.postUI, localstore.Call)
	}
	ui.Text(c, i18n.T("account.recovery.delete_local_copy_hint")).MaxLines(3)
	if ui.Button(c, i18n.T("account.recovery.confirm_delete_local_copy")).Disabled(f.busy).Clicked() {
		f.deleteConfirmed = !f.deleteConfirmed
	}
	if f.deleteConfirmed && ui.Button(c, i18n.T("account.recovery.delete_local_copy")).Disabled(f.busy || f.oldPassword == "").Clicked() {
		a.resolveAccountRecoveryWith(true, a.postUI, localstore.Call)
	}
	if ui.Button(c, i18n.T("account.recovery.cancel_keep_records")).Clicked() {
		a.runStorage(localstore.OperationLock)
	}
	ui.Text(c, f.status).MaxLines(16)
}
func clearSyncSecrets(result *vaultwarden.SyncResult) {
	clear(result.Session)
	result.Session = nil
	if result.PasswordUnlock != nil {
		clear(result.PasswordUnlock.Key)
		result.PasswordUnlock = nil
	}
	for i := range result.Credentials {
		result.Credentials[i].Password = ""
	}
	result.Credentials = nil
}
func (a *app) resolveAccountRecoveryWith(deleting bool, dispatch func(func()), storage func(localstore.Request) localstore.Reply) {
	f := a.recoveryForm
	if f == nil || f.closed || f.busy || a.snapshot == nil || a.snapshot.Scope == nil || a.snapshot.PasswordUnlock == nil || !a.snapshot.RecoveryPending || (deleting && !f.deleteConfirmed) || (!deleting && !f.confirmed) {
		return
	}
	epoch := a.epoch
	source := *a.snapshot
	scope := *source.Scope
	config := *source.PasswordUnlock
	source.Scope = &scope
	source.PasswordUnlock = &config
	oldPassword, password := []byte(f.oldPassword), []byte(f.currentPassword)
	email, deviceID := vaultcrypto.NormalizeEmail(f.email), a.deviceID
	f.oldPassword, f.currentPassword = "", ""
	f.busy = true
	a.pending++
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	f.cancel = cancel
	platform := sysauth.NewAuthenticationPlatform(a.mainWindow)
	go func() {
		defer clear(oldPassword)
		defer clear(password)
		defer cancel()
		var reply localstore.Reply
		var verified vaultwarden.AccountRecoveryVerification
		var session *vaultwarden.Session
		key, err := vaultwarden.DeriveSnapshotUnlockKey(oldPassword, config)
		clear(oldPassword)
		defer clear(key)
		var adapter *localstore.AccountRecoveryStorage
		if err == nil {
			adapter, err = localstore.NewAccountRecoveryStorage(&source, epoch, a.workerEpoch.Load, key, storage)
		}
		if adapter != nil {
			defer adapter.Close()
		}
		var record vaultwarden.AccountRecovery
		defer record.Close()
		phase := ""
		if err == nil {
			var queried localstore.Reply
			queried, err = adapter.Query()
			reply = queried
			if queried.Recovery != nil {
				phase = queried.Recovery.Phase
				if err == nil && json.Unmarshal(queried.Recovery.Record, &record) != nil {
					err = vaultwarden.ErrProtocol
				}
				queried.Recovery.Close()
				reply.Recovery = nil
			} else if err == nil {
				err = vaultwarden.ErrIdentity
			}
		}
		if err == nil && deleting {
			reply, err = adapter.DeleteConfirmed(true)
		} else if err == nil {
			var client *vaultwarden.Client
			client, err = vaultwarden.NewClient(scope.Server, deviceID)
			if err == nil {
				var result vaultwarden.MFALoginResult
				result, err = client.LoginMFA(ctx, email, password, "", func(promptCtx context.Context, ch vaultwarden.MFAChallenge) (vaultwarden.MFAResponse, error) {
					return a.requestMFA(promptCtx, scope.Server, email, epoch, ch, dispatch, platform.MFA(scope.Server, epoch))
				})
				clear(password)
				result.RememberToken = ""
				if result.RemovedAllMFA {
					a.mfaWarnings.record(scope.Server, email, true)
				}
				if err == nil {
					session = result.Session
				}
			}
			if err == nil {
				var fresh vaultwarden.SyncResult
				fresh, verified, err = session.SyncVerifiedAccountRecovery(ctx, record, phase, adapter.Checkpoint)
				if err == nil && !verified.Ready {
					err = vaultwarden.ErrIdentity
				}
				if err == nil {
					reply, err = adapter.ResolveVerified(fresh, true, true, true)
				}
				clearSyncSecrets(&fresh)
				if err == nil {
					if reply.State == nil || reply.State.Scope == nil || *reply.State.Scope != scope || reply.State.RecoveryPending || reply.Vault == nil {
						err = vaultwarden.ErrIdentity
					} else {
						err = session.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision)
					}
				}
			}
		}
		if ctx.Err() != nil && err == nil {
			err = vaultwarden.ErrCancelled
		}
		if err != nil && session != nil {
			session.Close()
			session = nil
		}
		if err != nil {
			status := storage(localstore.Request{Operation: localstore.OperationStatus})
			if status.State != nil {
				reply.State = status.State
			}
		}
		dispatch(func() {
			a.pending--
			if a.epoch != epoch || a.recoveryForm != f || f.closed {
				if session != nil {
					go session.Close()
				}
				return
			}
			f.busy = false
			f.cancel = nil
			a.resetLoginForm()
			if reply.State != nil {
				a.snapshot = reply.State
			}
			if err != nil {
				f.status = vaultwarden.ErrorMessage(err)
				if len(verified.Issues) > 0 {
					f.status += "\n" + strings.Join(verified.Issues, "\n")
				}
				return
			}
			a.stopNetwork()
			a.snapshot = reply.State
			if deleting {
				a.status = i18n.T("account.recovery.status_local_copy_deleted")
				a.showLogin = false
				return
			}
			a.session = session
			a.liveScope = &scope
			a.sessionRevision = reply.State.Revision
			if adoptErr := a.adoptVault(reply.Vault); adoptErr != nil {
				a.stopNetwork()
				a.status = vaultwarden.ErrorMessage(adoptErr)
				return
			}
			a.itemsRevision = reply.State.Revision
			a.showLogin = false
			a.status = i18n.Tf("account.recovery.status_verified_receipt", strings.Join(verified.ResourceEvidence, "；"))
			a.startNotifications(dispatch, storage)
		})
	}()
}
