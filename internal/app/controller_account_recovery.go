// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
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
	a.recoveryForm = &accountRecoveryForm{email: a.snapshot.PasswordUnlock.Email, status: "先用原主密码打开本机加密恢复材料，再用服务器当前凭据全新登录核验；不会重放原请求。"}
}
func (a *app) accountRecoveryView(c *ui.Context) {
	f := a.recoveryForm
	if f == nil || f.closed {
		return
	}
	ui.Text(c, "账号恢复与完整资源核验").FontSize(20)
	ui.Text(c, "恢复记录中的旧会话不会用作网络或离线权限。混合、缺失、未知资源继续保留屏障及旧新材料。").MaxLines(5)
	ui.TextInput(c, &f.oldPassword).Label("原主密码（解密本机恢复材料）").Password().Disabled(f.busy)
	ui.TextInput(c, &f.email).Label("服务器当前登录邮箱").Disabled(f.busy)
	ui.TextInput(c, &f.currentPassword).Label("服务器当前主密码").Password().Disabled(f.busy)
	label := "确认核验全部资源，成功后才解除恢复屏障"
	if f.confirmed {
		label = "已确认完整核验后解除屏障（点击撤回）"
	}
	if ui.Button(c, label).Disabled(f.busy).Clicked() {
		f.confirmed = !f.confirmed
	}
	if ui.Button(c, "全新登录并核验恢复").Disabled(f.busy || !f.confirmed || f.oldPassword == "" || f.currentPassword == "").Clicked() {
		a.resolveAccountRecoveryWith(false, a.window.Update, callStorage)
	}
	ui.Text(c, "仅当加密日志记录服务器已确认删除账号时，才能明确删除本机恢复副本。").MaxLines(3)
	if ui.Button(c, "确认删除本机恢复副本").Disabled(f.busy).Clicked() {
		f.deleteConfirmed = !f.deleteConfirmed
	}
	if f.deleteConfirmed && ui.Button(c, "执行本机恢复副本删除").Disabled(f.busy || f.oldPassword == "").Clicked() {
		a.resolveAccountRecoveryWith(true, a.window.Update, callStorage)
	}
	if ui.Button(c, "取消并保留恢复记录").Clicked() {
		a.runStorage("lock")
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
func (a *app) resolveAccountRecoveryWith(deleting bool, dispatch func(func()), storage func(storageRequest) storageReply) {
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
	email, deviceID := vaultwarden.NormalizeEmail(f.email), a.deviceID
	f.oldPassword, f.currentPassword = "", ""
	f.busy = true
	a.pending++
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	f.cancel = cancel
	platform := sysauth.NewAuthenticationPlatform(a.window)
	go func() {
		defer clear(oldPassword)
		defer clear(password)
		defer cancel()
		var reply storageReply
		var verified vaultwarden.AccountRecoveryVerification
		var session *vaultwarden.Session
		key, err := vaultwarden.DeriveSnapshotUnlockKey(oldPassword, config)
		clear(oldPassword)
		defer clear(key)
		var adapter *accountRecoveryStorage
		if err == nil {
			adapter, err = newAccountRecoveryStorage(&source, epoch, a.workerEpoch.Load, key, storage)
		}
		if adapter != nil {
			defer adapter.Close()
		}
		var record vaultwarden.AccountRecovery
		defer record.Close()
		phase := ""
		if err == nil {
			var queried storageReply
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
			status := storage(storageRequest{Operation: "status"})
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
				f.status = err.Error()
				if len(verified.Issues) > 0 {
					f.status += "\n" + strings.Join(verified.Issues, "\n")
				}
				return
			}
			a.stopNetwork()
			a.snapshot = reply.State
			if deleting {
				a.status = "已删除本机恢复副本；没有向服务器重放删除请求。"
				a.showLogin = false
				return
			}
			a.session = session
			a.liveScope = &scope
			a.sessionRevision = reply.State.Revision
			if adoptErr := a.adoptVault(reply.Vault); adoptErr != nil {
				a.stopNetwork()
				a.status = adoptErr.Error()
				return
			}
			a.itemsRevision = reply.State.Revision
			a.showLogin, a.showSettings = false, false
			a.status = "恢复已通过完整认证核验并采用专用存储回执。" + strings.Join(verified.ResourceEvidence, "；")
			a.startNotifications(dispatch, storage)
		})
	}()
}
