// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/platform/sysauth"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type deviceLoginLifecycle struct {
	active, accepted atomic.Bool
	epoch            uint64
	clock            *atomic.Uint64
	scope            vaultwarden.Scope
	checkSource      func() error
}

func (l *deviceLoginLifecycle) check(scope vaultwarden.Scope, epoch uint64) error {
	if !l.active.Load() || scope != l.scope || epoch != l.epoch || (!l.accepted.Load() && l.clock.Load() != epoch) {
		return vaultwarden.ErrCancelled
	}
	return l.checkSource()
}
func (a *app) retainDeviceWarnings(panel *account.DeviceLoginPanel) {
	if panel == nil {
		return
	}
	for _, r := range panel.RecoveryOutcomes() {
		if r.State >= vaultwarden.DeviceLoginRecoverySubmitted {
			a.mfaWarnings.record(r.Scope.Server, r.Email, r.State == vaultwarden.DeviceLoginRecoveryConfirmed)
		}
	}
}
func (a *app) closeDeviceLogin() {
	if a.deviceLifecycle != nil {
		a.deviceLifecycle.active.Store(false)
		a.deviceLifecycle = nil
	}
	if a.runtimeExpiry != nil {
		a.runtimeExpiry.Stop()
		a.runtimeExpiry = nil
	}
	if a.deviceLoginPanel != nil {
		panel := a.deviceLoginPanel
		panel.Close()
		a.retainDeviceWarnings(panel)
		a.deviceLoginPanel = nil
	}
	if a.deviceFlow != nil {
		flow := a.deviceFlow
		a.deviceFlow = nil
		flow.Cancel()
		go flow.Close()
	}
}
func (a *app) openDeviceLogin() {
	a.openDeviceLoginWith(a.dispatchUI, a.storageCall, localstore.NewRuntimeSecrets)
}
func (a *app) openDeviceLoginWith(dispatch func(func()), storage func(localstore.Request) localstore.Reply, nativeFactory func() *localstore.NativeRuntimeSecrets) {
	if a.pending != 0 || a.snapshot == nil {
		return
	}
	server, err := vaultwarden.CanonicalServer(a.serverURL)
	if err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	email := vaultcrypto.NormalizeEmail(a.email)
	accountID := a.deviceAccountID
	if accountID == "" && a.snapshot.Scope != nil && a.snapshot.Scope.Server == server && a.snapshot.PasswordUnlock != nil && a.snapshot.PasswordUnlock.Email == email {
		accountID = a.snapshot.Scope.Account
	}
	if accountID == "" {
		a.status = i18n.T("account.device_login.err_account_identity_required")
		return
	}
	scope := vaultwarden.Scope{Server: server, Account: accountID}
	client, err := vaultwarden.NewClient(server, a.deviceID)
	if err != nil {
		a.status = vaultwarden.ErrorMessage(err)
		return
	}
	a.stopNetwork()
	a.showLogin = true
	a.deviceLoginSetup = true
	epoch := a.epoch
	source := *a.snapshot
	if source.Scope != nil {
		copyScope := *source.Scope
		source.Scope = &copyScope
	}
	lifetime := &deviceLoginLifecycle{epoch: epoch, clock: &a.workerEpoch, scope: scope}
	lifetime.active.Store(true)
	lifetime.checkSource = func() error {
		reply := storage(localstore.Request{Operation: localstore.OperationStatus})
		if !reply.OK {
			return reply.Failure()
		}
		if !localstore.SameStorageSource(&source, reply.State) {
			return vaultwarden.ErrIdentity
		}
		return nil
	}
	a.deviceLifecycle = lifetime
	a.pending++
	a.status = i18n.T("account.device_login.status_verifying_protection")
	go func() {
		var protection *vaultwarden.VaultData
		err := lifetime.check(scope, epoch)
		if err == nil && source.Scope != nil && *source.Scope == scope && source.Available {
			if source.RecoveryPending {
				err = localstore.ErrRuntimeTargetBlocked
			} else {
				reply := storage(localstore.Request{Operation: localstore.OperationList, Scope: &scope, ExpectedRevision: source.Revision})
				clear(reply.Session)
				reply.Session = nil
				reply.Items = nil
				if !reply.OK {
					err = reply.Failure()
				} else if !localstore.SameStorageSource(&source, reply.State) || reply.Vault == nil || reply.Vault.Scope != scope {
					err = vaultwarden.ErrIdentity
				} else {
					protection = &vaultwarden.VaultData{Version: reply.Vault.Version, Scope: scope, PendingPolicyMutations: append([]vaultwarden.PendingPolicyMutation(nil), reply.Vault.PendingPolicyMutations...), QuarantinedOrganizations: append([]string(nil), reply.Vault.QuarantinedOrganizations...)}
				}
				if reply.Vault != nil {
					clear(reply.Vault.Sync)
				}
			}
		}
		dispatch(func() {
			a.pending--
			if a.epoch != epoch || a.deviceLifecycle != lifetime || !lifetime.active.Load() {
				return
			}
			if err != nil {
				a.status = vaultwarden.ErrorMessage(err)
				lifetime.active.Store(false)
				return
			}
			platform := sysauth.NewAuthenticationPlatform(a.window)
			var panel *account.DeviceLoginPanel
			host := account.DeviceLoginHost{Check: lifetime.check, Platform: platform.MFA(server, epoch), AcceptingMessage: i18n.T("account.device_login.status_verifying_policy")}
			host.Dispatch = func(f func()) { dispatch(func() { f(); a.retainDeviceWarnings(panel) }) }
			host.Accept = func(flow *vaultwarden.DeviceLogin, result vaultwarden.DeviceLoginResult) error {
				if a.epoch != epoch || a.deviceLifecycle != lifetime || !lifetime.active.Load() || result.Session == nil || result.Sync.Scope != scope || result.Sync.Vault == nil {
					return vaultwarden.ErrIdentity
				}
				lifetime.accepted.Store(true)
				a.deviceFlow = flow
				a.pending++
				result.RememberToken = ""
				go func() {
					cap, vault, err := result.Session.AcceptRuntimeSnapshotWithProtection(result.Sync.Vault, protection)
					var targetProtection *vaultwarden.VaultData
					if err == nil {
						err = localstore.CheckRuntimeTargetProtection(cap, vault, &source, epoch, &a.workerEpoch, storage, nativeFactory(), &targetProtection)
					}
					if err == nil {
						// A same-scope authenticated current cache includes any later
						// explicit policy recovery; historical resolved projections
						// must not resurrect restrictions it already cleared.
						if protection != nil {
							targetProtection = nil
						}
						cap, vault, err = cap.Restrict(vault, targetProtection)
					}
					if err == nil {
						err = lifetime.check(scope, epoch)
					}
					var runtime *runtimeVault
					if err == nil {
						constraints := &vaultwarden.VaultData{Version: vault.Version, Scope: scope, PendingPolicyMutations: append([]vaultwarden.PendingPolicyMutation(nil), vault.PendingPolicyMutations...), QuarantinedOrganizations: append([]string(nil), vault.QuarantinedOrganizations...)}
						runtime = &runtimeVault{active: true, clock: &a.workerEpoch, session: result.Session, authority: cap, vault: vault, source: source, protection: constraints, native: nativeFactory(), sourceCheck: func(state localstore.SnapshotStatus, expected vaultwarden.Scope) error {
							if expected != scope {
								return vaultwarden.ErrIdentity
							}
							return lifetime.check(scope, epoch)
						}}
					}
					dispatch(func() {
						a.pending--
						if a.epoch != epoch || a.deviceLifecycle != lifetime || a.deviceFlow != flow || !lifetime.active.Load() {
							if runtime != nil {
								runtime.close()
							}
							flow.Cancel()
							go flow.Close()
							return
						}
						if err != nil {
							if cap != nil {
								cap.Close()
							}
							a.closeDeviceLogin()
							a.status = vaultwarden.ErrorMessage(err)
							return
						}
						a.diskSnapshot = &source
						a.runtimeVault = runtime
						a.snapshot = runtimeSnapshot(cap)
						a.session = result.Session
						a.liveScope = &scope
						a.sessionRevision = cap.Revision()
						if err = a.adoptVault(vault); err != nil {
							a.stopNetwork()
							a.status = vaultwarden.ErrorMessage(err)
							return
						}
						a.itemsRevision = cap.Revision()
						a.showLogin, a.showSettings = false, false
						panel.Close()
						a.retainDeviceWarnings(panel)
						a.deviceLoginPanel = nil
						a.status = i18n.T("account.device_login.status_temporary_vault_open")
						a.runtimeExpiry = time.AfterFunc(time.Until(cap.Expires()), func() {
							dispatch(func() {
								if a.runtimeVault == runtime {
									a.stopNetwork()
									a.status = i18n.T("account.device_login.status_temporary_session_expired")
								}
							})
						})
						a.startNotifications(dispatch, storage)
					})
				}()
				return nil
			}
			panel = account.NewDeviceLoginPanel(client, email, scope, epoch, host)
			a.deviceLoginPanel = panel
			a.deviceLoginSetup = false
			panel.Start()
		})
	}()
}

func (a *app) deviceLoginSetupView(c *ui.Context) {
	busy := a.pending != 0
	ui.Text(c, i18n.T("account.device_login.title")).FontSize(20)
	ui.TextInput(c, &a.serverURL).Label(i18n.T("common.server_url")).Disabled(busy)
	ui.TextInput(c, &a.email).Label(i18n.T("account.device_login.account_email")).Disabled(busy)
	ui.TextInput(c, &a.deviceAccountID).Label(i18n.T("account.device_login.known_account_id")).Disabled(busy)
	ui.Text(c, i18n.T("account.device_login.temporary_session_hint")).MaxLines(7)
	if kit.WidePrimary(c, i18n.T("account.device_login.request_approval"), busy).Clicked() {
		a.openDeviceLogin()
	}
	if kit.TextLink(c, i18n.T("account.device_login.back_to_password"), false).Clicked() {
		a.stopNetwork()
		a.showLogin = true
	}
	a.authStatus(c)
}

func (a *app) bindRuntimePasswordWith(dispatch func(func()), storage func(localstore.Request) localstore.Reply) {
	if a.pending != 0 || a.runtimeVault == nil || a.deviceFlow == nil || a.diskSnapshot == nil || a.masterPassword == "" {
		return
	}
	runtime, flow := a.runtimeVault, a.deviceFlow
	source := *a.diskSnapshot
	var switchBinding *localstore.AccountSwitchBinding
	if source.Scope != nil && *source.Scope != *a.liveScope {
		if !a.runtimeReplaceConfirmed {
			a.status = i18n.T("account.device_login.err_replace_confirmation_required")
			return
		}
		binding, err := localstore.NewAccountSwitchBinding(&source, *a.liveScope)
		if err != nil {
			a.status = vaultwarden.ErrorMessage(err)
			return
		}
		switchBinding = &binding
	}
	a.runtimeReplaceConfirmed = false
	password := []byte(a.masterPassword)
	a.clearLoginInputs()
	a.advanceEpoch()
	epoch := a.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	a.cancel = cancel
	a.pending++
	go func() {
		defer clear(password)
		err := flow.BindPassword(ctx, password)
		clear(password)
		var fresh vaultwarden.SyncResult
		var reply localstore.Reply
		if err == nil {
			fresh, err = runtime.session.SyncWithCheckpoint(ctx, nil)
		}
		if err == nil {
			err = mergeRuntimeProtection(fresh.Vault, runtime.protection)
		}
		if err == nil {
			err = runtime.sourceCheck(source, fresh.Scope)
		}
		if err == nil && a.workerEpoch.Load() != epoch {
			err = vaultwarden.ErrCancelled
		}
		if err == nil {
			if switchBinding != nil {
				reply, err = localstore.PublishBoundAccount(ctx, &source, fresh, *switchBinding, storage)
			} else {
				reply = storage(localstore.Request{Operation: localstore.OperationPublishVault, ExpectedRevision: source.Revision, Scope: &fresh.Scope, Credentials: fresh.Credentials, PasswordUnlock: fresh.PasswordUnlock, Session: fresh.Session, Vault: fresh.Vault})
				if !reply.OK {
					err = reply.Failure()
				}
			}
			if err == nil && (reply.State == nil || reply.State.Scope == nil || *reply.State.Scope != fresh.Scope || reply.State.Revision == source.Revision || reply.Vault == nil || !reply.Vault.PreservesPendingPolicies(runtime.vault)) {
				err = vaultwarden.ErrIdentity
			}
		}
		clear(reply.Session)
		reply.Session = nil
		if err == nil {
			err = runtime.session.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision)
		}
		clearSyncSecrets(&fresh)
		dispatch(func() {
			a.pending--
			cancel()
			if a.epoch != epoch || a.runtimeVault != runtime {
				return
			}
			a.cancel = nil
			if err != nil {
				a.stopNetwork()
				if reply.State != nil {
					a.snapshot = reply.State
				}
				a.status = i18n.Tf("account.device_login.status_receipt_discarded", vaultwarden.ErrorMessage(err))
				return
			}
			runtime.close()
			a.runtimeVault = nil
			a.diskSnapshot = nil
			if a.runtimeExpiry != nil {
				a.runtimeExpiry.Stop()
				a.runtimeExpiry = nil
			}
			a.snapshot = reply.State
			a.sessionRevision = reply.State.Revision
			if e := a.adoptVault(reply.Vault); e != nil {
				a.stopNetwork()
				a.status = vaultwarden.ErrorMessage(e)
				return
			}
			a.itemsRevision = reply.State.Revision
			a.status = i18n.T("account.device_login.status_password_bound")
			a.startNotifications(dispatch, storage)
		})
	}()
}
