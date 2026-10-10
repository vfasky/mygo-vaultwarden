// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"time"
)

func (a *app) closeConnectedPanels() {
	if a.targetRecovery != nil {
		a.targetRecovery.Close()
		a.targetRecovery = nil
	}
	if a.orgServices != nil {
		a.orgServices.Close()
		a.orgServices = nil
	}
	if a.recoveryForm != nil {
		a.recoveryForm.Close()
		a.recoveryForm = nil
	}
	if a.authManagement != nil {
		a.authManagement.Close()
		a.authManagement = nil
	}
	if a.componentCancel != nil {
		a.componentCancel()
		a.componentCancel = nil
	}
	if a.accountForm != nil {
		a.accountForm.Close()
		a.accountForm = nil
	}
	if a.devicePanel != nil {
		a.devicePanel.Close()
		a.devicePanel = nil
	}
	if a.sendPanel != nil {
		a.sendPanel.Close()
		a.sendPanel = nil
	}
}

func (a *app) openSend() { a.openSendWith(a.dispatchUI, a.storageCall, true) }
func (a *app) openSendWith(dispatch func(func()), storage func(storageRequest) storageReply, dialogs bool) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	client, err := vaultwarden.NewClient(a.liveScope.Server, a.deviceID)
	if err != nil {
		a.status = err.Error()
		return
	}
	a.advanceEpoch()
	storage = a.routeStorage(storage, a.epoch)
	lease := a.newControllerLease()
	if lease == nil {
		return
	}
	epoch, vault, scope := a.epoch, a.vault, *a.liveScope
	host := SendHost{
		Busy:       a.componentBusy,
		Check:      func() error { return lease.check(storage) },
		Checkpoint: func(cp vaultwarden.SessionCheckpoint) error { return lease.persist(cp, storage) },
		Changed:    func() { a.syncVaultWith(false, dispatch, storage) },
	}
	host.Dispatch = func(f func()) {
		dispatch(func() {
			if a.epoch == epoch && a.session == session {
				if checkpoint := lease.takeCheckpoint(); checkpoint != nil {
					if !a.adoptSessionCheckpoint(checkpoint) {
						a.stopNetwork()
						a.status = vaultwarden.ErrIdentity.Error()
					} else {
						// Refresh has revoked Send drafts. Never assign a new revision to them.
						a.advanceEpoch()
						a.status = "登录凭据已更新，请重新打开 Send。"
					}
				}
			}
			// Always deliver cleanup, including after Close or an account switch.
			f()
		})
	}
	host.Copy = func(secret string) error {
		a.prepareRuntimeSecret()
		if a.epoch != epoch || a.session != session {
			return vaultwarden.ErrCancelled
		}
		if err := lease.check(storage); err != nil {
			return err
		}
		return session.WithSnapshotProtection(vault, a.sessionRevision, func(key []byte, deadline time.Time) error {
			reply := storage(storageRequest{Operation: "copySecret", SecretProtocol: 1, Secret: secret, SecretNotAfter: deadline.UnixMilli(), Scope: &scope, ExpectedRevision: a.sessionRevision, UnlockKey: key})
			if !reply.OK {
				return reply.failure()
			}
			a.secretClipboardOwned = true
			return nil
		})
	}
	if dialogs {
		ConfigureSendDialogs(a.window, &host)
	}
	a.sendPanel = NewSendPanel(session, client, vault, scope, host)
	a.category, a.showSettings = "send", false
	a.sendPanel.Offline()
}
