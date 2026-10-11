// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) componentDispatch(session *vaultwarden.Session, lease *controllerLease, epoch uint64, dispatch func(func())) func(func()) {
	return func(f func()) {
		dispatch(func() {
			if a.epoch == epoch && a.session == session {
				if cp := lease.takeCheckpoint(); cp != nil {
					if !a.adoptSessionCheckpoint(cp) {
						a.stopNetwork()
						a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
					} else {
						a.advanceEpoch()
						a.status = i18n.T("app.settings.err_credentials_changed")
					}
				}
			}
			f()
		})
	}
}
func (a *app) openDevices() { a.openDevicesWith(a.dispatchUI, a.storageCall) }
func (a *app) openDevicesWith(dispatch func(func()), storage func(localstore.Request) localstore.Reply) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	a.advanceEpoch()
	storage = a.routeStorage(storage, a.epoch)
	lease := a.newControllerLease()
	if lease == nil {
		return
	}
	host := account.DeviceHost{Busy: a.componentBusy, Dispatch: a.componentDispatch(session, lease, a.epoch, dispatch),
		Check: func() error { return lease.check(storage) }, Checkpoint: func(cp vaultwarden.SessionCheckpoint) error { return lease.persist(cp, storage) },
		Changed: func() { a.syncVaultWith(false, dispatch, storage) }}
	a.devicePanel = account.NewDevicePanel(session, a.vault, host)
	a.selectAccountTab(accountTabDevices)
	a.devicePanel.Refresh()
}
