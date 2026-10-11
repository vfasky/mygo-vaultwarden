// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Organization workflows request specific UI capabilities and submit receipts.
// They cannot read or mutate the window's session, epoch or editor fields.
// All host methods run on the UI dispatcher, except Window (captured before work).
type orgServicesHost interface {
	Current(orgServiceSnapshot) bool
	Busy() bool
	Window() *mygo.Window
	Warning(vaultwarden.Scope) string
	RequestSync()
	AdoptIsolation(localstore.Reply, string)
	AdoptNotificationCheckpoint(*localstore.SnapshotStatus)
	ResourceSourceCurrent(orgServiceSnapshot, localstore.SnapshotStatus) bool
	AdoptResourceCheckpoint(*localstore.SnapshotStatus) error
	ResourceFailure(localstore.Reply, error)
	AdoptResourceSnapshot(orgServiceSnapshot, localstore.Reply) (orgResourceAdoption, error)
	ResourceNotifications()
	RecoveryOutcome(orgServiceSnapshot, vaultwarden.Scope, *localstore.SnapshotStatus, string, bool)
}
type orgResourceAdoption struct {
	snapshot      orgServiceSnapshot
	organizations []vaultwarden.Organization
	collections   []vaultwarden.Collection
}

// This is the composition adapter, not the workflow owner. The controller keeps
// cancellation, prompts, operation leases, grants and result filtering itself.
type appOrgServicesHost struct {
	app        *app
	controller *orgServicesController
}

func (h appOrgServicesHost) Current(env orgServiceSnapshot) bool {
	return h.app.orgServices == h.controller && h.app.epoch == env.epoch && h.app.session == env.session
}
func (h appOrgServicesHost) Busy() bool           { return h.app.pending != 0 }
func (h appOrgServicesHost) Window() *mygo.Window { return h.app.accountParent() }
func (h appOrgServicesHost) Warning(scope vaultwarden.Scope) string {
	return h.app.targetOutcomeWarnings[scope]
}
func (h appOrgServicesHost) RequestSync() { h.app.syncVault(false) }
func (h appOrgServicesHost) AdoptIsolation(reply localstore.Reply, id string) {
	a := h.app
	if !a.adoptOrganizationIsolation(reply.State, reply.Vault, id) {
		a.stopNetwork()
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
	} else {
		a.advanceEpoch()
		a.status = i18n.T("org.services.status_quarantined")
	}
}
func (h appOrgServicesHost) AdoptNotificationCheckpoint(cp *localstore.SnapshotStatus) {
	a := h.app
	if !a.adoptSessionCheckpoint(cp) {
		a.stopNetwork()
		a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
	} else {
		a.advanceEpoch()
		a.status = i18n.T("org.services.status_credentials_updated")
	}
}
func (h appOrgServicesHost) ResourceSourceCurrent(env orgServiceSnapshot, original localstore.SnapshotStatus) bool {
	a := h.app
	return h.Current(env) && a.snapshot != nil && a.snapshot.Scope != nil && original.Scope != nil &&
		*a.snapshot.Scope == *original.Scope && a.snapshot.Revision == original.Revision && a.snapshot.SnapshotID == original.SnapshotID
}
func (h appOrgServicesHost) AdoptResourceCheckpoint(cp *localstore.SnapshotStatus) error {
	if !h.app.adoptSessionCheckpoint(cp) {
		h.app.stopNetwork()
		return vaultwarden.ErrIdentity
	}
	return nil
}
func (h appOrgServicesHost) ResourceFailure(reply localstore.Reply, err error) {
	h.app.syncFailed(reply, err)
}
func (h appOrgServicesHost) AdoptResourceSnapshot(env orgServiceSnapshot, reply localstore.Reply) (orgResourceAdoption, error) {
	a, c := h.app, h.controller
	if !env.runtime {
		if err := env.session.AcceptAuthenticatedSnapshot(reply.Vault, reply.State.Revision); err != nil {
			a.stopNetwork()
			return orgResourceAdoption{}, err
		}
	}
	// Detach only this continuation while revoking every other draft.
	a.orgServices = nil
	a.componentCancel = nil
	a.advanceEpoch()
	a.snapshot = reply.State
	a.sessionRevision = reply.State.Revision
	if err := a.adoptVault(reply.Vault); err != nil {
		c.Close()
		a.stopNetwork()
		return orgResourceAdoption{}, err
	}
	a.itemsRevision = reply.State.Revision
	lease := a.newControllerLease()
	if lease == nil {
		c.Close()
		a.stopNetwork()
		return orgResourceAdoption{}, vaultwarden.ErrIdentity
	}
	update := orgResourceAdoption{
		snapshot:      orgServiceSnapshot{env.session, reply.Vault, lease, a.epoch, env.runtime, a.routeStorage(c.baseStorage, a.epoch)},
		organizations: append([]vaultwarden.Organization(nil), a.organizations...),
		collections:   append([]vaultwarden.Collection(nil), a.collections...),
	}
	a.orgServices = c
	a.componentCancel = c.cancel
	return update, nil
}
func (h appOrgServicesHost) ResourceNotifications() {
	h.app.startNotifications(h.controller.dispatch, h.controller.baseStorage)
}
func (h appOrgServicesHost) RecoveryOutcome(env orgServiceSnapshot, actor vaultwarden.Scope, receipt *localstore.SnapshotStatus, message string, loginRequired bool) {
	a := h.app
	a.noteTargetOutcome(actor, message) // Preserve original-account warning even for a late outcome.
	if !h.Current(env) {
		return
	}
	if loginRequired {
		a.stopNetwork()
		if receipt != nil {
			a.snapshot = receipt
		}
		a.status = i18n.Tf("account.recovery.status_login_required", message)
		return
	}
	if receipt != nil && a.adoptSessionCheckpoint(receipt) {
		a.advanceEpoch()
		a.status = message
	} else {
		a.stopNetwork()
		if receipt != nil {
			a.snapshot = receipt
		}
		a.status = message
	}
}
