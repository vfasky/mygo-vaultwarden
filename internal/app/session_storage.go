// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) adoptSessionCheckpoint(state *localstore.SnapshotStatus) bool {
	if !a.sessionOwnsSnapshot() || state == nil || !state.Available || state.Scope == nil ||
		*state.Scope != *a.liveScope || state.SnapshotID != a.snapshot.SnapshotID || state.Revision == "" {
		return false
	}
	if a.itemsRevision == a.sessionRevision {
		a.itemsRevision = state.Revision
	}
	if a.editor != nil && a.editor.revision == a.sessionRevision {
		a.editor.revision = state.Revision
	}
	if a.organizationEditor != nil && a.organizationEditor.revision == a.sessionRevision {
		a.organizationEditor.revision = state.Revision
	}
	if a.folderEditor != nil && a.folderEditor.revision == a.sessionRevision {
		a.folderEditor.revision = state.Revision
	}
	if a.bulkEditor != nil && a.bulkEditor.revision == a.sessionRevision {
		a.bulkEditor.revision = state.Revision
	}
	a.snapshot, a.sessionRevision = state, state.Revision
	if session, ok := a.session.(*vaultwarden.Session); ok {
		if session.BindSnapshotRevision(*a.liveScope, state.Revision) != nil {
			return false
		}
	}
	if a.editor != nil && a.editor.authorization != nil {
		a.editor = nil
		a.secretInputVersion++
	}
	return true
}

func (a *app) restoreUnlockedSession(reply localstore.Reply) bool {
	a.stopNetwork()
	a.status = i18n.T("login.unlock.status_unlocked")
	if len(reply.Session) == 0 {
		a.status = i18n.T("login.unlock.status_credentials_not_saved")
		return false
	}
	if reply.State == nil || reply.State.Scope == nil || reply.State.PasswordUnlock == nil {
		a.status = i18n.T("login.unlock.err_incomplete_snapshot")
		return false
	}
	session, err := vaultwarden.RestoreSessionFromAuthenticatedSnapshot(reply.Session, *reply.State.Scope, reply.State.PasswordUnlock, reply.Vault, reply.State.Revision)
	migration := err != nil
	if migration {
		// Legacy snapshots can restore only network credentials. A successful
		// authenticated sync must replace them before any offline data is read.
		session, err = vaultwarden.RestoreSession(reply.Session, *reply.State.Scope, reply.State.PasswordUnlock)
	}
	if err != nil {
		a.status = i18n.T("login.unlock.status_credentials_unavailable")
		return false
	}
	a.session = session
	a.idleLock.start()
	scope := *reply.State.Scope
	a.liveScope, a.sessionRevision = &scope, reply.State.Revision
	a.serverURL, a.email = scope.Server, reply.State.PasswordUnlock.Email
	a.status = i18n.T("login.unlock.status_sync_ready")
	if migration {
		a.status = i18n.T("app.sync.policy_update_hint")
	}
	return !migration
}
