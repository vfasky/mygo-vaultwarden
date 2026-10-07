// SPDX-License-Identifier: GPL-3.0-only
package main

import "github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"

// A refresh checkpoint can advance only the exact session-owned snapshot.
// It must not replace credential identity or borrow a revision from status.
func saveSessionCheckpoint(prior *snapshotStatus, checkpoint vaultwarden.SessionCheckpoint, call func(storageRequest) storageReply) (storageReply, error) {
	if prior == nil || !prior.Available || prior.Scope == nil || *prior.Scope != checkpoint.Scope || prior.Revision == "" {
		return storageReply{}, vaultwarden.ErrIdentity
	}
	reply := call(storageRequest{Operation: "saveSession", ExpectedRevision: prior.Revision, Scope: &checkpoint.Scope,
		Session: checkpoint.Session, UnlockKey: checkpoint.UnlockKey})
	if !reply.OK {
		return reply, reply.failure()
	}
	if reply.State == nil || !reply.State.Available || reply.State.Scope == nil || *reply.State.Scope != checkpoint.Scope ||
		reply.State.Revision == "" || reply.State.Revision == prior.Revision || reply.State.SnapshotID != prior.SnapshotID {
		return reply, (&storageFailure{Code: "invalid_reply", Message: "未能确认登录凭据的保存结果，请重新解锁。"})
	}
	if err := checkpoint.AcceptAuthenticatedReceipt(reply.Vault, prior.Revision, reply.State.Revision); err != nil {
		return reply, err
	}
	return reply, nil
}

func (a *app) adoptSessionCheckpoint(state *snapshotStatus) bool {
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

func (a *app) restoreUnlockedSession(reply storageReply) bool {
	a.stopNetwork()
	a.status = "密码库已解锁。"
	if len(reply.Session) == 0 {
		a.status = "密码库已解锁。本机尚未保存登录凭据，点击同步重新登录一次即可启用。"
		return false
	}
	if reply.State == nil || reply.State.Scope == nil || reply.State.PasswordUnlock == nil {
		a.status = "本机认证快照不完整，请重新登录。"
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
		a.status = "密码库已解锁，但本机登录凭据不可用，请点击同步重新登录。"
		return false
	}
	a.session = session
	scope := *reply.State.Scope
	a.liveScope, a.sessionRevision = &scope, reply.State.Revision
	a.serverURL, a.email = scope.Server, reply.State.PasswordUnlock.Email
	a.status = "密码库已解锁，可以同步。"
	if migration {
		a.status = "本机快照需要更新策略，请先同步后使用密码库。"
	}
	return !migration
}
