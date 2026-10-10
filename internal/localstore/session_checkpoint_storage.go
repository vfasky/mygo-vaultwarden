// SPDX-License-Identifier: GPL-3.0-only
package localstore

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// A refresh checkpoint can advance only the exact session-owned snapshot.
// It must not replace credential identity or borrow a revision from status.
func SaveSessionCheckpoint(prior *SnapshotStatus, checkpoint vaultwarden.SessionCheckpoint, call func(Request) Reply) (Reply, error) {
	if prior == nil || !prior.Available || prior.Scope == nil || *prior.Scope != checkpoint.Scope || prior.Revision == "" {
		return Reply{}, vaultwarden.ErrIdentity
	}
	reply := call(Request{Operation: "saveSession", ExpectedRevision: prior.Revision, Scope: &checkpoint.Scope,
		Session: checkpoint.Session, UnlockKey: checkpoint.UnlockKey})
	if !reply.OK {
		return reply, reply.Failure()
	}
	if reply.State == nil || !reply.State.Available || reply.State.Scope == nil || *reply.State.Scope != checkpoint.Scope ||
		reply.State.Revision == "" || reply.State.Revision == prior.Revision || reply.State.SnapshotID != prior.SnapshotID {
		return reply, (&Failure{Code: "invalid_reply", Message: i18n.T("store.session.err_checkpoint_unconfirmed")})
	}
	if err := checkpoint.AcceptAuthenticatedReceipt(reply.Vault, prior.Revision, reply.State.Revision); err != nil {
		return reply, err
	}
	return reply, nil
}
