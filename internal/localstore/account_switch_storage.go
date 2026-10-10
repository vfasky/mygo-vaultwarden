// SPDX-License-Identifier: GPL-3.0-only
package localstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type AccountSwitchBinding struct {
	OperationID      string            `json:"operationID"`
	Source           vaultwarden.Scope `json:"source"`
	SourceSnapshotID string            `json:"sourceSnapshotID"`
	Target           vaultwarden.Scope `json:"target"`
}
type AccountSwitchReceipt struct {
	Binding       AccountSwitchBinding `json:"binding"`
	NewSnapshotID string               `json:"newSnapshotID"`
	Phase         string               `json:"phase"`
}

func NewAccountSwitchBinding(source *SnapshotStatus, target vaultwarden.Scope) (AccountSwitchBinding, error) {
	if source == nil || source.Scope == nil || !source.Available || source.SnapshotID == "" || *source.Scope == target {
		return AccountSwitchBinding{}, vaultwarden.ErrIdentity
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return AccountSwitchBinding{}, err
	}
	return AccountSwitchBinding{OperationID: hex.EncodeToString(id[:]), Source: *source.Scope, SourceSnapshotID: source.SnapshotID, Target: target}, nil
}
func PublishBoundAccount(ctx context.Context, source *SnapshotStatus, fresh vaultwarden.SyncResult, binding AccountSwitchBinding, storage func(Request) Reply) (Reply, error) {
	if ctx.Err() != nil {
		return Reply{}, vaultwarden.ErrCancelled
	}
	if source == nil || source.Scope == nil || *source.Scope != binding.Source || source.SnapshotID != binding.SourceSnapshotID || fresh.Scope != binding.Target || fresh.PasswordUnlock == nil || len(fresh.Session) == 0 || fresh.Vault == nil {
		return Reply{}, vaultwarden.ErrIdentity
	}
	reply := storage(Request{Operation: OperationPublishBoundAccount, ExpectedRevision: source.Revision, Scope: &fresh.Scope, SwitchBinding: &binding, Credentials: fresh.Credentials, PasswordUnlock: fresh.PasswordUnlock, Session: fresh.Session, Vault: fresh.Vault})
	if !reply.OK {
		return reply, reply.Failure()
	}
	if reply.State == nil || reply.State.Scope == nil || *reply.State.Scope != binding.Target || !reply.State.AccountSwitchPending || reply.State.Revision == source.Revision || reply.AccountSwitch == nil || reply.AccountSwitch.Binding != binding || reply.AccountSwitch.Phase != "pending" || reply.AccountSwitch.NewSnapshotID != reply.State.SnapshotID {
		return reply, vaultwarden.ErrIdentity
	}
	if ctx.Err() != nil {
		return reply, vaultwarden.ErrCancelled
	}
	pendingID := reply.State.SnapshotID
	// This is acknowledgement of the successful atomic publication, never a
	// retry of an unknown write. Failure retains the encrypted old-account copy.
	reply = storage(Request{Operation: OperationConfirmAccountSwitch, ExpectedRevision: reply.State.Revision, Scope: &fresh.Scope, SwitchOperationID: binding.OperationID, UnlockKey: fresh.PasswordUnlock.Key})
	if !reply.OK {
		return reply, reply.Failure()
	}
	if reply.AccountSwitch == nil || reply.AccountSwitch.Binding != binding || reply.AccountSwitch.Phase != "confirmed" || reply.State == nil || reply.State.AccountSwitchPending || reply.State.Scope == nil || *reply.State.Scope != binding.Target || reply.State.SnapshotID != pendingID || reply.AccountSwitch.NewSnapshotID != pendingID || reply.Vault == nil {
		return reply, vaultwarden.ErrIdentity
	}
	return reply, nil
}
