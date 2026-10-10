// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type accountSwitchBinding struct {
	OperationID      string            `json:"operationID"`
	Source           vaultwarden.Scope `json:"source"`
	SourceSnapshotID string            `json:"sourceSnapshotID"`
	Target           vaultwarden.Scope `json:"target"`
}
type accountSwitchReceipt struct {
	Binding       accountSwitchBinding `json:"binding"`
	NewSnapshotID string               `json:"newSnapshotID"`
	Phase         string               `json:"phase"`
}

func newAccountSwitchBinding(source *snapshotStatus, target vaultwarden.Scope) (accountSwitchBinding, error) {
	if source == nil || source.Scope == nil || !source.Available || source.SnapshotID == "" || *source.Scope == target {
		return accountSwitchBinding{}, vaultwarden.ErrIdentity
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return accountSwitchBinding{}, err
	}
	return accountSwitchBinding{OperationID: hex.EncodeToString(id[:]), Source: *source.Scope, SourceSnapshotID: source.SnapshotID, Target: target}, nil
}
func publishBoundAccount(ctx context.Context, source *snapshotStatus, fresh vaultwarden.SyncResult, binding accountSwitchBinding, storage func(storageRequest) storageReply) (storageReply, error) {
	if ctx.Err() != nil {
		return storageReply{}, vaultwarden.ErrCancelled
	}
	if source == nil || source.Scope == nil || *source.Scope != binding.Source || source.SnapshotID != binding.SourceSnapshotID || fresh.Scope != binding.Target || fresh.PasswordUnlock == nil || len(fresh.Session) == 0 || fresh.Vault == nil {
		return storageReply{}, vaultwarden.ErrIdentity
	}
	reply := storage(storageRequest{Operation: "publishBoundAccount", ExpectedRevision: source.Revision, Scope: &fresh.Scope, SwitchBinding: &binding, Credentials: fresh.Credentials, PasswordUnlock: fresh.PasswordUnlock, Session: fresh.Session, Vault: fresh.Vault})
	if !reply.OK {
		return reply, reply.failure()
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
	reply = storage(storageRequest{Operation: "confirmAccountSwitch", ExpectedRevision: reply.State.Revision, Scope: &fresh.Scope, SwitchOperationID: binding.OperationID, UnlockKey: fresh.PasswordUnlock.Key})
	if !reply.OK {
		return reply, reply.failure()
	}
	if reply.AccountSwitch == nil || reply.AccountSwitch.Binding != binding || reply.AccountSwitch.Phase != "confirmed" || reply.State == nil || reply.State.AccountSwitchPending || reply.State.Scope == nil || *reply.State.Scope != binding.Target || reply.State.SnapshotID != pendingID || reply.AccountSwitch.NewSnapshotID != pendingID || reply.Vault == nil {
		return reply, vaultwarden.ErrIdentity
	}
	return reply, nil
}
