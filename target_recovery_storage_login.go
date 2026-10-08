// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Fresh-login recovery for a signed-out or blocked target: no old target key is
// invented or retained. Only the trusted login controller may call this after
// new authentication, authoritative key/membership/MFA verification and full sync.
// It grants metadata query/resolve only, never a vault/AutoFill lease.
func newTargetRecoveryLoginStorage(state *snapshotStatus, epoch uint64, currentEpoch func() uint64,
	fresh vaultwarden.SyncResult, evidence targetRecoveryVerification, call func(storageRequest) storageReply) (*targetRecoveryStorage, error) {
	if state == nil || state.Revision == "" || epoch == 0 || currentEpoch == nil || currentEpoch() != epoch || call == nil || fresh.Vault == nil || fresh.PasswordUnlock == nil || len(fresh.PasswordUnlock.Key) != 32 || len(fresh.Session) == 0 || fresh.Scope != fresh.Vault.Scope || fresh.Scope.Account == "" || evidence.AuthenticationEpoch == 0 {
		return nil, errTargetRecovery
	}
	for _, h := range []string{evidence.AuthorityHash, evidence.KeyHash, evidence.MembershipHash, evidence.MFAHash, evidence.ConfirmationHash} {
		if !targetValidHash(h) {
			return nil, errTargetRecovery
		}
	}
	proof := targetRecoveryResolution{ExpectedRevision: state.Revision, Target: fresh.Scope, VaultHash: targetRecoveryHash(fresh.Vault.Sync), SessionHash: targetRecoveryHash(fresh.Session), UnlockHash: targetRecoveryHash(fresh.PasswordUnlock.Key), AuthorityHash: evidence.AuthorityHash, KeyHash: evidence.KeyHash, MembershipHash: evidence.MembershipHash, MFAHash: evidence.MFAHash, ConfirmationHash: evidence.ConfirmationHash, AuthenticationEpoch: evidence.AuthenticationEpoch}
	v := *fresh.Vault
	v.Sync = bytes.Clone(v.Sync)
	u := *fresh.PasswordUnlock
	u.Key = bytes.Clone(u.Key)
	return &targetRecoveryStorage{scope: fresh.Scope, localScope: state.Scope, revision: state.Revision, epoch: epoch, currentEpoch: currentEpoch, key: bytes.Clone(u.Key), call: call, login: &proof, loginVault: &v, loginSession: bytes.Clone(fresh.Session), loginUnlock: &u}, nil
}
