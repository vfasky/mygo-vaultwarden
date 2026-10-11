// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"sync/atomic"
	"time"
)

func runtimePasswordKey(ctx context.Context, client *Client, email, wrapped string, password []byte) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"email": email})
	status, data, err := client.request(ctx, "POST", "/identity/accounts/prelogin", "application/json", string(body), "")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, statusError(status)
	}
	var kdf vaultcrypto.KDF
	if strictJSON(data) != nil || json.Unmarshal(data, &kdf) != nil {
		return nil, ErrProtocol
	}
	master, err := vaultcrypto.DeriveOnlineMaster(password, email, kdf)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	stretched, err := vaultcrypto.StretchMaster(master)
	if err != nil {
		return nil, err
	}
	defer clear(stretched)
	return vaultcrypto.DecryptString(wrapped, stretched)
}

// RuntimeAuthority is a capability minted only from this Session's actual
// successful online Sync. Its revision is never a disk/Swift storage revision.
// It owns no persisted token, key, or snapshot and cannot enable AutoFill.
type RuntimeAuthority struct {
	session  *Session
	scope    Scope
	revision string
	digest   [32]byte
	epoch    uint64
	expires  time.Time
	closed   atomic.Bool
}

func (s *Session) AcceptRuntimeSnapshot(vault *VaultData) (*RuntimeAuthority, error) {
	authority, _, err := s.AcceptRuntimeSnapshotWithProtection(vault, nil)
	return authority, err
}

// local must be obtained by the privileged controller from an authenticated
// bridge receipt for this exact account. Only protection markers are merged;
// business data is always the actual fresh server Sync. The host must continue
// checking the bridge source revision and separate target recovery blockers.
func (s *Session) AcceptRuntimeSnapshotWithProtection(vault, local *VaultData) (*RuntimeAuthority, *VaultData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acceptRuntimeSnapshotWithProtectionLocked(vault, local)
}
func (s *Session) acceptRuntimeSnapshotWithProtectionLocked(vault, local *VaultData) (*RuntimeAuthority, *VaultData, error) {
	if !s.runtimeOnly || !s.itemSessionActiveLocked() || !time.Now().Before(s.expires) {
		return nil, nil, ErrExpired
	}
	digest, err := snapshotDigest(vault)
	if err != nil {
		return nil, nil, err
	}
	if s.runtimeSyncDigest == ([32]byte{}) || digest != s.runtimeSyncDigest {
		return nil, nil, ErrIdentity
	}
	accepted := *vault
	accepted.Sync = append([]byte(nil), vault.Sync...)
	accepted.PendingPolicyMutations = append([]PendingPolicyMutation(nil), vault.PendingPolicyMutations...)
	accepted.QuarantinedOrganizations = append([]string(nil), vault.QuarantinedOrganizations...)
	if local != nil {
		if local.Scope != vault.Scope {
			return nil, nil, ErrIdentity
		}
		for _, p := range local.PendingPolicyMutations {
			if !accepted.HasPendingPolicy(p) {
				accepted.PendingPolicyMutations = append(accepted.PendingPolicyMutations, p)
			}
		}
		for _, id := range local.QuarantinedOrganizations {
			found := false
			for _, existing := range accepted.QuarantinedOrganizations {
				if id == existing {
					found = true
				}
			}
			if !found {
				accepted.QuarantinedOrganizations = append(accepted.QuarantinedOrganizations, id)
			}
		}
		if len(accepted.PendingPolicyMutations) > 0 {
			accepted.Version = 2
		}
	}
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	revision := "runtime:" + hex.EncodeToString(nonce[:])
	if err = s.acceptSnapshotLocked(&accepted, revision); err != nil {
		return nil, nil, err
	}
	digest, err = snapshotDigest(&accepted)
	if err != nil {
		return nil, nil, err
	}
	s.runtimeSyncDigest = [32]byte{}
	r := &RuntimeAuthority{session: s, scope: vault.Scope, revision: revision, digest: digest, epoch: s.authorizationEpoch, expires: s.expires}
	s.runtimeCurrent.Store(r)
	return r, &accepted, nil
}

// Restrict adds authenticated local restrictions to an existing provisional
// runtime capability. It cannot remove policy/quarantine or accept other data.
func (r *RuntimeAuthority) Restrict(vault, local *VaultData) (*RuntimeAuthority, *VaultData, error) {
	if r == nil {
		return nil, nil, ErrExpired
	}
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := r.checkLocked(vault); err != nil {
		return nil, nil, err
	}
	s.runtimeSyncDigest = r.digest
	return s.acceptRuntimeSnapshotWithProtectionLocked(vault, local)
}

func (s *Session) advanceAuthorizationLocked() {
	s.authorizationEpoch++
	if current := s.runtimeCurrent.Swap(nil); current != nil {
		current.Close()
	}
}

// CheckLease is safe even inside a Session callback: no Session lock or native
// I/O is taken. Every authorization revocation atomically removes this handle.
func (r *RuntimeAuthority) CheckLease() error {
	if r == nil || r.closed.Load() || !time.Now().Before(r.expires) || r.session.runtimeCurrent.Load() != r {
		return ErrExpired
	}
	return nil
}
func (r *RuntimeAuthority) Scope() Scope {
	if r == nil {
		return Scope{}
	}
	return r.scope
}
func (r *RuntimeAuthority) Revision() string {
	if r == nil {
		return ""
	}
	return r.revision
}
func (r *RuntimeAuthority) Expires() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.expires
}
func (r *RuntimeAuthority) Close() {
	if r != nil {
		r.closed.Store(true)
	}
}
func (r *RuntimeAuthority) checkLocked(vault *VaultData) error {
	if r == nil || r.closed.Load() || !time.Now().Before(r.expires) {
		return ErrExpired
	}
	s := r.session
	if !s.runtimeOnly || !s.itemSessionActiveLocked() || s.authorizationEpoch != r.epoch || s.authorizationRevision != r.revision {
		return ErrExpired
	}
	if vault == nil || vault.Scope != r.scope {
		return ErrIdentity
	}
	digest, err := snapshotDigest(vault)
	if err != nil {
		return err
	}
	if digest != r.digest {
		return ErrIdentity
	}
	_, err = s.snapshotPoliciesLocked(vault)
	return err
}
func (r *RuntimeAuthority) Check(vault *VaultData) error {
	if r == nil {
		return ErrExpired
	}
	r.session.mu.Lock()
	defer r.session.mu.Unlock()
	return r.checkLocked(vault)
}

// WithProtection permits native runtime display/copy only while the original
// online capability is live. It never lends the disk snapshot unlock key.
// The callback must not reenter Session, and the host must check its own UI
// lifecycle/operation generation and revoke the corresponding native lease.
func (r *RuntimeAuthority) WithProtection(vault *VaultData, use func(time.Time) error) error {
	if r == nil || use == nil {
		return ErrExpired
	}
	r.session.mu.Lock()
	defer r.session.mu.Unlock()
	if err := r.checkLocked(vault); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	if r.expires.Before(deadline) {
		deadline = r.expires
	}
	return use(deadline)
}
