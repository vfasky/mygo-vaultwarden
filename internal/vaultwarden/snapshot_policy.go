// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
)

// snapshotPolicies is authority held by this session, never by caller-owned
// VaultData. It binds all server policy and local quarantine bytes, not just the
// selected cipher. The copied policy tree does not alias the bridge reply.
type snapshotPolicies struct {
	policies *operationPolicies
	digest   [32]byte
	revision string
	epoch    uint64
}

func snapshotDigest(vault *VaultData) ([32]byte, error) {
	if vault == nil {
		return [32]byte{}, ErrIdentity
	}
	if _, err := vault.Documents(vault.Scope); err != nil {
		return [32]byte{}, err
	}
	encoded, err := json.Marshal(vault)
	if err != nil {
		return [32]byte{}, ErrProtocol
	}
	defer clear(encoded)
	return sha256.Sum256(encoded), nil
}

// RestoreSessionFromAuthenticatedSnapshot is a privileged app-controller entry
// point. The caller MUST have verified an authenticated list/listPassword bridge
// receipt, its current UI epoch, unlocked state, expected revision, and scope.
// This function does not authenticate Swift credentials and is not a sandbox
// against arbitrary in-process Go code. Ordinary RestoreSession restores only
// network credentials; a legacy cache without complete policy must sync first.
func RestoreSessionFromAuthenticatedSnapshot(data []byte, scope Scope, config *PasswordUnlockConfig, vault *VaultData, revision string) (*Session, error) {
	if len(data) == 0 || len(data) > 64*1024 || strictJSON(data) != nil {
		return nil, ErrProtocol
	}
	s, err := RestoreSession(data, scope, config)
	if err != nil {
		return nil, err
	}
	if err := s.AcceptAuthenticatedSnapshot(vault, revision); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// AcceptAuthenticatedSnapshot is the privileged counterpart for authenticated
// publish/quarantine/restore receipts on a live session. Call only AFTER the app
// verifies operation, epoch, previous revision, scope, new snapshot identity and
// preservation of quarantine markers. Public VaultData or BindSnapshotRevision
// alone is never authentication. Failure revokes the old authority as well.
func (s *Session) AcceptAuthenticatedSnapshot(vault *VaultData, revision string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.acceptSnapshotLocked(vault, revision); err != nil {
		return err
	}
	s.runtimeOnly = false
	s.runtimeSyncDigest = [32]byte{}
	return nil
}

func (s *Session) acceptSnapshotLocked(vault *VaultData, revision string) error {
	s.clearFreshRecoveryLogin()
	s.offlinePolicies = nil
	s.checkpointPolicies = nil
	s.advanceAuthorizationLocked()
	if !s.itemSessionActiveLocked() || revision == "" || len(revision) > 1024 {
		return ErrExpired
	}
	if vault == nil || s.requireScopeLocked(vault.Scope) != nil {
		return ErrIdentity
	}
	if (vault.Version != 1 && vault.Version != 2) || len(vault.Sync) == 0 || len(vault.Sync) > maxResponse || len(vault.QuarantinedOrganizations) > 1024 {
		return ErrProtocol
	}
	// Clone BEFORE parsing: no map, raw message or slice in the authority may
	// point back into the public snapshot passed by the controller.
	copyVault := &VaultData{Version: vault.Version, Scope: vault.Scope,
		Sync:                     append([]byte(nil), vault.Sync...),
		PendingPolicyMutations:   append([]PendingPolicyMutation(nil), vault.PendingPolicyMutations...),
		QuarantinedOrganizations: append([]string(nil), vault.QuarantinedOrganizations...)}
	defer clear(copyVault.Sync)
	digest, err := snapshotDigest(copyVault)
	if err != nil {
		return err
	}
	policies, err := parseOperationPolicies(copyVault.Sync, copyVault.Scope, s.email, s.wrapped)
	if err != nil {
		return err
	}
	if err := validateSnapshotOrganizationIdentity(copyVault.Sync, s.account); err != nil {
		return err
	}
	// Validate the complete organization identity/key chain before installing
	// any capability. Quarantine never removes server policies from parsing.
	organizations, err := s.decodeOrganizationVaultLocked(copyVault)
	if err != nil {
		return err
	}
	organizations.close()
	s.pendingPolicyMutations = append([]PendingPolicyMutation(nil), copyVault.PendingPolicyMutations...)
	applyPendingPolicies(policies, s.pendingPolicyMutations)
	s.authorizationRevision = revision
	s.offlinePolicies = &snapshotPolicies{policies: policies, digest: digest, revision: revision, epoch: s.authorizationEpoch}
	return nil
}

func validateSnapshotOrganizationIdentity(sync []byte, account string) error {
	var data struct {
		Profile struct{ Organizations, OrganizationsNew []Organization }
	}
	if json.Unmarshal(sync, &data) != nil || data.Profile.Organizations == nil || data.Profile.OrganizationsNew == nil || len(data.Profile.OrganizationsNew) > 2048 {
		return ErrProtocol
	}
	// Check even locally quarantined memberships: isolation removes access,
	// not the server identity or the policies attached to that identity.
	newer := make(map[string]Organization, len(data.Profile.OrganizationsNew))
	members := make(map[string]bool, len(data.Profile.OrganizationsNew))
	for _, org := range data.Profile.OrganizationsNew {
		if _, duplicate := newer[org.ID]; duplicate || !validObjectID(org.ID) || !validObjectID(org.OrganizationUserID) || org.UserID != account || org.OrganizationUserID == account || members[org.OrganizationUserID] {
			return ErrIdentity
		}
		members[org.OrganizationUserID] = true
		newer[org.ID] = org
	}
	for _, org := range data.Profile.Organizations {
		other, found := newer[org.ID]
		if !found || !reflect.DeepEqual(org, other) {
			return ErrIdentity
		}
	}
	return nil
}

func (s *Session) snapshotPoliciesLocked(vault *VaultData) (*operationPolicies, error) {
	p := s.offlinePolicies
	if !s.itemSessionActiveLocked() || p == nil || p.epoch != s.authorizationEpoch || p.revision == "" || p.revision != s.authorizationRevision {
		return nil, ErrExpired
	}
	if vault == nil || vault.Scope != p.policies.scope {
		return nil, ErrIdentity
	}
	digest, err := snapshotDigest(vault)
	if err != nil {
		return nil, err
	}
	if digest != p.digest {
		return nil, ErrExpired
	}
	return p.policies, nil
}

// DefaultURIMatch returns the effective inherited rule for an authenticated
// snapshot. Keep login.uri.match null in editors: policy changes must continue
// to affect inherited defaults instead of freezing them as explicit rules.
func (s *Session) DefaultURIMatch(vault *VaultData) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policies, err := s.snapshotPoliciesLocked(vault)
	if err != nil {
		return 0, err
	}
	return policies.defaultURIMatch, nil
}

// ValidateAuthenticatedSnapshot checks an already installed capability; it never
// creates one. The controller calls it before adopting any display metadata.
func (s *Session) ValidateAuthenticatedSnapshot(vault *VaultData, revision string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision == "" || revision != s.authorizationRevision {
		return ErrExpired
	}
	_, err := s.snapshotPoliciesLocked(vault)
	return err
}
