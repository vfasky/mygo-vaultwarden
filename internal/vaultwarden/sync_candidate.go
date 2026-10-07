// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

// A network candidate can prove only recovery eligibility. It cannot authorize
// offline reads before the bridge durably publishes a verified snapshot receipt.
type syncCandidate struct {
	session       *Session
	epoch         uint64
	scope         Scope
	digest        [32]byte
	organizations []string
}

func (s *Session) recoveryCandidateLocked(result *SyncResult) error {
	digest, err := snapshotDigest(result.Vault)
	if err != nil {
		return err
	}
	result.candidate = &syncCandidate{session: s, epoch: s.authorizationEpoch, scope: result.Scope, digest: digest, organizations: append([]string(nil), result.confirmedOrganizations...)}
	result.confirmedOrganizations = nil
	return nil
}

// ValidateOrganizationRecoveryCandidate checks a successful sync's private
// provenance and complete content without granting an offline policy context.
func (s *Session) ValidateOrganizationRecoveryCandidate(result SyncResult, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := result.candidate
	if !s.itemSessionActiveLocked() || c == nil || c.session != s || c.epoch != s.authorizationEpoch {
		return ErrExpired
	}
	if result.Scope != c.scope || s.requireScopeLocked(c.scope) != nil || result.Vault == nil || result.Vault.Scope != c.scope {
		return ErrIdentity
	}
	digest, err := snapshotDigest(result.Vault)
	if err != nil {
		return err
	}
	if digest != c.digest {
		return ErrExpired
	}
	for _, org := range c.organizations {
		if org == id {
			return nil
		}
	}
	return ErrPermission
}
