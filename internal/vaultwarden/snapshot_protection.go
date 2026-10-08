// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "time"

func (s *Session) secretProtectionKeyLocked() ([]byte, error) {
	if s.runtimeOnly {
		if err := s.runtimeCurrent.Load().CheckLease(); err != nil {
			return nil, err
		}
		return nil, nil // native runtime lease, never a disk unwrap key
	}
	if s.passwordUnlock == nil {
		return nil, ErrExpired
	}
	return append([]byte(nil), s.passwordUnlock.Key...), nil
}
func (s *Session) secretDeadlineLocked(deadline time.Time) time.Time {
	if s.runtimeOnly && s.expires.Before(deadline) {
		return s.expires
	}
	return deadline
}

// WithSnapshotProtection authorizes a short native secret action for the exact
// accepted vault. The callback borrows a copy of the snapshot key and must not
// reenter Session. It neither exports credentials nor renews a vault lease.
func (s *Session) WithSnapshotProtection(vault *VaultData, revision string, use func([]byte, time.Time) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return err
	}
	if revision == "" || revision != s.authorizationRevision || (s.passwordUnlock == nil && !s.runtimeOnly) || use == nil || !s.itemSessionActiveLocked() {
		return ErrExpired
	}
	key, err := s.secretProtectionKeyLocked()
	if err != nil {
		return err
	}
	defer clear(key)
	return use(key, s.secretDeadlineLocked(time.Now().Add(30*time.Second)))
}
