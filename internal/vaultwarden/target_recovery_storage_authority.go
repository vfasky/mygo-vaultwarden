// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

// WithTargetRecoveryStorageKey borrows only the genuine current local unlock
// material for constructing a scoped metadata adapter. The callback may copy it
// into that adapter; it must not reenter Session, prompt, or dispatch UI work.
// Runtime sessions must use their separate native recovery capability instead.
func (s *Session) WithTargetRecoveryStorageKey(vault *VaultData, revision string, use func(Scope, []byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if use == nil || s.runtimeOnly || s.passwordUnlock == nil || len(s.passwordUnlock.Key) != 32 || revision == "" || revision != s.authorizationRevision {
		return ErrPermission
	}
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return err
	}
	key := append([]byte(nil), s.passwordUnlock.Key...)
	defer clear(key)
	return use(vault.Scope, key)
}
