// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
)

// personalBackupAccess is used only during one locked Session operation. It
// exposes authorization and cryptography, never the session or its raw key.
type personalBackupAccess interface {
	checkScope(Scope) error
	policies(*VaultData) (*operationPolicies, error)
	validGrant(*ItemAuthorization, CipherDocument) bool
	decryptItem(CipherDocument, map[string]any) (CipherFields, error)
	decryptFolder(string) ([]byte, error)
	checkExport(*VaultData, []string, map[string]*ItemAuthorization) error
}

type personalBackupService struct{ access personalBackupAccess }
type sessionPersonalBackupAccess struct{ session *Session }

func (a sessionPersonalBackupAccess) checkScope(scope Scope) error {
	return a.session.requireScopeLocked(scope)
}
func (a sessionPersonalBackupAccess) policies(vault *VaultData) (*operationPolicies, error) {
	return a.session.snapshotPoliciesLocked(vault)
}
func (a sessionPersonalBackupAccess) validGrant(grant *ItemAuthorization, doc CipherDocument) bool {
	return a.session.validItemAuthorizationLocked(grant, doc)
}
func (a sessionPersonalBackupAccess) decryptItem(doc CipherDocument, object map[string]any) (CipherFields, error) {
	fields, err := DecryptCipherDocument(doc, a.session.key)
	if err != nil {
		return CipherFields{}, err
	}
	key, err := cipherItemKey(object, a.session.key)
	if err != nil {
		return CipherFields{}, err
	}
	defer clear(key)
	if err := transformCompleteCipher(object, key, false); err != nil {
		return CipherFields{}, err
	}
	return fields, nil
}
func (a sessionPersonalBackupAccess) decryptFolder(name string) ([]byte, error) {
	return vaultcrypto.DecryptString(name, a.session.key)
}
func (a sessionPersonalBackupAccess) checkExport(vault *VaultData, ids []string, grants map[string]*ItemAuthorization) error {
	return a.session.personalBackupAuthorizationLocked(vault, ids, grants)
}

func (s *Session) exportPersonalBackup(ctx context.Context, vault *VaultData, ids []string, format BackupFormat, grants map[string]*ItemAuthorization, resources bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	service := personalBackupService{access: sessionPersonalBackupAccess{session: s}}
	return service.export(ctx, vault, ids, format, grants, resources)
}
