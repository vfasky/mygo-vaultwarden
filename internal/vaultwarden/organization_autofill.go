// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "encoding/json"

// appendOrganizationCredentialsLocked creates only the minimal authenticated
// Login projection. No organization key, membership or collection metadata is
// copied into the AutoFill payload. Full sync replacement revokes old entries.
func (s *Session) appendOrganizationCredentialsLocked(result *SyncResult) error {
	data, err := s.organizationVaultLocked(result.Vault)
	if err != nil {
		return err
	}
	defer data.close()
	documents, err := result.Vault.Documents(result.Vault.Scope)
	if err != nil {
		return err
	}
	for _, document := range documents {
		var item encryptedCipher
		if json.Unmarshal(document.JSON, &item) != nil {
			return ErrProtocol
		}
		if item.OrganizationID == nil || item.Type != 1 || item.Login == nil || item.Reprompt != 0 || item.DeletedDate != nil || item.ArchivedDate != nil || item.ViewPassword == nil || !*item.ViewPassword {
			continue
		}
		_, key, err := s.organizationDocumentLocked(result.Vault, item.ID, data)
		if err == ErrPermission || err == ErrNotFound {
			continue
		}
		if err != nil {
			return err
		}
		credential, skipped, err := decryptCipher(item, key)
		if err != nil {
			return err
		}
		result.Credentials = append(result.Credentials, credential)
		result.Summary.UnsupportedURIs += skipped
		result.Summary.Logins++
		if result.Summary.Organizations > 0 {
			result.Summary.Organizations--
		}
		if len(result.Credentials) > 10000 {
			return ErrProtocol
		}
	}
	return nil
}
