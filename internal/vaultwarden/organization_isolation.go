// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "encoding/json"

// IsolatedOrganizations returns only the names needed for explicit recovery.
// Missing memberships remain listed so ordinary sync cannot hide a local marker.
func (s *Session) IsolatedOrganizations(vault *VaultData) ([]Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.itemSessionActiveLocked() || vault == nil {
		return nil, ErrExpired
	}
	if err := s.requireScopeLocked(vault.Scope); err != nil {
		return nil, err
	}
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return nil, err
	}
	if _, err := vault.Documents(vault.Scope); err != nil {
		return nil, err
	}
	var data struct {
		Profile struct{ Organizations []Organization }
	}
	if json.Unmarshal(vault.Sync, &data) != nil {
		return nil, ErrProtocol
	}
	result := make([]Organization, 0, len(vault.QuarantinedOrganizations))
	for _, id := range vault.QuarantinedOrganizations {
		name := "已退出或删除的组织"
		for _, org := range data.Profile.Organizations {
			if org.ID == id {
				name = org.Name
			}
		}
		result = append(result, Organization{ID: id, Name: name})
	}
	return result, nil
}
