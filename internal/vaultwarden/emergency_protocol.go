// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
)

// EmergencyContact describes the OTHER party. Trusted is the grantor's list;
// granted is the grantee's list. Neither response contains the acting user's ID.
type EmergencyContact struct {
	ID           string `json:"id"`
	Status       int    `json:"status"`
	Type         int    `json:"type"`
	WaitTimeDays int    `json:"waitTimeDays"`
	GrantorID    string `json:"grantorId,omitempty"`
	GranteeID    string `json:"granteeId,omitempty"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	Object       string `json:"object"`
}

func decodeEmergencyContacts(body []byte, trusted bool, actor string) ([]EmergencyContact, error) {
	var list struct {
		Data              []json.RawMessage `json:"data"`
		Object            string            `json:"object"`
		ContinuationToken json.RawMessage   `json:"continuationToken"`
	}
	if strictJSON(body) != nil || json.Unmarshal(body, &list) != nil || list.Data == nil || list.Object != "list" || string(list.ContinuationToken) != "null" {
		return nil, ErrProtocol
	}
	out := make([]EmergencyContact, 0, len(list.Data))
	seen := map[string]bool{}
	for _, raw := range list.Data {
		var c EmergencyContact
		var fields map[string]json.RawMessage
		if strictJSON(raw) != nil || json.Unmarshal(raw, &c) != nil || json.Unmarshal(raw, &fields) != nil {
			return nil, ErrProtocol
		}
		for field := range fields {
			switch field {
			case "id", "status", "type", "waitTimeDays", "email", "name", "object", "granteeId", "grantorId", "avatarColor":
			default:
				return nil, ErrProtocol
			}
		}
		for _, f := range []string{"id", "status", "type", "waitTimeDays", "email", "object"} {
			if fields[f] == nil || string(fields[f]) == "null" {
				return nil, ErrProtocol
			}
		}
		if !validObjectID(c.ID) || seen[c.ID] || c.Status < 0 || c.Status > 4 || c.Type < 0 || c.Type > 1 || c.WaitTimeDays < 0 || c.Email == "" {
			return nil, ErrProtocol
		}
		if trusted {
			if c.Object != "emergencyAccessGranteeDetails" || !validObjectID(c.GranteeID) || c.GranteeID == actor || c.GrantorID != "" {
				return nil, ErrIdentity
			}
		} else {
			if c.Object != "emergencyAccessGrantorDetails" || !validObjectID(c.GrantorID) || c.GrantorID == actor || c.GranteeID != "" {
				return nil, ErrIdentity
			}
		}
		seen[c.ID] = true
		out = append(out, c)
	}
	return out, nil
}

func (s *Session) recoveryReadLocked(ctx context.Context, path string, persist func(SessionCheckpoint) error, guard func() error) ([]byte, error) {
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, path, "", "", persist, guard)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, statusError(status)
	}
	return body, nil
}
func (s *Session) recoveryGuardLocked(epoch uint64, revision string) func() error {
	return func() error {
		if !s.itemSessionActiveLocked() || epoch != s.authorizationEpoch || revision == "" || revision != s.authorizationRevision {
			return ErrExpired
		}
		return nil
	}
}
func (s *Session) emergencyContactsLocked(ctx context.Context, trusted bool, persist func(SessionCheckpoint) error, guard func() error) ([]EmergencyContact, error) {
	path := "/api/emergency-access/granted"
	if trusted {
		path = "/api/emergency-access/trusted"
	}
	body, err := s.recoveryReadLocked(ctx, path, persist, guard)
	if err != nil {
		return nil, err
	}
	return decodeEmergencyContacts(body, trusted, s.account)
}

// EmergencyContacts requires the authenticated full snapshot. An empty response
// is NOT proof that no grants exist: 1.37.4 hides them when the feature is off.
func (s *Session) EmergencyContacts(ctx context.Context, vault *VaultData, trusted bool, persist func(SessionCheckpoint) error) ([]EmergencyContact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	return s.emergencyContactsLocked(ctx, trusted, persist, s.recoveryGuardLocked(s.authorizationEpoch, s.authorizationRevision))
}

// EmergencyActionAllowed is a UI filter only. Commit re-reads the list and the
// server always enforces the final role/state. No client clock grants access.
func EmergencyActionAllowed(c EmergencyContact, trusted bool, action string) bool {
	switch action {
	case "reinvite":
		return trusted && c.Status == 0
	case "confirm":
		return trusted && c.Status == 1
	case "initiate":
		return !trusted && c.Status == 2
	case "approve":
		return trusted && c.Status == 3
	case "reject":
		return trusted && (c.Status == 3 || c.Status == 4)
	case "view":
		return !trusted && c.Status == 4 && c.Type == 0
	case "takeover", "password", "policies":
		return !trusted && c.Status == 4 && c.Type == 1
	case "delete", "update":
		return action == "delete" || trusted
	}
	return false
}
