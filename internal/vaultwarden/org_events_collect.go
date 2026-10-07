// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// OrganizationClientEvent is emitted only after the corresponding client action
// actually happens. It is not a facility for forging server-side management logs.
type OrganizationClientEvent struct {
	Type           int       `json:"type"`
	Date           time.Time `json:"date"`
	OrganizationID string    `json:"organizationId"`
	CipherID       string    `json:"cipherId,omitempty"`
}

func (s *Session) CollectOrganizationEvents(ctx context.Context, vault *VaultData, events []OrganizationClientEvent, persist func(SessionCheckpoint) error) error {
	if len(events) == 0 || len(events) > 1000 {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	for _, event := range events {
		if !validObjectID(event.OrganizationID) || event.Date.IsZero() || data.keys[event.OrganizationID] == nil {
			return ErrPermission
		}
		if event.Type == 1602 {
			if event.CipherID != "" {
				return ErrValidation
			}
			continue
		}
		if !((event.Type >= 1107 && event.Type <= 1114) || event.Type == 1117 || (event.Type >= 1119 && event.Type <= 1132)) || !validObjectID(event.CipherID) {
			return ErrValidation
		}
		doc, ok := data.documents[event.CipherID]
		var meta struct{ OrganizationID *string }
		if !ok || json.Unmarshal(doc.JSON, &meta) != nil || meta.OrganizationID == nil || *meta.OrganizationID != event.OrganizationID {
			return ErrPermission
		}
	}
	body, err := json.Marshal(events)
	if err != nil {
		return ErrValidation
	}
	status, response, err := s.authenticatedGuardedLocked(ctx, http.MethodPost, "/events/collect", "application/json", string(body), persist, s.organizationManagementGuardLocked(s.authorizationRevision))
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
