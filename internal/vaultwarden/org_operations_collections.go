// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// AssignOrganizationCipherCollections replaces the caller-visible collection
// associations, as the official /collections route does. The server may retain
// associations hidden from this member. Empty targets are allowed (unassignment).
// Since removing an association can revoke the caller's own access, isolation
// must be durable before even the policy preflight GET. It is never auto-lifted.
func (s *Session) AssignOrganizationCipherCollections(ctx context.Context, vault *VaultData, orgID, cipherID string, collectionIDs []string, grant *ItemAuthorization, isolate, persist func(SessionCheckpoint) error) error {
	if !validObjectID(orgID) || !validObjectID(cipherID) || len(collectionIDs) > 10000 {
		return ErrValidation
	}
	targets := map[string]bool{}
	for _, id := range collectionIDs {
		if !validObjectID(id) || targets[id] {
			return ErrValidation
		}
		targets[id] = true
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
	doc, _, err := s.organizationDocumentLocked(vault, cipherID, data)
	if err != nil {
		return err
	}
	meta, err := validateOrganizationState(doc, orgID, CipherTrash)
	if err != nil {
		return err
	}
	var original struct{ CollectionIDs []string }
	if json.Unmarshal(doc.JSON, &original) != nil {
		return ErrProtocol
	}
	current := map[string]bool{}
	for _, id := range original.CollectionIDs {
		current[id] = true
	}
	for id := range targets {
		if !current[id] && !data.writableCollection(orgID, id) {
			return ErrPermission
		}
	}
	for id := range current {
		if !targets[id] && !data.writableCollection(orgID, id) {
			return ErrPermission
		}
	}
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	if *meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, doc) {
		return ErrPermission
	}
	// A successful isolation deliberately invalidates external grants. Retain
	// only this already-authorized operation's deadline under the session lock.
	var deadline time.Time
	if *meta.Reprompt != 0 {
		deadline = grant.ExpiresAt()
	}
	guard := func() error {
		if !s.itemSessionActiveLocked() || revision == "" || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return ErrPermission
		}
		return nil
	}
	if err := guard(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if isolate == nil {
		return ErrCheckpoint
	}
	if err := s.checkpointLocked(isolate); err != nil {
		return ErrCheckpoint
	}
	epoch = s.authorizationEpoch
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return err
	}
	found := false
	for _, raw := range policies.ciphers {
		var identity struct{ ID string }
		if json.Unmarshal(raw, &identity) != nil {
			return ErrProtocol
		}
		if identity.ID != cipherID {
			continue
		}
		if found {
			return ErrProtocol
		}
		found = true
		live, err := validateOrganizationState(CipherDocument{JSON: raw}, orgID, CipherTrash)
		if err != nil {
			return err
		}
		if live.Type != meta.Type || *live.Reprompt != *meta.Reprompt || !sameOptional(live.RevisionDate, meta.RevisionDate) {
			return ErrConflict
		}
		var associations struct{ CollectionIDs []string }
		if json.Unmarshal(raw, &associations) != nil {
			return ErrProtocol
		}
		liveSet := map[string]bool{}
		for _, id := range associations.CollectionIDs {
			liveSet[id] = true
		}
		if len(liveSet) != len(current) {
			return ErrConflict
		}
		for id := range current {
			if !liveSet[id] {
				return ErrConflict
			}
		}
	}
	if !found {
		return ErrConflict
	}
	guard, err = s.organizationCipherPolicyGuardLocked(ctx, data, orgID, meta.Type, persist, guard)
	if err != nil {
		return err
	}
	// Encode an empty selection as [], never null.
	selected := append([]string{}, collectionIDs...)
	body, _ := json.Marshal(map[string]any{"collectionIds": selected})
	status, response, err := s.authenticatedGuardedLocked(ctx, http.MethodPut, "/api/ciphers/"+cipherID+"/collections", "application/json", string(body), persist, guard)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	var result struct {
		ID             string
		OrganizationID *string
	}
	if json.Unmarshal(response, &result) != nil || result.ID != cipherID || result.OrganizationID == nil || *result.OrganizationID != orgID {
		return &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
