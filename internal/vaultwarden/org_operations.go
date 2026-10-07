// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
)

// OrganizationOperationResult never infers rollback from an HTTP error. An
// uncertain batch must be reconciled by a fresh sync before any retry.
type OrganizationOperationResult struct {
	IDs                  []string
	Applied              bool
	ReconcileRequired    bool
	ImportReconciliation *OrganizationImportReconciliation
}

func (s *Session) orgOperationGuardLocked() func() error {
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	return func() error {
		if !s.itemSessionActiveLocked() || revision == "" || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		return nil
	}
}

func organizationStateRoute(action CipherAction) (string, string, error) {
	switch action {
	case CipherTrash:
		return http.MethodPut, "/api/ciphers/delete", nil
	case CipherRestore:
		return http.MethodPut, "/api/ciphers/restore", nil
	case CipherArchive:
		return http.MethodPut, "/api/ciphers/archive", nil
	case CipherUnarchive:
		return http.MethodPut, "/api/ciphers/unarchive", nil
	case CipherDeletePermanently:
		return http.MethodDelete, "/api/ciphers", nil
	}
	return "", "", ErrValidation
}

type organizationStateMeta struct {
	ID                        string
	OrganizationID            *string
	Edit, ViewPassword        *bool
	Reprompt                  *int
	Type                      int
	DeletedDate, RevisionDate *string
}

func validateOrganizationState(document CipherDocument, orgID string, action CipherAction) (organizationStateMeta, error) {
	var m organizationStateMeta
	if json.Unmarshal(document.JSON, &m) != nil {
		return m, ErrProtocol
	}
	if m.OrganizationID == nil || *m.OrganizationID != orgID || m.Edit == nil || !*m.Edit || m.ViewPassword == nil || !*m.ViewPassword || m.Reprompt == nil || *m.Reprompt < 0 || *m.Reprompt > 1 || m.Type < 1 || m.Type > 8 {
		return m, ErrPermission
	}
	if action == CipherDeletePermanently && m.DeletedDate == nil {
		return m, ErrPermission
	}
	return m, nil
}

// ChangeOrganizationCiphers supports a single ID or one nontransactional batch.
// Grants are per-item and bound to the authenticated snapshot; the caller must
// clear its editor and sync after completion. No plaintext is decrypted here.
func (s *Session) ChangeOrganizationCiphers(ctx context.Context, vault *VaultData, orgID string, ids []string, action CipherAction, grants map[string]*ItemAuthorization, persist func(SessionCheckpoint) error) (OrganizationOperationResult, error) {
	result := OrganizationOperationResult{IDs: append([]string(nil), ids...)}
	method, path, err := organizationStateRoute(action)
	if err != nil {
		return result, err
	}
	if !validObjectID(orgID) || len(ids) == 0 || len(ids) > 10000 {
		return result, ErrValidation
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !validObjectID(id) || seen[id] {
			return result, ErrValidation
		}
		seen[id] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return result, err
	}
	defer data.close()
	documents := map[string]CipherDocument{}
	metadata := map[string]organizationStateMeta{}
	for _, id := range ids {
		doc, _, err := s.organizationDocumentLocked(vault, id, data)
		if err != nil {
			return result, err
		}
		meta, err := validateOrganizationState(doc, orgID, action)
		if err != nil {
			return result, err
		}
		if *meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grants[id], doc) {
			return result, ErrPermission
		}
		documents[id], metadata[id] = doc, meta
	}
	// Read current memberships, policy and cipher flags once for the whole batch.
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return result, err
	}
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return result, err
	}
	member, ok := policies.memberships[orgID]
	if !ok || *member.Status != 2 || !*member.Enabled {
		return result, ErrPermission
	}
	matched := false
	for _, org := range data.organizations {
		if org.ID == orgID && org.OrganizationUserID == member.MemberID && org.UserID == member.UserID && org.Type == *member.Type {
			matched = true
		}
	}
	if !matched {
		return result, ErrExpired
	}
	found := map[string]bool{}
	for _, raw := range policies.ciphers {
		var identity struct{ ID string }
		if json.Unmarshal(raw, &identity) != nil {
			return result, ErrProtocol
		}
		if !seen[identity.ID] {
			continue
		}
		if found[identity.ID] {
			return result, ErrProtocol
		}
		m, err := validateOrganizationState(CipherDocument{JSON: raw}, orgID, action)
		if err != nil {
			return result, err
		}
		old := metadata[identity.ID]
		if m.Type != old.Type || *m.Reprompt != *old.Reprompt || !sameOptional(m.RevisionDate, old.RevisionDate) || !sameOptional(m.DeletedDate, old.DeletedDate) {
			return result, ErrConflict
		}
		if policies.restricts(m.OrganizationID, m.Type) {
			return result, ErrPermission
		}
		found[identity.ID] = true
	}
	if len(found) != len(seen) {
		return result, ErrConflict
	}
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	guard := func() error {
		if !s.itemSessionActiveLocked() || revision == "" || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		if err := s.checkOperationPoliciesLocked(ctx, policies); err != nil {
			return err
		}
		for id, doc := range documents {
			if *metadata[id].Reprompt != 0 && !s.validItemAuthorizationLocked(grants[id], doc) {
				return ErrPermission
			}
		}
		return nil
	}
	body, _ := json.Marshal(map[string]any{"ids": ids})
	status, response, err := s.authenticatedGuardedLocked(ctx, method, path, "application/json", string(body), persist, guard)
	if err != nil {
		// Conservatively reconcile transport/checkpoint errors; never retry a batch.
		result.ReconcileRequired = true
		return result, err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		result.ReconcileRequired = true
		return result, &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	if ctx.Err() != nil {
		result.ReconcileRequired = true
		return result, &MutationUncertainError{Cause: ErrCancelled}
	}
	result.Applied = true
	return result, nil
}
