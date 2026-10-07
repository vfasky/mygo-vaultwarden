// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
)

const CipherMove CipherAction = "move"

// ChangePersonalCiphers uses the server's batch routes. Even a 400 can follow
// partial writes (Vaultwarden 1.37.4 ciphers.rs); any response failure requires
// sync reconciliation of every selected ID, never an automatic retry.
func (s *Session) ChangePersonalCiphers(ctx context.Context, scope Scope, vault *VaultData, ids []string, action CipherAction, folderID *string, persist func(SessionCheckpoint) error) error {
	if len(ids) == 0 || len(ids) > 10000 || (folderID != nil && !validObjectID(*folderID)) {
		return ErrValidation
	}
	if vault == nil || vault.Scope != scope {
		return ErrIdentity
	}
	docs, err := vault.Documents(scope)
	if err != nil {
		return err
	}
	records := map[string]struct{ deleted bool }{}
	for _, doc := range docs {
		var meta struct {
			ID             string
			OrganizationID *string
			Edit           *bool
			DeletedDate    *string
			Reprompt       int
			ViewPassword   *bool
		}
		if json.Unmarshal(doc.JSON, &meta) != nil {
			return ErrProtocol
		}
		if meta.OrganizationID == nil && (meta.Edit == nil || *meta.Edit) && meta.Reprompt == 0 && (meta.ViewPassword == nil || *meta.ViewPassword) {
			records[meta.ID] = struct{ deleted bool }{meta.DeletedDate != nil}
		}
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !validObjectID(id) || seen[id] {
			return ErrValidation
		}
		seen[id] = true
		record, ok := records[id]
		if !ok {
			return ErrPermission
		}
		if action == CipherDeletePermanently && !record.deleted {
			return ErrPermission
		}
	}
	method, endpoint := http.MethodPut, "/api/ciphers"
	switch action {
	case CipherTrash:
		endpoint += "/delete"
	case CipherRestore:
		endpoint += "/restore"
	case CipherArchive:
		endpoint += "/archive"
	case CipherUnarchive:
		endpoint += "/unarchive"
	case CipherDeletePermanently:
		method = http.MethodDelete
	case CipherMove:
		endpoint += "/move"
	default:
		return ErrValidation
	}
	body := map[string]any{"ids": ids}
	if action == CipherMove {
		body["folderId"] = folderID
	}
	raw, _ := json.Marshal(body)
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err = s.requireScopeLocked(scope); err != nil {
		return err
	}
	status, _, err := s.authenticatedLocked(ctx, method, endpoint, "application/json", string(raw), persist)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return &MutationUncertainError{Cause: statusError(status)}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
