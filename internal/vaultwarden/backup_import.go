// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"net/http"
)

// Import kinds and states describe in-memory outcomes, not backup or API fields.
const (
	ImportKindFolder              = "folder"
	ImportKindItem                = "item"
	ImportKindItemTrashUnverified = "item_trash_unverified"

	ImportStateCreated            = "created"
	ImportStateCreatedPendingSync = "created_pending_sync"
	ImportStateStopped            = "stopped"
	ImportStateUnknown            = "unknown"
	ImportStateMetadataCopied     = "metadata_copied"
)

func ImportKindText(kind string) string {
	switch kind {
	case ImportKindFolder:
		return i18n.T("state.import.kind_folder")
	case ImportKindItem:
		return i18n.T("state.import.kind_item")
	case ImportKindItemTrashUnverified:
		return i18n.T("state.import.kind_item_trash_unverified")
	default:
		return kind
	}
}

func ImportStateText(state string) string {
	switch state {
	case ImportStateCreated:
		return i18n.T("state.import.status_created")
	case ImportStateCreatedPendingSync:
		return i18n.T("state.import.status_created_pending_sync")
	case ImportStateStopped:
		return i18n.T("state.import.status_stopped")
	case ImportStateUnknown:
		return i18n.T("state.import.status_unknown")
	case ImportStateMetadataCopied:
		return i18n.T("state.import.status_metadata_copied")
	default:
		return state
	}
}

// ImportResult records each attempted create. Stop at the first failure; never
// repeat the import automatically, including when only folder creation succeeded.
type ImportResult struct{ Entries []ImportEntry }
type ImportEntry struct{ Kind, Name, ID, State, SourceID string }

func (s *Session) ImportPersonalBackup(ctx context.Context, scope Scope, plan *ImportPlan, persist func(SessionCheckpoint) error) (ImportResult, error) {
	result := ImportResult{}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	if err = s.requireScopeLocked(scope); err != nil {
		return result, err
	}
	if plan == nil {
		return result, ErrValidation
	}
	file, err := decodeBackup(plan.data, plan.Format)
	if err != nil {
		return result, err
	}
	// Encrypt and validate EVERY item before creating ANY folder. Failure cannot
	// leave a partially imported file due to a later unsupported crypto field.
	documents := make([]CipherDocument, len(file.Items))
	for i, item := range file.Items {
		if ctx.Err() != nil {
			return result, ErrCancelled
		}
		documents[i], err = encryptImportedItem(item, s.key, s.account)
		if err != nil {
			return result, err
		}
	}
	// Check every item's policy before the first folder or cipher is created.
	// The private context is reused only inside this import operation.
	if _, err := s.operationPoliciesLocked(ctx, persist); err != nil {
		return result, err
	}
	for _, document := range documents {
		var metadata struct{ Type int }
		if json.Unmarshal(document.JSON, &metadata) != nil {
			return result, ErrProtocol
		}
		if _, err := s.personalCipherPolicyGuardLocked(ctx, metadata.Type, persist, nil); err != nil {
			return result, err
		}
	}
	mapping := map[string]string{}
	fail := func(kind, name, id string, err error) (ImportResult, error) {
		state := ImportStateStopped
		var uncertain *MutationUncertainError
		if errors.As(err, &uncertain) {
			state = ImportStateUnknown
		}
		result.Entries = append(result.Entries, ImportEntry{Kind: kind, Name: name, ID: id, State: state})
		return result, err
	}
	for _, folder := range file.Folders {
		if ctx.Err() != nil {
			return result, ErrCancelled
		}
		created, err := s.saveFolderLocked(ctx, "", folder.Name, persist)
		if err != nil {
			return fail(ImportKindFolder, folder.Name, "", err)
		}
		mapping[folder.ID] = created.ID
		result.Entries = append(result.Entries, ImportEntry{Kind: ImportKindFolder, Name: folder.Name, ID: created.ID, State: ImportStateCreated})
	}
	for i, document := range documents {
		if ctx.Err() != nil {
			return result, ErrCancelled
		}
		item := file.Items[i]
		identity, err := backupItemIdentity(item)
		if err != nil {
			return result, err
		}
		name := identity.Name
		object, err := documentObject(document)
		if err != nil {
			return result, err
		}
		if folder, ok := item["folderId"].(string); ok {
			object["folderId"] = mapping[folder]
		}
		encoded, err := json.Marshal(object)
		if err != nil {
			return result, ErrProtocol
		}
		created, err := s.createCipherDocumentLocked(ctx, CipherDocument{JSON: encoded}, persist)
		if err != nil {
			return fail(ImportKindItem, name, "", err)
		}
		fields, err := DecryptCipherDocument(created, s.key)
		if err != nil {
			return fail(ImportKindItem, name, "", &MutationUncertainError{Cause: err})
		}
		if item["deletedDate"] != nil {
			// POST creates active records. Preserve trash membership with the actual
			// soft-delete method; the server assigns a new deletion timestamp.
			status, _, err := s.authenticatedLocked(ctx, http.MethodPut, "/api/ciphers/"+fields.ID+"/delete", "", "", persist)
			if err == nil && status != http.StatusOK && status != http.StatusNoContent {
				err = mutationStatusError(status)
			}
			if err != nil {
				return fail(ImportKindItemTrashUnverified, name, fields.ID, err)
			}
		}
		result.Entries = append(result.Entries, ImportEntry{Kind: ImportKindItem, Name: name, ID: fields.ID, State: ImportStateCreatedPendingSync, SourceID: identity.ID})
	}
	if ctx.Err() != nil {
		return result, &MutationUncertainError{Cause: ErrCancelled}
	}
	return result, nil
}
