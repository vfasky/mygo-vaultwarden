// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

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
		state := "已停止，请同步核对"
		var uncertain *MutationUncertainError
		if errors.As(err, &uncertain) {
			state = "结果未知，请同步核对；禁止重试"
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
			return fail("文件夹", folder.Name, "", err)
		}
		mapping[folder.ID] = created.ID
		result.Entries = append(result.Entries, ImportEntry{Kind: "文件夹", Name: folder.Name, ID: created.ID, State: "已创建"})
	}
	for i, document := range documents {
		if ctx.Err() != nil {
			return result, ErrCancelled
		}
		item := file.Items[i]
		name := item["name"].(string)
		object, _ := documentObject(document)
		if folder, ok := item["folderId"].(string); ok {
			object["folderId"] = mapping[folder]
		}
		encoded, _ := json.Marshal(object)
		created, err := s.createCipherDocumentLocked(ctx, CipherDocument{JSON: encoded}, persist)
		if err != nil {
			return fail("项目", name, "", err)
		}
		fields, err := DecryptCipherDocument(created, s.key)
		if err != nil {
			return fail("项目", name, "", &MutationUncertainError{Cause: err})
		}
		if item["deletedDate"] != nil {
			// POST creates active records. Preserve trash membership with the actual
			// soft-delete method; the server assigns a new deletion timestamp.
			status, _, err := s.authenticatedLocked(ctx, http.MethodPut, "/api/ciphers/"+fields.ID+"/delete", "", "", persist)
			if err == nil && status != http.StatusOK && status != http.StatusNoContent {
				err = mutationStatusError(status)
			}
			if err != nil {
				return fail("项目（已创建，回收站状态待核对）", name, fields.ID, err)
			}
		}
		result.Entries = append(result.Entries, ImportEntry{Kind: "项目", Name: name, ID: fields.ID, State: "已创建，待同步核对", SourceID: item["id"].(string)})
	}
	if ctx.Err() != nil {
		return result, &MutationUncertainError{Cause: ErrCancelled}
	}
	return result, nil
}
