// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// ParseBitwardenOrganizationJSON reads the official unencrypted organization
// envelope. It is deliberately separate from the lossless MyGo format. Unsupported
// fields fail closed; no private key, attachment or passkey is silently dropped.
func ParseBitwardenOrganizationJSON(raw []byte) (*OrganizationImportPlan, error) {
	if len(raw) == 0 || len(raw) > maxResponse || strictJSON(raw) != nil {
		return nil, ErrValidation
	}
	root, err := documentObject(CipherDocument{JSON: raw})
	if err != nil {
		return nil, err
	}
	if err := copyKeys(root, "encrypted", "collections", "items"); err != nil {
		return nil, err
	}
	if flag, ok := root["encrypted"].(bool); !ok || flag {
		return nil, ErrValidation
	}
	var input struct {
		Encrypted   bool `json:"encrypted"`
		Collections []struct {
			ID             string  `json:"id"`
			OrganizationID *string `json:"organizationId"`
			Name           string  `json:"name"`
			ExternalID     *string `json:"externalId"`
		} `json:"collections"`
		Items []map[string]any `json:"items"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || input.Encrypted || input.Collections == nil || input.Items == nil {
		return nil, ErrValidation
	}
	// Official exports can omit organizationId. This namespace is local preview
	// metadata only and is never used as target authority or sent to the server.
	source := "00000000-0000-4000-8000-000000000001"
	declared := ""
	acceptOrg := func(value any) bool {
		if value == nil {
			return true
		}
		id, ok := value.(string)
		if !ok || !backupUUID(id) {
			return false
		}
		if declared != "" && declared != id {
			return false
		}
		declared = id
		return true
	}
	for _, c := range input.Collections {
		if c.OrganizationID != nil && !acceptOrg(*c.OrganizationID) {
			return nil, ErrIdentity
		}
	}
	for _, item := range input.Items {
		if !acceptOrg(item["organizationId"]) {
			return nil, ErrIdentity
		}
	}
	if declared != "" {
		source = declared
	}
	file := organizationBackup{Format: organizationBackupFormat, Version: 1, OrganizationID: source, Collections: []OrganizationBackupCollection{}, Items: input.Items}
	for _, c := range input.Collections {
		if !backupUUID(c.ID) {
			return nil, ErrValidation
		}
		file.Collections = append(file.Collections, OrganizationBackupCollection{ID: c.ID, OrganizationID: source, Name: c.Name, ExternalID: c.ExternalID})
	}
	for _, item := range file.Items {
		if id, ok := item["id"].(string); !ok || !backupUUID(id) {
			return nil, ErrValidation
		}
		if err := validateOfficialOrganizationItem(item); err != nil {
			return nil, err
		}
		item["organizationId"] = source
	}
	encoded, err := json.Marshal(file)
	if err != nil {
		return nil, ErrProtocol
	}
	defer clear(encoded)
	return ParseOrganizationImport(encoded)
}

// Only derived aliases and verifiably regenerable checksums can be omitted.
// Real metadata, conflicting legacy URI and unknown fields fail closed.
func normalizeOfficialOrganizationLogin(item map[string]any) error {
	login, ok := item["login"].(map[string]any)
	if !ok {
		return nil
	}
	uris, _ := login["uris"].([]any)
	if alias := login["uri"]; alias != nil {
		if len(uris) == 0 {
			return ErrUnsupportedEdit
		}
		first, ok := uris[0].(map[string]any)
		if !ok || first["uri"] != alias {
			return ErrUnsupportedEdit
		}
	}
	if login["autofillOnPageLoad"] != nil || login["passwordRevisionDate"] != nil {
		return ErrUnsupportedEdit
	}
	delete(login, "uri")
	delete(login, "autofillOnPageLoad")
	delete(login, "passwordRevisionDate")
	for _, raw := range uris {
		uri, ok := raw.(map[string]any)
		if !ok {
			return ErrProtocol
		}
		if checksum := uri["uriChecksum"]; checksum != nil {
			text, ok := uri["uri"].(string)
			hash := sha256.Sum256([]byte(text))
			if !ok || checksum != base64.StdEncoding.EncodeToString(hash[:]) {
				return ErrUnsupportedEdit
			}
		}
		delete(uri, "uriChecksum")
	}
	return nil
}

func validateOfficialOrganizationItem(item map[string]any) error {
	local := map[string]any{}
	for k, v := range item {
		local[k] = v
	}
	delete(local, "organizationId")
	delete(local, "collectionIds")
	return validateBackupItem(local, BitwardenJSON)
}

// WithBitwardenOrganizationJSON uses the same official encrypted export route,
// permission checks, reprompt authorization and borrowed-save lifetime as MyGo.
// Conversion rejects any field the official plaintext importer cannot preserve.
func (s *Session) WithBitwardenOrganizationJSON(ctx context.Context, vault *VaultData, orgID string, grants map[string]*ItemAuthorization, confirmed bool, save func([]byte) error, persist func(SessionCheckpoint) error) error {
	if save == nil {
		return ErrValidation
	}
	return s.WithOrganizationBackup(ctx, vault, orgID, grants, confirmed, func(raw []byte) error {
		plan, err := ParseOrganizationImport(raw)
		if err != nil {
			return err
		}
		defer plan.Clear()
		collections := []map[string]any{}
		for _, c := range plan.file.Collections {
			if !backupUUID(c.ID) {
				return ErrUnsupportedEdit
			}
			collections = append(collections, map[string]any{"id": c.ID, "organizationId": c.OrganizationID, "name": c.Name, "externalId": c.ExternalID})
		}
		for _, item := range plan.file.Items {
			if err := normalizeOfficialOrganizationLogin(item); err != nil {
				return err
			}
			if err := validateOfficialOrganizationItem(item); err != nil {
				return err
			}
			if item["folderId"] != nil || item["archivedDate"] != nil {
				return ErrUnsupportedEdit
			}
		}
		encoded, err := json.MarshalIndent(map[string]any{"encrypted": false, "collections": collections, "items": plan.file.Items}, "", "  ")
		if err != nil {
			return ErrProtocol
		}
		defer clear(encoded)
		checked, err := ParseBitwardenOrganizationJSON(encoded)
		if err != nil {
			return err
		}
		checked.Clear()
		return save(encoded)
	}, persist)
}
