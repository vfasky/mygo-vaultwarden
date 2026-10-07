// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AttachmentUploadResult identifies the server object even when a later phase
// fails. An error with MetadataCreated requires reconciliation, never blind
// retry or automatic deletion. It is not a multi-request transaction.
type AttachmentUploadResult struct {
	AttachmentID    string
	MetadataCreated bool
	Uploaded        bool
	Reconciled      bool
}

type attachmentRecord struct {
	ID       string          `json:"id"`
	FileName string          `json:"fileName"`
	Key      string          `json:"key"`
	Size     json.RawMessage `json:"size"`
	URL      string          `json:"url"`
}

func (a attachmentRecord) size() (int64, error) {
	raw := string(a.Size)
	if strings.HasPrefix(raw, `"`) {
		if json.Unmarshal(a.Size, &raw) != nil {
			return 0, ErrProtocol
		}
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	maxSize, _ := attachmentEncryptedSize(attachmentPlaintextLimit)
	if err != nil || n < attachmentHeaderSize+16 || n > maxSize || (n-attachmentHeaderSize)%16 != 0 {
		return 0, ErrProtocol
	}
	return n, nil
}

func attachmentRecords(document CipherDocument) ([]attachmentRecord, error) {
	if strictJSON(document.JSON) != nil {
		return nil, ErrProtocol
	}
	var data struct{ Attachments []attachmentRecord }
	if json.Unmarshal(document.JSON, &data) != nil {
		return nil, ErrProtocol
	}
	seen := map[string]bool{}
	for _, a := range data.Attachments {
		if !validObjectID(a.ID) || seen[a.ID] || a.FileName == "" {
			return nil, ErrProtocol
		}
		if _, err := a.size(); err != nil {
			return nil, err
		}
		seen[a.ID] = true
	}
	return data.Attachments, nil
}

// Signed URLs change on every sync. All other known and unknown fields remain
// part of the comparison; no float64 conversion may erase opaque large values.
func attachmentComparable(document CipherDocument, ignoreAttachments, ignoreRevision bool) ([]byte, error) {
	if strictJSON(document.JSON) != nil {
		return nil, ErrProtocol
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(document.JSON, &object) != nil || object == nil {
		return nil, ErrProtocol
	}
	if ignoreRevision {
		delete(object, "revisionDate")
	}
	if ignoreAttachments {
		delete(object, "attachments")
	} else if raw := object["attachments"]; len(raw) > 0 && string(raw) != "null" {
		var rows []map[string]json.RawMessage
		if json.Unmarshal(raw, &rows) != nil {
			return nil, ErrProtocol
		}
		for _, row := range rows {
			delete(row, "url")
		}
		object["attachments"], _ = json.Marshal(rows)
	}
	return json.Marshal(object)
}

func attachmentSameDocument(a, b CipherDocument, ignoreAttachments, ignoreRevision bool) bool {
	x, e := attachmentComparable(a, ignoreAttachments, ignoreRevision)
	y, f := attachmentComparable(b, ignoreAttachments, ignoreRevision)
	return e == nil && f == nil && rawJSONEqual(x, y)
}

type attachmentAuthority struct {
	document CipherDocument
	ownerKey []byte
	guard    func() error
}

// The snapshot establishes the local lease/quarantine and decryption key; a
// fresh authenticated sync independently establishes server policy/permissions.
type attachmentPurpose uint8

const (
	attachmentPurposeRead attachmentPurpose = iota
	attachmentPurposeWrite
	attachmentPurposeCreate
	attachmentBackupRead
)

func (s *Session) attachmentAuthorityLocked(ctx context.Context, vault *VaultData, id string, grant *ItemAuthorization, write, create bool, persist func(SessionCheckpoint) error) (*attachmentAuthority, error) {
	purpose := attachmentPurposeRead
	if write {
		purpose = attachmentPurposeWrite
	}
	if create {
		purpose = attachmentPurposeCreate
	}
	return s.attachmentPurposeAuthorityLocked(ctx, vault, id, grant, purpose, persist)
}

func (s *Session) attachmentPurposeAuthorityLocked(ctx context.Context, vault *VaultData, id string, grant *ItemAuthorization, purpose attachmentPurpose, persist func(SessionCheckpoint) error) (*attachmentAuthority, error) {
	if purpose > attachmentBackupRead {
		return nil, ErrValidation
	}
	write, create := purpose == attachmentPurposeWrite || purpose == attachmentPurposeCreate, purpose == attachmentPurposeCreate
	if !validObjectID(id) {
		return nil, ErrValidation
	}
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return nil, err
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return nil, err
	}
	var document CipherDocument
	var ownerKey []byte
	var meta struct {
		ID                 string
		OrganizationID     *string
		Type, Reprompt     int
		Edit, ViewPassword *bool
		DeletedDate        *string
		RevisionDate       string
	}
	for _, candidate := range documents {
		var m struct{ ID string }
		if json.Unmarshal(candidate.JSON, &m) != nil {
			return nil, ErrProtocol
		}
		if m.ID == id {
			if document.JSON != nil {
				return nil, ErrProtocol
			}
			document = candidate
		}
	}
	if document.JSON == nil {
		return nil, ErrNotFound
	}
	if json.Unmarshal(document.JSON, &meta) != nil {
		return nil, ErrProtocol
	}
	var data *organizationVault
	if meta.OrganizationID == nil {
		document, err = s.personalDocumentLocked(vault, id)
		ownerKey = s.key
	} else {
		data, err = s.organizationVaultLocked(vault)
		if err != nil {
			return nil, err
		}
		defer data.close()
		document, ownerKey, err = s.organizationDocumentLocked(vault, id, data)
	}
	if err != nil {
		return nil, err
	}
	if meta.RevisionDate == "" || (meta.DeletedDate != nil && purpose != attachmentBackupRead) || meta.ViewPassword == nil || !*meta.ViewPassword || meta.Edit == nil || (write && !*meta.Edit) {
		return nil, ErrPermission
	}
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	guard := func() error {
		if ctx.Err() != nil {
			return ErrCancelled
		}
		if !s.itemSessionActiveLocked() || revision == "" || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		if meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
			return ErrPermission
		}
		return nil
	}
	if err := guard(); err != nil {
		return nil, err
	}
	// Never reuse an earlier phase's server authority.
	s.writePolicies = nil
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return nil, err
	}
	if err := guard(); err != nil {
		return nil, err
	}
	if policies.restricts(meta.OrganizationID, meta.Type) || (create && meta.OrganizationID == nil && policies.personalOwnership) {
		return nil, ErrPermission
	}
	if meta.OrganizationID != nil {
		member, exists := policies.memberships[*meta.OrganizationID]
		if !exists || *member.Status != 2 || !*member.Enabled {
			return nil, ErrPermission
		}
		matched := false
		for _, local := range data.organizations {
			if local.ID == *meta.OrganizationID && local.OrganizationUserID == member.MemberID && local.UserID == member.UserID && local.Type == *member.Type {
				matched = true
			}
		}
		if !matched {
			return nil, ErrExpired
		}
	}
	found := false
	for _, raw := range policies.ciphers {
		var m struct{ ID string }
		if json.Unmarshal(raw, &m) != nil {
			return nil, ErrProtocol
		}
		if m.ID != id {
			continue
		}
		if found {
			return nil, ErrProtocol
		}
		found = true
		if !attachmentSameDocument(document, CipherDocument{JSON: raw}, false, false) {
			return nil, ErrConflict
		}
	}
	if !found {
		return nil, ErrConflict
	}
	return &attachmentAuthority{document: document, ownerKey: bytes.Clone(ownerKey), guard: func() error {
		if err := s.checkOperationPoliciesLocked(ctx, policies); err != nil {
			return err
		}
		return guard()
	}}, nil
}

func validateAttachmentUploadReceipt(body []byte, original CipherDocument, filename, wrappedKey string, size int64) (string, CipherDocument, error) {
	if strictJSON(body) != nil {
		return "", CipherDocument{}, ErrProtocol
	}
	var response struct {
		AttachmentID       string
		URL                string
		FileUploadType     *int
		CipherResponse     json.RawMessage
		CipherMiniResponse json.RawMessage
	}
	if json.Unmarshal(body, &response) != nil || !validObjectID(response.AttachmentID) {
		return "", CipherDocument{}, ErrProtocol
	}
	id := response.AttachmentID
	var originalMeta struct {
		ID             string
		OrganizationID *string
		RevisionDate   string
	}
	if json.Unmarshal(original.JSON, &originalMeta) != nil {
		return id, CipherDocument{}, ErrProtocol
	}
	if response.FileUploadType == nil || *response.FileUploadType != 0 || response.URL != "/ciphers/"+originalMeta.ID+"/attachment/"+id {
		return id, CipherDocument{}, ErrProtocol
	}
	bodyCipher := response.CipherResponse
	if len(bodyCipher) == 0 || string(bodyCipher) == "null" {
		bodyCipher = response.CipherMiniResponse
	} else if len(response.CipherMiniResponse) > 0 && string(response.CipherMiniResponse) != "null" {
		return id, CipherDocument{}, ErrProtocol
	}
	result := CipherDocument{JSON: bodyCipher}
	var metadata struct {
		ID             string
		OrganizationID *string
		RevisionDate   string
	}
	if json.Unmarshal(result.JSON, &metadata) != nil || metadata.ID != originalMeta.ID || !sameOptional(metadata.OrganizationID, originalMeta.OrganizationID) || metadata.RevisionDate == "" {
		return id, CipherDocument{}, ErrIdentity
	}
	// Metadata creation in fixed 1.37.4 does not update the cipher revision.
	if metadata.RevisionDate != originalMeta.RevisionDate || !attachmentSameDocument(original, result, true, false) {
		return id, CipherDocument{}, ErrConflict
	}
	prior, err := attachmentRecords(original)
	if err != nil {
		return id, CipherDocument{}, err
	}
	current, err := attachmentRecords(result)
	if err != nil || len(current) != len(prior)+1 {
		return id, CipherDocument{}, ErrProtocol
	}
	remaining := map[string]attachmentRecord{}
	for _, a := range prior {
		remaining[a.ID] = a
	}
	found := false
	for _, a := range current {
		if a.ID == id {
			n, _ := a.size()
			if found || a.FileName != filename || a.Key != wrappedKey || n != size {
				return id, CipherDocument{}, ErrProtocol
			}
			if _, exists := remaining[id]; exists {
				return id, CipherDocument{}, ErrIdentity
			}
			found = true
		} else {
			old, exists := remaining[a.ID]
			n, _ := a.size()
			oldN, _ := old.size()
			if !exists || a.FileName != old.FileName || a.Key != old.Key || n != oldN {
				return id, CipherDocument{}, ErrConflict
			}
			delete(remaining, a.ID)
		}
	}
	if !found || len(remaining) != 0 {
		return id, CipherDocument{}, ErrProtocol
	}
	return id, result, nil
}

// UploadAttachment consumes and closes a caller-owned, securely opened regular
// file. Native callers must pin the selected path with no-follow open; paths and
// file bytes never travel through the JSON bridge. A final normal Sync/checkpoint
// is still required to publish new local vault content.
func (s *Session) UploadAttachment(ctx context.Context, vault *VaultData, id, filename string, file *os.File, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (AttachmentUploadResult, error) {
	var result AttachmentUploadResult
	if file == nil {
		return result, ErrValidation
	}
	defer file.Close()
	if filename == "" || len(filename) > 4096 || !utf8.ValidString(filename) || strings.ContainsAny(filename, "/\\\x00\r\n") {
		return result, ErrValidation
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > attachmentPlaintextLimit {
		return result, ErrValidation
	}
	if offset, err := file.Seek(0, 0); err != nil || offset != 0 {
		return result, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	stop := context.AfterFunc(ctx, func() { _ = file.Close() })
	defer stop()
	authority, err := s.attachmentAuthorityLocked(ctx, vault, id, grant, true, true, persist)
	if err != nil {
		return result, err
	}
	defer clear(authority.ownerKey)
	object, err := documentObject(authority.document)
	if err != nil {
		return result, err
	}
	cipherKey, err := cipherItemKey(object, authority.ownerKey)
	if err != nil {
		return result, err
	}
	defer clear(cipherKey)
	key := make([]byte, 64)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return result, ErrEncryption
	}
	encrypted, err := encryptAttachment(ctx, file, info.Size(), key)
	if err != nil {
		return result, err
	}
	defer encrypted.close()
	after, err := file.Stat()
	if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return result, ErrConflict
	}
	encryptedName, err := EncryptString([]byte(filename), cipherKey)
	if err != nil {
		return result, err
	}
	wrappedKey, err := EncryptString(key, cipherKey)
	if err != nil {
		return result, err
	}
	// File encryption can take minutes. Re-read server authority after it, before
	// creating metadata, while retaining the original local capability boundary.
	fresh, err := s.attachmentAuthorityLocked(ctx, vault, id, grant, true, true, persist)
	if err != nil {
		return result, err
	}
	clear(fresh.ownerKey)
	if err := authority.guard(); err != nil {
		return result, err
	}
	authority.guard = fresh.guard
	body, _ := json.Marshal(map[string]any{"fileName": encryptedName, "key": wrappedKey, "fileSize": encrypted.size, "adminRequest": false})
	status, response, err := s.authenticatedGuardedLocked(ctx, http.MethodPost, "/api/ciphers/"+id+"/attachment/v2", "application/json", string(body), persist, authority.guard)
	if err != nil {
		return result, err
	}
	if status != http.StatusOK {
		return result, mutationStatusError(status)
	}
	result.MetadataCreated = true
	attachmentID, receipt, err := validateAttachmentUploadReceipt(response, authority.document, encryptedName, wrappedKey, encrypted.size)
	result.AttachmentID = attachmentID
	if err != nil {
		return result, &MutationUncertainError{Cause: err}
	}
	// The local document remains the reprompt capability target. Only the exact
	// acknowledged attachment is permitted to differ during subsequent syncs.
	reconcile := func(final bool) error {
		s.writePolicies = nil
		policies, err := s.operationPoliciesLocked(ctx, persist)
		if err != nil {
			return err
		}
		// Check the original local lease/grant independently of the new policy object.
		if !s.itemSessionActiveLocked() || policies.revision != s.authorizationRevision {
			return ErrExpired
		}
		var meta struct {
			OrganizationID *string
			Type           int
		}
		_ = json.Unmarshal(authority.document.JSON, &meta)
		if policies.restricts(meta.OrganizationID, meta.Type) || (meta.OrganizationID == nil && policies.personalOwnership) {
			return ErrPermission
		}
		if meta.OrganizationID != nil {
			member, ok := policies.memberships[*meta.OrganizationID]
			if !ok || *member.Status != 2 || !*member.Enabled {
				return ErrPermission
			}
			// A role/member change can leave cipher flags temporarily identical.
			// Compare authenticated membership independently of those flags.
			local, e := s.organizationVaultLocked(vault)
			if e != nil {
				return e
			}
			matched := false
			for _, org := range local.organizations {
				if org.ID == *meta.OrganizationID && org.OrganizationUserID == member.MemberID && org.UserID == member.UserID && org.Type == *member.Type {
					matched = true
				}
			}
			local.close()
			if !matched {
				return ErrExpired
			}
		}
		found := false
		for _, raw := range policies.ciphers {
			var m struct{ ID string }
			if json.Unmarshal(raw, &m) != nil {
				return ErrProtocol
			}
			if m.ID != id {
				continue
			}
			if found || !attachmentSameDocument(receipt, CipherDocument{JSON: raw}, false, final) {
				return ErrConflict
			}
			found = true
		}
		if !found {
			return ErrConflict
		}
		// The earlier guard binds epoch/revision/reprompt. A refresh may invalidate it.
		return authority.guard()
	}
	if err := reconcile(false); err != nil {
		return result, &MutationUncertainError{Cause: err}
	}
	if err := s.prepareAuthenticatedDispatchLocked(ctx, true, persist, authority.guard); err != nil {
		return result, &MutationUncertainError{Cause: err}
	}
	status, err = s.client.uploadAttachment(ctx, id, attachmentID, s.access, encrypted)
	if err != nil {
		return result, &MutationUncertainError{Cause: err}
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return result, &MutationUncertainError{Cause: mutationStatusError(status)}
	}
	result.Uploaded = true
	if err := reconcile(true); err != nil {
		return result, &MutationUncertainError{Cause: err}
	}
	result.Reconciled = true
	return result, nil
}
