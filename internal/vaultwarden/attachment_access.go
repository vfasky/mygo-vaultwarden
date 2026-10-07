// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// AttachmentInfo contains authenticated display metadata, never a signed URL or
// attachment key. CiphertextSize is the server's encrypted size, not plaintext.
type AttachmentInfo struct {
	ID             string
	FileName       string
	CiphertextSize int64
}

func attachmentDisplayName(encrypted string, cipherKey []byte) (string, error) {
	plain, err := DecryptString(encrypted, cipherKey)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	if len(plain) == 0 || len(plain) > 4096 || !utf8.Valid(plain) {
		return "", ErrProtocol
	}
	// The name is only a suggestion. Drop all server-provided path components;
	// native Save decides the actual output path independently.
	name := strings.ReplaceAll(string(plain), "\\", "/")
	parts := strings.Split(name, "/")
	name = parts[len(parts)-1]
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	if strings.TrimSpace(name) == "" || name == "." || name == ".." {
		name = "attachment"
	}
	return name, nil
}

func attachmentRecordForID(document CipherDocument, id string) (attachmentRecord, error) {
	if !validObjectID(id) {
		return attachmentRecord{}, ErrValidation
	}
	rows, err := attachmentRecords(document)
	if err != nil {
		return attachmentRecord{}, err
	}
	for _, a := range rows {
		if a.ID == id {
			return a, nil
		}
	}
	return attachmentRecord{}, ErrNotFound
}

func (s *Session) Attachments(ctx context.Context, vault *VaultData, id string, grant *ItemAuthorization, persist func(SessionCheckpoint) error) ([]AttachmentInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	a, err := s.attachmentAuthorityLocked(ctx, vault, id, grant, false, false, persist)
	if err != nil {
		return nil, err
	}
	defer clear(a.ownerKey)
	object, err := documentObject(a.document)
	if err != nil {
		return nil, err
	}
	key, err := cipherItemKey(object, a.ownerKey)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	rows, err := attachmentRecords(a.document)
	if err != nil {
		return nil, err
	}
	result := make([]AttachmentInfo, 0, len(rows))
	for _, row := range rows {
		name, err := attachmentDisplayName(row.FileName, key)
		if err != nil {
			return nil, err
		}
		size, _ := row.size()
		result = append(result, AttachmentInfo{ID: row.ID, FileName: name, CiphertextSize: size})
	}
	if err := a.guard(); err != nil {
		return nil, err
	}
	return result, nil
}

// AttachmentPublication is an in-process, single-use authorization for a file
// that passed complete MAC verification and a final authenticated server sync.
// The UI still checks its own account/snapshot lease immediately before publish.
type AttachmentPublication struct {
	session  *Session
	vault    *VaultData
	expires  time.Time
	document CipherDocument
	revision string
	epoch    uint64
	used     bool
}

// DownloadAttachment stages plaintext through consume only after full MAC
// verification. consume must write an unpublished private file, and must not
// call Session methods. On any error the caller removes its own unpublished
// stage. Neither the file contents nor the signed URL enter a JSON bridge.
func (s *Session) DownloadAttachment(ctx context.Context, vault *VaultData, id, attachmentID string, grant *ItemAuthorization, persist func(SessionCheckpoint) error, consume func(*os.File, int64) error) (*AttachmentPublication, error) {
	if consume == nil || !validObjectID(attachmentID) {
		return nil, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	a, err := s.attachmentAuthorityLocked(ctx, vault, id, grant, false, false, persist)
	if err != nil {
		return nil, err
	}
	defer clear(a.ownerKey)
	record, err := attachmentRecordForID(a.document, attachmentID)
	if err != nil {
		return nil, err
	}
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/ciphers/"+id+"/attachment/"+attachmentID, "", "", persist, a.guard)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, statusError(status)
	}
	var remote attachmentRecord
	if strictJSON(body) != nil || json.Unmarshal(body, &remote) != nil {
		return nil, ErrProtocol
	}
	size, err := remote.size()
	if err != nil {
		return nil, err
	}
	expectedSize, _ := record.size()
	if remote.ID != record.ID || remote.Key != record.Key || remote.FileName != record.FileName || size != expectedSize {
		return nil, ErrConflict
	}
	object, err := documentObject(a.document)
	if err != nil {
		return nil, err
	}
	cipherKey, err := cipherItemKey(object, a.ownerKey)
	if err != nil {
		return nil, err
	}
	defer clear(cipherKey)
	// Official legacy v1 files without an attachment key use the user/org key,
	// including ciphers that later acquired an independent item key.
	key := a.ownerKey
	if record.Key != "" {
		key, err = DecryptString(record.Key, cipherKey)
		if err != nil {
			return nil, err
		}
		defer clear(key)
	}
	if len(key) != 64 {
		return nil, ErrEncryption
	}
	if err := a.guard(); err != nil {
		return nil, err
	}
	plain, err := s.client.downloadAttachment(ctx, remote.URL, size, key)
	if err != nil {
		return nil, err
	}
	defer plain.close()
	if err := a.guard(); err != nil {
		return nil, err
	}
	if err := consume(plain.file, plain.size); err != nil {
		return nil, err
	}
	// Staging may take time. Recheck server policy and exact cipher after staging,
	// then issue a single-use publication capability tied to this local epoch.
	fresh, err := s.attachmentAuthorityLocked(ctx, vault, id, grant, false, false, persist)
	if err != nil {
		return nil, err
	}
	clear(fresh.ownerKey)
	if err := a.guard(); err != nil {
		return nil, err
	}
	if err := fresh.guard(); err != nil {
		return nil, err
	}
	return &AttachmentPublication{session: s, vault: vault, expires: time.Now().Add(30 * time.Second), document: a.document, revision: s.authorizationRevision, epoch: s.authorizationEpoch}, nil
}

// PublishAttachment runs only the short atomic no-replace publication callback.
// Holding operationMu makes publication and Close's revocation linearizable.
// The callback must not call Session methods or perform long file copies.
func (s *Session) PublishAttachment(ctx context.Context, proof *AttachmentPublication, grant *ItemAuthorization, publish func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if proof == nil || proof.session != s || proof.used || publish == nil {
		return ErrPermission
	}
	proof.used = true
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if proof.revision == "" || proof.revision != s.authorizationRevision || proof.epoch != s.authorizationEpoch || !time.Now().Before(proof.expires) {
		return ErrExpired
	}
	if _, err := s.snapshotPoliciesLocked(proof.vault); err != nil {
		return err
	}
	var meta struct{ Reprompt int }
	if json.Unmarshal(proof.document.JSON, &meta) != nil {
		return ErrProtocol
	}
	if meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, proof.document) {
		return ErrPermission
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.stopping || s.closed {
		return ErrExpired
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return publish()
}

// DeleteAttachment performs one explicitly confirmed deletion. The caller must
// run normal Sync/checkpoint before presenting a refreshed attachment list.
func (s *Session) DeleteAttachment(ctx context.Context, vault *VaultData, id, attachmentID string, grant *ItemAuthorization, persist func(SessionCheckpoint) error) error {
	if !validObjectID(attachmentID) {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	a, err := s.attachmentAuthorityLocked(ctx, vault, id, grant, true, false, persist)
	if err != nil {
		return err
	}
	defer clear(a.ownerKey)
	if _, err := attachmentRecordForID(a.document, attachmentID); err != nil {
		return err
	}
	status, _, err := s.authenticatedGuardedLocked(ctx, http.MethodDelete, "/api/ciphers/"+id+"/attachment/"+attachmentID, "", "", persist, a.guard)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return mutationStatusError(status)
	}
	if err := a.guard(); err != nil {
		return &MutationUncertainError{Cause: err}
	}
	return nil
}
