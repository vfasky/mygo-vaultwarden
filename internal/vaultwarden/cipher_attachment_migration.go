// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// CipherAttachmentMigrationInfo is authenticated metadata for explicit pairing.
// ID is displayed because filenames are not unique and cannot identify a file.
type CipherAttachmentMigrationInfo struct {
	ID, FileName string
	Legacy       bool
}

// CipherAttachmentMigrationResult records only acknowledged phases. Any error
// after upload/deletion dispatch requires a fresh sync, never an automatic retry.
// OriginalDeleted denotes the DELETE acknowledgement; the caller must still sync.
type CipherAttachmentMigrationResult struct {
	CipherID, OriginalID, ReplacementID               string
	MetadataCreated, Uploaded, Reconciled             bool
	ContentVerified, DeleteAttempted, OriginalDeleted bool
}

func (s *Session) CipherAttachmentMigrationInfo(vault *VaultData, id string, grant *ItemAuthorization) ([]CipherAttachmentMigrationInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.personalDocumentLocked(vault, id)
	if err != nil {
		return nil, err
	}
	if !s.validItemAuthorizationLocked(grant, doc) {
		var meta struct{ Reprompt int }
		if json.Unmarshal(doc.JSON, &meta) != nil {
			return nil, ErrProtocol
		}
		if meta.Reprompt != 0 {
			return nil, ErrPermission
		}
	}
	object, err := documentObject(doc)
	if err != nil {
		return nil, err
	}
	attachments := object["attachments"]
	delete(object, "attachments")
	if err = validateCopyObject(object); err != nil {
		return nil, err
	}
	key, err := cipherItemKey(object, s.key)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	// Preflight every known field before any migration write, including passkeys.
	if err = transformCompleteCipher(object, key, false); err != nil {
		return nil, err
	}
	if err = validateMigrationAttachments(attachments); err != nil {
		return nil, err
	}
	rows, _ := attachments.([]any)
	result := make([]CipherAttachmentMigrationInfo, 0, len(rows))
	seen := map[string]bool{}
	for _, raw := range rows {
		row := raw.(map[string]any)
		attachmentID, ok := row["id"].(string)
		if !ok || !validObjectID(attachmentID) || seen[attachmentID] {
			return nil, ErrProtocol
		}
		seen[attachmentID] = true
		if err = transformField(row, "fileName", key, false); err != nil {
			return nil, err
		}
		name, ok := row["fileName"].(string)
		if !ok || name == "" || len(name) > 4096 || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\\x00\r\n") {
			return nil, fmt.Errorf("附件 %s 的文件名包含当前上传接口不支持的路径、控制字符或长度，无法无损迁移：%w", attachmentID, ErrUnsupportedEdit)
		}
		wrapped, _ := row["key"].(string)
		if row["key"] != nil && row["key"] != "" && wrapped == "" {
			return nil, ErrProtocol
		}
		if wrapped != "" {
			attachmentKey, err := vaultcrypto.DecryptString(wrapped, key)
			if err != nil {
				return nil, err
			}
			valid := len(attachmentKey) == 64
			clear(attachmentKey)
			if !valid {
				return nil, ErrEncryption
			}
		}
		result = append(result, CipherAttachmentMigrationInfo{ID: attachmentID, FileName: name, Legacy: wrapped == ""})
	}
	return result, nil
}

func migrationCopy(ctx context.Context, target io.Writer, source io.Reader, size int64) error {
	if size < 0 || size > 512<<20 {
		return ErrValidation
	}
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	remaining := size
	for remaining > 0 {
		if ctx.Err() != nil {
			return ErrCancelled
		}
		n := int64(len(buffer))
		if remaining < n {
			n = remaining
		}
		read, err := io.ReadFull(source, buffer[:n])
		if err != nil {
			return err
		}
		written, err := target.Write(buffer[:read])
		if err != nil {
			return err
		}
		if written != read {
			return io.ErrShortWrite
		}
		remaining -= int64(read)
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}

// UpgradeLegacyCipherAttachment creates a keyed replacement while leaving the
// original intact. Sync and explicit VerifyAndDeleteLegacyCipherAttachment are
// separate user actions. No step changes ownership or deletes the sole copy.
func (s *Session) UpgradeLegacyCipherAttachment(ctx context.Context, vault *VaultData, cipherID, oldID string, confirmed bool, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherAttachmentMigrationResult, error) {
	result := CipherAttachmentMigrationResult{CipherID: cipherID, OriginalID: oldID}
	if !confirmed {
		return result, ErrPermission
	}
	rows, err := s.CipherAttachmentMigrationInfo(vault, cipherID, grant)
	if err != nil {
		return result, err
	}
	name := ""
	for _, row := range rows {
		if row.ID == oldID && row.Legacy {
			name = row.FileName
		}
	}
	if name == "" {
		return result, ErrValidation
	}
	var spool *os.File
	defer func() {
		if spool != nil {
			spool.Close()
			os.Remove(spool.Name())
		}
	}()
	proof, err := s.DownloadAttachment(ctx, vault, cipherID, oldID, grant, persist, func(file *os.File, size int64) error {
		var err error
		spool, err = os.CreateTemp("", "mygo-legacy-upgrade-*")
		if err != nil {
			return err
		}
		if err = migrationCopy(ctx, spool, file, size); err != nil {
			return err
		}
		_, err = spool.Seek(0, io.SeekStart)
		return err
	})
	if err != nil {
		return result, err
	}
	if err = s.PublishAttachment(ctx, proof, grant, func() error { return nil }); err != nil {
		return result, err
	}
	upload, err := s.UploadAttachment(ctx, vault, cipherID, name, spool, grant, persist)
	result.ReplacementID, result.MetadataCreated, result.Uploaded, result.Reconciled = upload.AttachmentID, upload.MetadataCreated, upload.Uploaded, upload.Reconciled
	return result, err
}

// VerifyAndDeleteLegacyCipherAttachment is deliberately separate from upload:
// after fresh sync and authorization it downloads BOTH server objects, checks
// full MAC through the public API and compares length/SHA256 before one DELETE.
// A restart loses no required recovery material: the original and replacement
// remain on the server until this explicitly confirmed operation.
func (s *Session) VerifyAndDeleteLegacyCipherAttachment(ctx context.Context, vault *VaultData, cipherID, oldID, newID string, confirmed bool, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherAttachmentMigrationResult, error) {
	result := CipherAttachmentMigrationResult{CipherID: cipherID, OriginalID: oldID, ReplacementID: newID}
	if !confirmed || oldID == newID {
		return result, ErrValidation
	}
	rows, err := s.CipherAttachmentMigrationInfo(vault, cipherID, grant)
	if err != nil {
		return result, err
	}
	var old, replacement *CipherAttachmentMigrationInfo
	for i := range rows {
		if rows[i].ID == oldID {
			old = &rows[i]
		}
		if rows[i].ID == newID {
			replacement = &rows[i]
		}
	}
	if old == nil || replacement == nil || !old.Legacy || replacement.Legacy || old.FileName != replacement.FileName {
		return result, ErrValidation
	}
	var sizes [2]int64
	var sums [2][]byte
	for i, id := range []string{oldID, newID} {
		proof, err := s.DownloadAttachment(ctx, vault, cipherID, id, grant, persist, func(file *os.File, size int64) error {
			hash := sha256.New()
			if err := migrationCopy(ctx, hash, file, size); err != nil {
				return err
			}
			sizes[i], sums[i] = size, hash.Sum(nil)
			return nil
		})
		if err != nil {
			return result, err
		}
		if err = s.PublishAttachment(ctx, proof, grant, func() error { return nil }); err != nil {
			return result, err
		}
	}
	if sizes[0] != sizes[1] || !bytes.Equal(sums[0], sums[1]) {
		return result, ErrConflict
	}
	// DeleteAttachment independently obtains fresh server authority for the
	// exact cipher/attachment metadata before dispatch. Old file capabilities
	// are consumed promptly, never extended while a second large file downloads.
	result.ContentVerified = true
	result.DeleteAttempted = true
	err = s.DeleteAttachment(ctx, vault, cipherID, oldID, grant, persist)
	result.OriginalDeleted = err == nil
	return result, err
}
