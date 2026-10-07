// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const MyGoResources BackupFormat = "mygo-resources"
const MaxResourceBackupSize int64 = (1 << 30) + MaxBackupSize + (4 << 20)
const resourceBackupSignature = "mygo-vaultwarden-resource-backup"

type BackupResource struct {
	CipherID     string `json:"cipherId"`
	AttachmentID string `json:"attachmentId"`
	FileName     string `json:"fileName"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}
type resourceManifest struct {
	Format           string           `json:"format"`
	Version          int              `json:"version"`
	OrganizationID   string           `json:"organizationId,omitempty"`
	CopyCipherID     string           `json:"copyCipherId,omitempty"`
	CopySourceDigest string           `json:"copySourceDigest,omitempty"`
	Metadata         json.RawMessage  `json:"metadata"`
	Resources        []BackupResource `json:"resources"`
}

type ResourceBackupPublication struct {
	vault    *VaultData
	session  *Session
	revision string
	epoch    uint64
	ids      []string
	expires  time.Time
	used     bool
}

func (s *Session) backupResourceDescriptions(vault *VaultData, ids []string, grants map[string]*ItemAuthorization) ([]BackupResource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if vault == nil {
		return nil, ErrIdentity
	}
	if err := s.requireScopeLocked(vault.Scope); err != nil {
		return nil, err
	}
	policies, err := s.snapshotPoliciesLocked(vault)
	if err != nil {
		return nil, err
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		if !validObjectID(id) || wanted[id] {
			return nil, ErrValidation
		}
		wanted[id] = true
	}
	result := []BackupResource{}
	seenItems := map[string]bool{}
	var org *organizationVault
	defer func() {
		if org != nil {
			org.close()
		}
	}()
	for _, document := range documents {
		var meta struct {
			ID             string
			OrganizationID *string
			Reprompt, Type int
			ViewPassword   *bool
		}
		if json.Unmarshal(document.JSON, &meta) != nil {
			return nil, ErrProtocol
		}
		if !wanted[meta.ID] {
			continue
		}
		if seenItems[meta.ID] {
			return nil, ErrProtocol
		}
		seenItems[meta.ID] = true
		ownerKey := s.key
		if meta.OrganizationID != nil {
			if org == nil {
				org, err = s.organizationVaultLocked(vault)
				if err != nil {
					return nil, err
				}
			}
			document, ownerKey, err = organizationDocumentWithPolicies(meta.ID, org, policies)
		} else if meta.ViewPassword == nil || !*meta.ViewPassword || meta.Reprompt < 0 || meta.Reprompt > 1 || policies.restricts(nil, meta.Type) {
			return nil, ErrPermission
		}
		if err != nil {
			return nil, err
		}
		object, err := documentObject(document)
		if err != nil {
			return nil, err
		}
		key, err := cipherItemKey(object, ownerKey)
		if err != nil {
			return nil, err
		}
		if meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grants[meta.ID], document) {
			clear(key)
			return nil, ErrPermission
		}
		rows := object["attachments"]
		if err = validateMigrationAttachments(rows); err != nil {
			clear(key)
			return nil, err
		}
		list, _ := rows.([]any)
		seen := map[string]bool{}
		for _, raw := range list {
			row := raw.(map[string]any)
			id, ok := row["id"].(string)
			if !ok || !validObjectID(id) || seen[id] {
				clear(key)
				return nil, ErrProtocol
			}
			seen[id] = true
			if err = transformField(row, "fileName", key, false); err != nil {
				clear(key)
				return nil, err
			}
			name, ok := row["fileName"].(string)
			if !ok || name == "" || len(name) > 4096 || strings.ContainsAny(name, "/\\\x00\r\n") {
				clear(key)
				return nil, fmt.Errorf("附件 %s 的文件名无法通过当前上传接口无损恢复，请保留原件并明确处理文件名：%w", id, ErrUnsupportedEdit)
			}
			result = append(result, BackupResource{CipherID: meta.ID, AttachmentID: id, FileName: name, Path: fmt.Sprintf("files/%06d.bin", len(result))})
			if len(result) > 10000 {
				clear(key)
				return nil, ErrValidation
			}
		}
		clear(key)
	}
	if len(seenItems) != len(wanted) {
		return nil, ErrNotFound
	}
	return result, nil
}

// WriteResourceBackup writes a distinct, uncompressed ZIP contract. Metadata
// remains the existing MyGo plaintext schema; binary entries are separate and
// never embedded in the JSON/native bridge. The caller must stage, then publish
// with the returned capability. Partial archives must be discarded.
func (s *Session) WriteResourceBackup(ctx context.Context, vault *VaultData, ids []string, organizationID string, grants map[string]*ItemAuthorization, confirmed bool, writer io.Writer, persist func(SessionCheckpoint) error) (*ResourceBackupPublication, error) {
	if !confirmed || writer == nil {
		return nil, ErrPermission
	}
	var metadata []byte
	var err error
	if organizationID == "" {
		metadata, err = s.exportPersonalBackup(ctx, vault, ids, MyGoBackup, grants, true)
	} else {
		err = s.withOrganizationBackup(ctx, vault, organizationID, grants, true, func(data []byte) error { metadata = bytes.Clone(data); return nil }, persist, true)
		if err == nil {
			plan, e := ParseOrganizationImport(metadata)
			if e != nil {
				clear(metadata)
				return nil, e
			}
			ids = nil
			for _, item := range plan.file.Items {
				ids = append(ids, item["id"].(string))
			}
			plan.Clear()
		}
	}
	if err != nil {
		return nil, err
	}
	defer clear(metadata)
	resources, err := s.backupResourceDescriptions(vault, ids, grants)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	publication := &ResourceBackupPublication{vault: vault, session: s, revision: s.authorizationRevision, epoch: s.authorizationEpoch, ids: append([]string(nil), ids...)}
	s.mu.Unlock()
	manifest := resourceManifest{Format: resourceBackupSignature, Version: 1, OrganizationID: organizationID, Metadata: metadata, Resources: resources}
	return s.writeResourceArchive(ctx, vault, grants, manifest, publication, writer, persist)
}

func (s *Session) writeResourceArchive(ctx context.Context, vault *VaultData, grants map[string]*ItemAuthorization, manifest resourceManifest, publication *ResourceBackupPublication, writer io.Writer, persist func(SessionCheckpoint) error) (*ResourceBackupPublication, error) {
	archive := zip.NewWriter(writer)
	var total int64
	for i := range manifest.Resources {
		resource := &manifest.Resources[i]
		proof, err := s.DownloadAttachmentForBackup(ctx, vault, resource.CipherID, resource.AttachmentID, grants[resource.CipherID], persist, func(file *os.File, size int64) error {
			if size < 0 || size > 512<<20 || total+size > 1<<30 {
				return ErrValidation
			}
			total += size
			header := &zip.FileHeader{Name: resource.Path, Method: zip.Store}
			header.SetMode(0600)
			entry, err := archive.CreateHeader(header)
			if err != nil {
				return err
			}
			hash := sha256.New()
			if err = migrationCopy(ctx, io.MultiWriter(entry, hash), file, size); err != nil {
				return err
			}
			resource.Size, resource.SHA256 = size, hex.EncodeToString(hash.Sum(nil))
			return nil
		})
		if err != nil {
			return nil, err
		}
		// Consume each file's short-lived proof immediately. The archive remains
		// private; one fresh aggregate permission/read check below authorizes its
		// eventual publication without retaining N complete cipher documents.
		if err = s.PublishAttachment(ctx, proof, grants[resource.CipherID], func() error { return nil }); err != nil {
			return nil, err
		}
	}
	encoded, err := json.Marshal(manifest)
	if err != nil || len(encoded) > MaxBackupSize {
		clear(encoded)
		return nil, ErrValidation
	}
	defer clear(encoded)
	header := &zip.FileHeader{Name: "manifest.json", Method: zip.Store}
	header.SetMode(0600)
	entry, err := archive.CreateHeader(header)
	if err != nil {
		return nil, err
	}
	if _, err = entry.Write(encoded); err != nil {
		return nil, err
	}
	if err = archive.Close(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	if err = s.prepareResourcePublication(ctx, publication, grants, persist, len(manifest.Resources) > 0); err != nil {
		return nil, err
	}
	return publication, nil
}

func (s *Session) PublishResourceBackup(ctx context.Context, proof *ResourceBackupPublication, grants map[string]*ItemAuthorization, publish func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if proof == nil || proof.session != s || proof.used || publish == nil {
		return ErrPermission
	}
	proof.used = true
	if proof.revision != s.authorizationRevision || proof.epoch != s.authorizationEpoch || !time.Now().Before(proof.expires) {
		return ErrExpired
	}
	if _, err := s.snapshotPoliciesLocked(proof.vault); err != nil {
		return err
	}
	documents, err := proof.vault.Documents(proof.vault.Scope)
	if err != nil {
		return err
	}
	needed := map[string]bool{}
	for _, id := range proof.ids {
		needed[id] = true
	}
	earliest := proof.expires
	for _, doc := range documents {
		var meta struct {
			ID       string
			Reprompt int
		}
		if json.Unmarshal(doc.JSON, &meta) != nil {
			return ErrProtocol
		}
		if !needed[meta.ID] {
			continue
		}
		delete(needed, meta.ID)
		if meta.Reprompt != 0 {
			grant := grants[meta.ID]
			if !s.validItemAuthorizationLocked(grant, doc) {
				return ErrPermission
			}
			if grant.expires.Before(earliest) {
				earliest = grant.expires
			}
		}
	}
	if len(needed) != 0 {
		return ErrNotFound
	}
	if !time.Now().Before(earliest) {
		return ErrExpired
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.stopping || s.closed || ctx.Err() != nil {
		return ErrCancelled
	}
	return publish()
}

// ResourceImportPlan owns a private immutable spool. Clear after completion or
// cancellation; no caller-provided path is used as an archive extraction path.
type ResourceImportPlan struct {
	file     *os.File
	archive  *zip.Reader
	manifest resourceManifest
	entries  map[string]*zip.File
}

func (p *ResourceImportPlan) Clear() {
	if p == nil {
		return
	}
	if p.file != nil {
		name := p.file.Name()
		p.file.Close()
		os.Remove(name)
		p.file = nil
	}
	clear(p.manifest.Metadata)
	p.manifest = resourceManifest{}
	p.entries = nil
	p.archive = nil
}
func (p *ResourceImportPlan) Resources() []BackupResource {
	if p == nil {
		return nil
	}
	return append([]BackupResource(nil), p.manifest.Resources...)
}
func (p *ResourceImportPlan) OrganizationID() string {
	if p == nil {
		return ""
	}
	return p.manifest.OrganizationID
}
func (p *ResourceImportPlan) PersonalMetadata() (*ImportPlan, error) {
	if p == nil || p.file == nil || p.manifest.OrganizationID != "" {
		return nil, ErrValidation
	}
	return ParseImport(p.manifest.Metadata, MyGoBackup)
}

// PersonalRestoreMetadata defers trash state only for items with files, so the
// new target can receive attachments. The source archive records the final
// state; callers must visibly finalize it after every file is verified.
func (p *ResourceImportPlan) PersonalRestoreMetadata() (*ImportPlan, error) {
	if p == nil || p.file == nil || p.manifest.OrganizationID != "" {
		return nil, ErrValidation
	}
	file, err := decodeBackup(p.manifest.Metadata, MyGoBackup)
	if err != nil {
		return nil, err
	}
	withFiles := map[string]bool{}
	for _, resource := range p.manifest.Resources {
		withFiles[resource.CipherID] = true
	}
	for _, item := range file.Items {
		if withFiles[item["id"].(string)] {
			delete(item, "deletedDate")
		}
	}
	data, err := json.Marshal(file)
	if err != nil {
		return nil, ErrProtocol
	}
	defer clear(data)
	return ParseImport(data, MyGoBackup)
}

func (p *ResourceImportPlan) DeferredTrashIDs() []string {
	if p == nil || p.file == nil || p.manifest.OrganizationID != "" {
		return nil
	}
	file, err := decodeBackup(p.manifest.Metadata, MyGoBackup)
	if err != nil {
		return nil
	}
	withFiles := map[string]bool{}
	for _, resource := range p.manifest.Resources {
		withFiles[resource.CipherID] = true
	}
	ids := []string{}
	for _, item := range file.Items {
		id := item["id"].(string)
		if withFiles[id] && item["deletedDate"] != nil {
			ids = append(ids, id)
		}
	}
	return ids
}

func (p *ResourceImportPlan) OrganizationMetadata() (*OrganizationImportPlan, error) {
	if p == nil || p.file == nil || p.manifest.OrganizationID == "" || p.manifest.CopyCipherID != "" {
		return nil, ErrValidation
	}
	return ParseOrganizationImport(p.manifest.Metadata)
}

func (p *ResourceImportPlan) OrganizationRestoreMetadata() (*OrganizationImportPlan, error) {
	plan, err := p.OrganizationMetadata()
	if err != nil {
		return nil, err
	}
	for _, item := range plan.file.Items {
		delete(item, "deletedDate")
		delete(item, "archivedDate")
		delete(item, "folderId")
	}
	return plan, nil
}

type ResourceItemState struct {
	SourceID          string
	FolderID          *string
	Archived, Deleted bool
}

func (p *ResourceImportPlan) ItemStates() []ResourceItemState {
	if p == nil || p.file == nil {
		return nil
	}
	var items []map[string]any
	if p.manifest.OrganizationID == "" || p.manifest.CopyCipherID != "" {
		file, err := decodeBackup(p.manifest.Metadata, MyGoBackup)
		if err != nil {
			return nil
		}
		items = file.Items
	} else {
		plan, err := ParseOrganizationImport(p.manifest.Metadata)
		if err != nil {
			return nil
		}
		defer plan.Clear()
		items = plan.file.Items
	}
	result := make([]ResourceItemState, 0, len(items))
	for _, item := range items {
		state := ResourceItemState{SourceID: item["id"].(string), Archived: item["archivedDate"] != nil, Deleted: item["deletedDate"] != nil}
		if folder, ok := item["folderId"].(string); ok {
			state.FolderID = &folder
		}
		result = append(result, state)
	}
	return result
}

// ParseResourceImport takes ownership of input and closes it. ZIP compression,
// duplicate paths, undeclared entries, bad hashes and oversized resources fail
// before callers can create any item. All extracted files remain unpublished.
func ParseResourceImport(ctx context.Context, input *os.File) (_ *ResourceImportPlan, err error) {
	if input == nil {
		return nil, ErrValidation
	}
	defer input.Close()
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	stopClosing := context.AfterFunc(ctx, func() { _ = input.Close() })
	defer stopClosing()
	info, err := input.Stat()
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxResourceBackupSize {
		return nil, ErrValidation
	}
	spool, err := os.CreateTemp("", "mygo-resource-import-*")
	if err != nil {
		return nil, err
	}
	plan := &ResourceImportPlan{file: spool}
	defer func() {
		if err != nil {
			plan.Clear()
		}
	}()
	// Archive itself can exceed one binary's 512 MiB bound.
	buffer := make([]byte, 64<<10)
	defer clear(buffer)
	remaining := info.Size()
	for remaining > 0 {
		if ctx.Err() != nil {
			return nil, ErrCancelled
		}
		n := int64(len(buffer))
		if remaining < n {
			n = remaining
		}
		if _, err = io.ReadFull(input, buffer[:n]); err != nil {
			if ctx.Err() != nil {
				return nil, ErrCancelled
			}
			return nil, err
		}
		if _, err = spool.Write(buffer[:n]); err != nil {
			return nil, err
		}
		remaining -= n
	}
	archive, err := zip.NewReader(spool, info.Size())
	if err != nil || len(archive.File) > 10001 {
		return nil, ErrValidation
	}
	plan.archive, plan.entries = archive, map[string]*zip.File{}
	for _, entry := range archive.File {
		if entry.Method != zip.Store || !entry.Mode().IsRegular() || plan.entries[entry.Name] != nil || entry.UncompressedSize64 > uint64(MaxResourceBackupSize) {
			return nil, ErrValidation
		}
		plan.entries[entry.Name] = entry
	}
	manifest := plan.entries["manifest.json"]
	if manifest == nil || manifest.UncompressedSize64 > MaxBackupSize {
		return nil, ErrValidation
	}
	reader, err := manifest.Open()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(reader, MaxBackupSize+1))
	reader.Close()
	defer clear(data)
	if err != nil || strictJSON(data) != nil {
		return nil, ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan.manifest) != nil || plan.manifest.Format != resourceBackupSignature || plan.manifest.Version != 1 || plan.manifest.Resources == nil {
		return nil, ErrValidation
	}
	ids := map[string]bool{}
	if plan.manifest.OrganizationID == "" || plan.manifest.CopyCipherID != "" {
		file, e := decodeBackup(plan.manifest.Metadata, MyGoBackup)
		if e != nil {
			return nil, e
		}
		for _, item := range file.Items {
			ids[item["id"].(string)] = true
		}
	} else {
		metadata, e := ParseOrganizationImport(plan.manifest.Metadata)
		if e != nil {
			return nil, e
		}
		if metadata.file.OrganizationID != plan.manifest.OrganizationID {
			metadata.Clear()
			return nil, ErrIdentity
		}
		for _, item := range metadata.file.Items {
			ids[item["id"].(string)] = true
		}
		metadata.Clear()
	}
	if plan.manifest.CopyCipherID != "" {
		if !validObjectID(plan.manifest.CopyCipherID) || !validObjectID(plan.manifest.OrganizationID) || len(plan.manifest.CopySourceDigest) != 64 || len(ids) != 1 || !ids[plan.manifest.CopyCipherID] {
			return nil, ErrValidation
		}
		if _, e := hex.DecodeString(plan.manifest.CopySourceDigest); e != nil {
			return nil, ErrValidation
		}
	} else if plan.manifest.CopySourceDigest != "" {
		return nil, ErrValidation
	}
	if len(plan.manifest.Resources)+1 != len(plan.entries) {
		return nil, ErrValidation
	}
	var total int64
	pairs := map[string]bool{}
	for i, resource := range plan.manifest.Resources {
		pair := resource.CipherID + "/" + resource.AttachmentID
		if !ids[resource.CipherID] || !validObjectID(resource.AttachmentID) || pairs[pair] || resource.Path != fmt.Sprintf("files/%06d.bin", i) || resource.Size < 0 || resource.Size > 512<<20 || resource.FileName == "" || len(resource.FileName) > 4096 || strings.ContainsAny(resource.FileName, "/\\\x00\r\n") {
			return nil, ErrValidation
		}
		pairs[pair] = true
		total += resource.Size
		if total > 1<<30 {
			return nil, ErrValidation
		}
		entry := plan.entries[resource.Path]
		if entry == nil || entry.UncompressedSize64 != uint64(resource.Size) {
			return nil, ErrValidation
		}
		hash := sha256.New()
		reader, err := entry.Open()
		if err != nil {
			return nil, err
		}
		err = migrationCopy(ctx, hash, reader, resource.Size)
		// Reading EOF is required to validate ZIP's own CRC too.
		if err == nil {
			var extra [1]byte
			n, e := reader.Read(extra[:])
			if n != 0 || e != io.EOF {
				err = ErrProtocol
			}
		}
		reader.Close()
		if err != nil || hex.EncodeToString(hash.Sum(nil)) != resource.SHA256 {
			return nil, ErrEncryption
		}
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return plan, nil
}

// UploadResource restores exactly one declared file to an explicitly selected
// authenticated target. It never repeats a request and returns the server's
// attachment ID even when later confirmation fails. Caller must sync and verify
// every acknowledged file before considering a multi-item restore complete.
func (s *Session) UploadResource(ctx context.Context, vault *VaultData, targetID string, plan *ResourceImportPlan, index int, confirmed bool, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (AttachmentUploadResult, error) {
	if !confirmed || plan == nil || plan.file == nil || index < 0 || index >= len(plan.manifest.Resources) {
		return AttachmentUploadResult{}, ErrValidation
	}
	resource := plan.manifest.Resources[index]
	entry := plan.entries[resource.Path]
	reader, err := entry.Open()
	if err != nil {
		return AttachmentUploadResult{}, err
	}
	defer reader.Close()
	file, err := os.CreateTemp("", "mygo-resource-upload-*")
	if err != nil {
		return AttachmentUploadResult{}, err
	}
	defer func() { file.Close(); os.Remove(file.Name()) }()
	hash := sha256.New()
	if err = migrationCopy(ctx, io.MultiWriter(file, hash), reader, resource.Size); err != nil {
		return AttachmentUploadResult{}, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != resource.SHA256 {
		return AttachmentUploadResult{}, ErrEncryption
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return AttachmentUploadResult{}, err
	}
	return s.UploadAttachment(ctx, vault, targetID, resource.FileName, file, grant, persist)
}

func (s *Session) VerifyRestoredResource(ctx context.Context, vault *VaultData, targetID, attachmentID string, plan *ResourceImportPlan, index int, grant *ItemAuthorization, persist func(SessionCheckpoint) error) error {
	if plan == nil || plan.file == nil || index < 0 || index >= len(plan.manifest.Resources) {
		return ErrValidation
	}
	resource := plan.manifest.Resources[index]
	rows, err := s.backupResourceDescriptions(vault, []string{targetID}, map[string]*ItemAuthorization{targetID: grant})
	if err != nil {
		return err
	}
	matched := false
	for _, row := range rows {
		if row.AttachmentID == attachmentID && row.FileName == resource.FileName {
			matched = true
		}
	}
	if !matched {
		return ErrConflict
	}
	proof, err := s.DownloadAttachmentForBackup(ctx, vault, targetID, attachmentID, grant, persist, func(file *os.File, size int64) error {
		if size != resource.Size {
			return ErrConflict
		}
		hash := sha256.New()
		if err := migrationCopy(ctx, hash, file, size); err != nil {
			return err
		}
		if hex.EncodeToString(hash.Sum(nil)) != resource.SHA256 {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.PublishAttachment(ctx, proof, grant, func() error { return nil })
}
