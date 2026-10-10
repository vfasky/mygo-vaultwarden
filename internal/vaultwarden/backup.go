// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// BackupFormat identifies two deliberately distinct plaintext file contracts.
type BackupFormat string

const (
	BitwardenJSON BackupFormat = "bitwarden"
	MyGoBackup    BackupFormat = "mygo"
	MaxBackupSize              = 32 << 20
)
const backupSignature = "mygo-vaultwarden-personal-backup"

type backupFile struct {
	Format    string           `json:"format,omitempty"`
	Version   int              `json:"version,omitempty"`
	Encrypted bool             `json:"encrypted"`
	Folders   []Folder         `json:"folders"`
	Items     []map[string]any `json:"items"`
}

// ImportPlan is preflighted plaintext; never persist it in preferences or logs.
// Its private serialized representation prevents callers changing the approved
// preview between validation and import. Clear it on cancel, lock and completion.
type ImportPreview struct {
	Name              string
	Type              int
	Archived, Deleted bool
}

type ImportPlan struct {
	data                              []byte
	preview                           []ImportPreview
	Format                            BackupFormat
	Folders, Items, Archived, Deleted int
}

func (p *ImportPlan) Clear() {
	if p != nil {
		clear(p.data)
		p.data = nil
		clear(p.preview)
		p.preview = nil
	}
}
func (p *ImportPlan) PreviewItems() []ImportPreview {
	if p == nil {
		return nil
	}
	return append([]ImportPreview(nil), p.preview...)
}

// BackupConversionError retains a stable cause independently of UI language.
type BackupConversionError struct {
	Index  int
	Reason string
	Cause  error
}

func (e *BackupConversionError) Error() string {
	return fmt.Sprintf(i18n.T("第 %d 个项目无法无损转换：%s"), e.Index+1, e.Reason)
}
func (e *BackupConversionError) Unwrap() error { return e.Cause }

func backupError(index int, reason string) error {
	return &BackupConversionError{Index: index, Reason: reason, Cause: ErrUnsupportedEdit}
}

type backupUnsupportedError struct{ reason string }

func (e backupUnsupportedError) Error() string { return i18n.T(e.reason) }
func (e backupUnsupportedError) Unwrap() error { return ErrUnsupportedEdit }

// strictJSON rejects duplicate keys as well as trailing documents. Importing a
// file must not present one interpretation for preview and another for writes.
func strictJSON(data []byte) error {
	if len(data) == 0 || len(data) > MaxBackupSize || !utf8.Valid(data) {
		return ErrValidation
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return ErrValidation
		}
		token, err := d.Token()
		if err != nil {
			return ErrProtocol
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, err = d.Token()
				key, ok := token.(string)
				if err != nil || !ok || seen[key] {
					return ErrProtocol
				}
				seen[key] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrProtocol
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrProtocol
	}
	return nil
}

func decodeBackup(data []byte, format BackupFormat) (backupFile, error) {
	var file backupFile
	if err := strictJSON(data); err != nil {
		return file, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(&file) != nil || file.Encrypted || file.Items == nil || file.Folders == nil || len(file.Items) > 10000 || len(file.Folders) > 10000 {
		return file, ErrValidation
	}
	if format == BitwardenJSON {
		if file.Format != "" || file.Version != 0 {
			return file, ErrUnsupportedEdit
		}
	} else if format != MyGoBackup || file.Format != backupSignature || file.Version != 1 {
		return file, ErrUnsupportedEdit
	}
	folders := map[string]bool{}
	for _, f := range file.Folders {
		if !validObjectID(f.ID) || folders[f.ID] || strings.TrimSpace(f.Name) == "" || len(f.Name) > 4096 {
			return file, ErrValidation
		}
		if format == BitwardenJSON && !backupUUID(f.ID) {
			return file, ErrValidation
		}
		folders[f.ID] = true
	}
	seen := map[string]bool{}
	for i, item := range file.Items {
		if err := validateBackupItem(item, format); err != nil {
			return file, &BackupConversionError{Index: i, Reason: err.Error(), Cause: err}
		}
		id, ok := item["id"].(string)
		if !ok || !validObjectID(id) || seen[id] {
			return file, backupError(i, i18n.T("项目标识缺失或重复"))
		}
		if format == BitwardenJSON && !backupUUID(id) {
			return file, backupError(i, i18n.T("Bitwarden 格式要求 UUID 项目标识"))
		}
		seen[id] = true
		if folder := item["folderId"]; folder != nil {
			id, ok := folder.(string)
			if !ok || !folders[id] {
				return file, backupError(i, i18n.T("文件夹引用不存在"))
			}
		}
	}
	return file, nil
}

func validateBackupItem(item map[string]any, format BackupFormat) error {
	if _, err := backupItemIdentity(item); err != nil {
		return err
	}
	if err := copyKeys(item, "id", "type", "name", "notes", "folderId", "organizationId", "collectionIds", "favorite", "reprompt", "fields", "passwordHistory", "creationDate", "revisionDate", "deletedDate", "archivedDate", "login", "secureNote", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport"); err != nil {
		return err
	}
	// Reuse the complete known-field audit, without allowing encrypted keys or
	// opaque extensions into a plaintext file. This does not mutate the input.
	object := map[string]any{}
	for k, v := range item {
		object[k] = v
	}
	object["edit"], object["viewPassword"] = true, true
	if err := validateCopyObject(object); err != nil {
		return err
	}
	fields, err := decodeCipherFields(item)
	if err != nil {
		return err
	}
	if fields.Reprompt < 0 || fields.Reprompt > 1 {
		return ErrValidation
	}
	if fields.Type == 5 {
		for _, name := range cipherSecrets["sshKey"] {
			if text, ok := fields.SSHKey[name].(string); !ok || text == "" {
				return ErrValidation
			}
		}
	}
	if fields.Type == 2 {
		if n, ok := fields.SecureNote["type"].(json.Number); !ok || n != "0" {
			return ErrUnsupportedEdit
		}
	}
	for _, field := range fields.Fields {
		n, ok := field["type"].(json.Number)
		if !ok {
			return ErrValidation
		}
		kind, err := n.Int64()
		if err != nil || kind < 0 || kind > 3 {
			return ErrUnsupportedEdit
		}
		if linked := field["linkedId"]; linked != nil {
			if _, ok := linked.(json.Number); !ok {
				return ErrValidation
			}
		}
	}
	for _, entry := range fields.PasswordHistory {
		date, ok := entry["lastUsedDate"].(string)
		if !ok {
			return ErrValidation
		}
		if _, err := time.Parse(time.RFC3339Nano, date); err != nil {
			return ErrValidation
		}
	}
	if fields.Login != nil {
		if raw := fields.Login["autofillOnPageLoad"]; raw != nil {
			if _, ok := raw.(bool); !ok {
				return ErrValidation
			}
		}
		if raw := fields.Login["passwordRevisionDate"]; raw != nil {
			date, ok := raw.(string)
			if !ok {
				return ErrValidation
			}
			if _, err := time.Parse(time.RFC3339Nano, date); err != nil {
				return ErrValidation
			}
		}
		uris, err := backupObjectRows(fields.Login["uris"])
		if err != nil {
			return err
		}
		for _, uri := range uris {
			if match := uri["match"]; match != nil {
				n, ok := match.(json.Number)
				if !ok {
					return ErrValidation
				}
				strategy, err := n.Int64()
				if err != nil || strategy < 0 || strategy > 5 {
					return ErrUnsupportedEdit
				}
			}
		}
	}
	if _, ok := item["favorite"].(bool); !ok {
		return ErrValidation
	}
	for _, name := range []string{"creationDate", "revisionDate", "deletedDate", "archivedDate"} {
		if v := item[name]; v != nil {
			str, ok := v.(string)
			if !ok {
				return ErrValidation
			}
			if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
				return ErrValidation
			}
		}
	}
	// Validate types and crypto-transformability before the first remote write.
	key := make([]byte, 64)
	data, _ := json.Marshal(item)
	defer clear(data)
	copy, err := documentObject(CipherDocument{JSON: data})
	if err != nil {
		return err
	}
	if err = transformCompleteCipher(copy, key, true); err != nil {
		return err
	}
	if format == BitwardenJSON {
		if strings.TrimSpace(fields.Name) == "" || (fields.Notes != nil && strings.TrimSpace(*fields.Notes) == "") {
			return backupUnsupportedError{reason: "Bitwarden 会改写空白名称或备注，请使用 MyGo 备份"}
		}
		for _, entry := range fields.PasswordHistory {
			text, ok := entry["lastUsedDate"].(string)
			if !ok {
				return ErrProtocol
			}
			date, err := time.Parse(time.RFC3339Nano, text)
			if err != nil {
				return ErrProtocol
			}
			if date.Nanosecond()%1000000 != 0 {
				return backupUnsupportedError{reason: "Bitwarden 无法保留亚毫秒密码历史时间，请使用 MyGo 备份"}
			}
		}
		if fields.Type == 8 {
			return backupUnsupportedError{reason: "此版本 Bitwarden 格式不支持护照，请改用 MyGo 备份"}
		}
		if len(fields.PasswordHistory) > 5 {
			return backupUnsupportedError{reason: "Bitwarden 导入器只保留五条密码历史，请改用 MyGo 备份"}
		}
		if fields.DeletedDate != nil {
			return backupUnsupportedError{reason: "回收站项目请使用 MyGo 备份"}
		}
		if fields.Login != nil {
			if !emptyCopyArray(fields.Login["fido2Credentials"]) {
				return backupUnsupportedError{reason: "完整通行密钥请使用 MyGo 备份；官方 JSON 适配尚未验证"}
			}
			if err := copyKeys(fields.Login, "username", "password", "totp", "uris", "fido2Credentials"); err != nil {
				return err
			}
			uris, err := backupObjectRows(fields.Login["uris"])
			if err != nil {
				return err
			}
			for _, uri := range uris {
				if err := copyKeys(uri, "uri", "match"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func backupUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
		} else if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func ParseImport(data []byte, format BackupFormat) (*ImportPlan, error) {
	file, err := decodeBackup(data, format)
	if err != nil {
		return nil, err
	}
	plan := &ImportPlan{data: append([]byte(nil), data...), Format: format, Folders: len(file.Folders), Items: len(file.Items)}
	for _, item := range file.Items {
		identity, err := backupItemIdentity(item)
		if err != nil {
			plan.Clear()
			return nil, err
		}
		plan.preview = append(plan.preview, ImportPreview{Name: identity.Name, Type: identity.Type, Archived: item["archivedDate"] != nil, Deleted: item["deletedDate"] != nil})
		if item["archivedDate"] != nil {
			plan.Archived++
		}
		if item["deletedDate"] != nil {
			plan.Deleted++
		}
	}
	return plan, nil
}

// ExportPersonalBackup converts only the explicitly selected IDs. An unrelated
// unsupported item elsewhere in the vault does not block a compatible subset.
func (s *Session) ExportPersonalBackup(ctx context.Context, vault *VaultData, ids []string, format BackupFormat) ([]byte, error) {
	return s.ExportPersonalBackupAuthorized(ctx, vault, ids, format, nil)
}

// ExportPersonalBackupAuthorized requires a separate current authorization for
// each protected item. A grant for one item never authorizes the rest of a batch.
func (s *Session) ExportPersonalBackupAuthorized(ctx context.Context, vault *VaultData, ids []string, format BackupFormat, grants map[string]*ItemAuthorization) ([]byte, error) {
	return s.exportPersonalBackup(ctx, vault, ids, format, grants, false)
}

func (s *Session) exportPersonalBackup(ctx context.Context, vault *VaultData, ids []string, format BackupFormat, grants map[string]*ItemAuthorization, resources bool) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if vault == nil {
		return nil, ErrIdentity
	}
	if err = s.requireScopeLocked(vault.Scope); err != nil {
		return nil, err
	}
	if format != BitwardenJSON && format != MyGoBackup {
		return nil, ErrValidation
	}
	policies, err := s.snapshotPoliciesLocked(vault)
	if err != nil {
		return nil, err
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, id := range ids {
		if !validObjectID(id) || selected[id] {
			return nil, ErrValidation
		}
		selected[id] = true
	}
	file := backupFile{Folders: []Folder{}, Items: []map[string]any{}}
	if format == MyGoBackup {
		file.Format = backupSignature
		file.Version = 1
	}
	needed := map[string]bool{}
	for _, doc := range documents {
		if ctx.Err() != nil {
			return nil, ErrCancelled
		}
		object, err := documentObject(doc)
		if err != nil {
			return nil, err
		}
		id, _ := object["id"].(string)
		if !selected[id] {
			continue
		}
		delete(selected, id)
		var metadata struct {
			Type, Reprompt int
			OrganizationID *string
			ViewPassword   *bool
		}
		if json.Unmarshal(doc.JSON, &metadata) != nil {
			return nil, ErrProtocol
		}
		if metadata.OrganizationID != nil || (metadata.Reprompt != 0 && !s.validItemAuthorizationLocked(grants[id], doc)) || metadata.ViewPassword == nil || !*metadata.ViewPassword || policies.restricts(nil, metadata.Type) {
			return nil, ErrPermission
		}
		if resources {
			delete(object, "attachments")
		}
		if err = validateCopyObject(object); err != nil {
			return nil, backupError(len(file.Items), i18n.T("包含尚不支持的附件、通行密钥、扩展或权限"))
		}
		fields, err := DecryptCipherDocument(doc, s.key)
		if err != nil {
			return nil, err
		}
		key, err := cipherItemKey(object, s.key)
		if err != nil {
			return nil, err
		}
		err = transformCompleteCipher(object, key, false)
		clear(key)
		if err != nil {
			return nil, err
		}
		for _, name := range []string{"object", "key", "edit", "viewPassword", "permissions", "organizationUseTotp", "encryptedFor", "encryptedByKeyId", "lastKnownRevisionDate", "attachments"} {
			delete(object, name)
		}
		if login, ok := object["login"].(map[string]any); ok && format == BitwardenJSON {
			// The legacy alias is derived from uris, and checksums are regenerated on
			// import. The official plaintext schema has neither field.
			uris, err := backupObjectRows(login["uris"])
			if err != nil {
				return nil, err
			}
			if alias := login["uri"]; alias != nil {
				text, ok := alias.(string)
				if !ok {
					return nil, ErrProtocol
				}
				if len(uris) == 0 || uris[0]["uri"] != text {
					return nil, backupError(len(file.Items), i18n.T("旧网址与网址列表不同，请使用 MyGo 备份"))
				}
			}
			delete(login, "uri")
			if login["autofillOnPageLoad"] != nil || login["passwordRevisionDate"] != nil {
				return nil, backupError(len(file.Items), i18n.T("登录自动填充设置或密码修订时间需 MyGo 备份"))
			}
			delete(login, "autofillOnPageLoad")
			delete(login, "passwordRevisionDate")
			for _, uri := range uris {
				if checksum := uri["uriChecksum"]; checksum != nil {
					text, ok := uri["uri"].(string)
					hash := sha256.Sum256([]byte(text))
					if !ok || checksum != base64.StdEncoding.EncodeToString(hash[:]) {
						return nil, backupError(len(file.Items), i18n.T("网址校验值无法重建，请使用 MyGo 备份"))
					}
				}
				delete(uri, "uriChecksum")
			}
		}
		if err = validateBackupItem(object, format); err != nil {
			return nil, &BackupConversionError{Index: len(file.Items), Reason: err.Error(), Cause: err}
		}
		if fields.FolderID != nil {
			needed[*fields.FolderID] = true
		}
		file.Items = append(file.Items, object)
	}
	if len(selected) != 0 {
		return nil, ErrNotFound
	}
	var folders struct {
		Folders []Folder `json:"folders"`
	}
	if json.Unmarshal(vault.Sync, &folders) != nil {
		return nil, ErrProtocol
	}
	for _, folder := range folders.Folders {
		plain, err := vaultcrypto.DecryptString(folder.Name, s.key)
		if err != nil {
			return nil, err
		}
		folder.Name = string(plain)
		clear(plain)
		file.Folders = append(file.Folders, folder)
		delete(needed, folder.ID)
	}
	if len(needed) != 0 {
		return nil, ErrProtocol
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, ErrProtocol
	}
	if _, err = decodeBackup(data, format); err != nil {
		clear(data)
		return nil, err
	}
	if ctx.Err() != nil {
		clear(data)
		return nil, ErrCancelled
	}
	if err := s.personalBackupAuthorizationLocked(vault, ids, grants); err != nil {
		clear(data)
		return nil, err
	}
	if ctx.Err() != nil {
		clear(data)
		return nil, ErrCancelled
	}
	return data, nil
}

// PublishPersonalBackup rechecks the authenticated snapshot and every expiring
// grant immediately before a short atomic file publication callback. The callback
// must not reenter Session. A Save dialog must never extend a grant's lifetime.
func (s *Session) PublishPersonalBackup(ctx context.Context, vault *VaultData, ids []string, grants map[string]*ItemAuthorization, publish func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if publish == nil {
		return ErrValidation
	}
	if err := s.personalBackupAuthorizationLocked(vault, ids, grants); err != nil {
		return err
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.stopping || ctx.Err() != nil {
		return ErrCancelled
	}
	return publish()
}

func (s *Session) personalBackupAuthorizationLocked(vault *VaultData, ids []string, grants map[string]*ItemAuthorization) error {
	if len(ids) == 0 || len(ids) > 10000 {
		return ErrValidation
	}
	if vault == nil || !s.itemSessionActiveLocked() {
		return ErrExpired
	}
	if err := s.requireScopeLocked(vault.Scope); err != nil {
		return err
	}
	policies, err := s.snapshotPoliciesLocked(vault)
	if err != nil {
		return err
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return err
	}
	wanted, seen := map[string]bool{}, map[string]bool{}
	for _, id := range ids {
		if !validObjectID(id) || wanted[id] {
			return ErrValidation
		}
		wanted[id] = true
	}
	var earliest time.Time
	// One authenticated vault scan, not one full parse/hash per selected ID.
	for _, doc := range documents {
		var metadata struct {
			ID             string
			Type, Reprompt int
			OrganizationID *string
			ViewPassword   bool
		}
		if json.Unmarshal(doc.JSON, &metadata) != nil {
			return ErrProtocol
		}
		if !wanted[metadata.ID] {
			continue
		}
		if seen[metadata.ID] {
			return ErrProtocol
		}
		seen[metadata.ID] = true
		if metadata.OrganizationID != nil || !metadata.ViewPassword || metadata.Reprompt < 0 || metadata.Reprompt > 1 || policies.restricts(nil, metadata.Type) {
			return ErrPermission
		}
		if metadata.Reprompt != 0 {
			grant := grants[metadata.ID]
			if !s.validItemAuthorizationLocked(grant, doc) {
				return ErrPermission
			}
			if earliest.IsZero() || grant.expires.Before(earliest) {
				earliest = grant.expires
			}
		}
	}
	if len(seen) != len(wanted) {
		return ErrNotFound
	}
	if !earliest.IsZero() && !time.Now().Before(earliest) {
		return ErrPermission
	}
	return nil
}

func encryptImportedItem(item map[string]any, userKey []byte, account string) (CipherDocument, error) {
	// Work on an independent object; retain the plan for preview/reconciliation.
	data, _ := json.Marshal(item)
	defer clear(data)
	object, err := documentObject(CipherDocument{JSON: data})
	if err != nil {
		return CipherDocument{}, err
	}
	for _, name := range []string{"id", "creationDate", "revisionDate", "deletedDate", "collectionIds"} {
		delete(object, name)
	}
	key := make([]byte, 64)
	if _, err = rand.Read(key); err != nil {
		return CipherDocument{}, ErrEncryption
	}
	defer clear(key)
	wrapped, err := vaultcrypto.EncryptString(key, userKey)
	if err != nil {
		return CipherDocument{}, err
	}
	object["key"], object["encryptedFor"] = wrapped, account
	if login, ok := object["login"].(map[string]any); ok {
		uris, err := backupObjectRows(login["uris"])
		if err != nil {
			return CipherDocument{}, err
		}
		for _, uri := range uris {
			_, hasChecksum := uri["uriChecksum"]
			if text, ok := uri["uri"].(string); ok && !hasChecksum {
				hash := sha256.Sum256([]byte(text))
				uri["uriChecksum"] = base64.StdEncoding.EncodeToString(hash[:])
			}
		}
	}
	if err = transformCompleteCipher(object, key, true); err != nil {
		return CipherDocument{}, err
	}
	encrypted, err := json.Marshal(object)
	if err != nil {
		return CipherDocument{}, ErrProtocol
	}
	return CipherDocument{JSON: encrypted}, nil
}
