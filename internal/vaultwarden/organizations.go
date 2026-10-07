// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"hash"
	"net/http"
	"reflect"
)

// Organization separates the organization, membership and global account IDs.
// Name is plaintext in Vaultwarden's profile, unlike collection names.
type Organization struct {
	ID                 string
	OrganizationUserID string
	UserID             string
	Name               string
	Key                string
	Status             int
	Type               int
	Enabled            bool
	Permissions        map[string]bool
}

type Collection struct {
	ID, OrganizationID, Name        string
	ReadOnly, HidePasswords, Manage bool
}

type organizationVault struct {
	documents        map[string]CipherDocument
	collectionOwners map[string]string
	organizations    []Organization
	collections      []Collection
	keys             map[string][]byte
}

func (v *organizationVault) close() {
	for _, key := range v.keys {
		clear(key)
	}
	v.keys = nil
}

// unwrapOrganizationKey accepts only the two unsigned RSA-OAEP encodings used
// for membership keys. RSA signature encodings and arbitrary OAEP labels fail.
func unwrapOrganizationKey(wrapped string, private *rsa.PrivateKey) ([]byte, error) {
	if len(wrapped) > 2048 || len(wrapped) < 3 || wrapped[1] != '.' {
		return nil, ErrEncryption
	}
	var digest hash.Hash
	switch wrapped[0] {
	case '3':
		digest = sha256.New()
	case '4':
		digest = sha1.New()
	default:
		return nil, ErrEncryption
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(wrapped[2:])
	if err != nil || len(ciphertext) != private.Size() {
		return nil, ErrEncryption
	}
	plain, err := rsa.DecryptOAEP(digest, rand.Reader, private, ciphertext, nil)
	if err != nil || len(plain) != 64 {
		clear(plain)
		return nil, ErrEncryption
	}
	return plain, nil
}

func accountPrivateKey(profile json.RawMessage, key []byte) (*rsa.PrivateKey, error) {
	var p struct {
		PrivateKey  *string
		AccountKeys *struct {
			PublicKeyEncryptionKeyPair *struct{ WrappedPrivateKey, PublicKey string }
		}
	}
	if json.Unmarshal(profile, &p) != nil {
		return nil, ErrProtocol
	}
	wrapped, public := "", ""
	if p.PrivateKey != nil {
		wrapped = *p.PrivateKey
	}
	if p.AccountKeys != nil && p.AccountKeys.PublicKeyEncryptionKeyPair == nil {
		return nil, ErrEncryption
	}
	if p.AccountKeys != nil && p.AccountKeys.PublicKeyEncryptionKeyPair != nil {
		pair := p.AccountKeys.PublicKeyEncryptionKeyPair
		if pair.PublicKey == "" || pair.WrappedPrivateKey == "" {
			return nil, ErrEncryption
		}
		if p.PrivateKey != nil && wrapped != pair.WrappedPrivateKey {
			return nil, ErrIdentity
		}
		wrapped, public = pair.WrappedPrivateKey, pair.PublicKey
	}
	if len(wrapped) == 0 || len(wrapped) > 16384 || len(public) > 4096 {
		return nil, ErrEncryption
	}
	der, err := DecryptString(wrapped, key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	if len(der) > 8192 {
		return nil, ErrEncryption
	}
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &sequence); err != nil || len(rest) != 0 || sequence.Tag != asn1.TagSequence {
		return nil, ErrEncryption
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, ErrEncryption
	}
	private, ok := parsed.(*rsa.PrivateKey)
	if !ok || private.N.BitLen() < 2048 || private.N.BitLen() > 4096 || private.E != 65537 || private.Validate() != nil {
		return nil, ErrEncryption
	}
	if public != "" {
		encoded, err := base64.StdEncoding.Strict().DecodeString(public)
		if err != nil {
			return nil, ErrEncryption
		}
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		pub, ok := parsed.(*rsa.PublicKey)
		if err != nil || !ok || !private.PublicKey.Equal(pub) {
			return nil, ErrIdentity
		}
	}
	return private, nil
}

// Keys exist only during an operation and are never attached to display state or
// persisted independently of the encrypted sync. Callers hold the session lock.
func (s *Session) organizationVaultLocked(vault *VaultData) (*organizationVault, error) {
	if !s.itemSessionActiveLocked() || vault == nil {
		return nil, ErrExpired
	}
	if err := s.requireScopeLocked(vault.Scope); err != nil {
		return nil, err
	}
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return nil, err
	}
	var data struct {
		Profile     json.RawMessage
		Collections []json.RawMessage
	}
	if json.Unmarshal(vault.Sync, &data) != nil {
		return nil, ErrProtocol
	}
	var profile struct{ Organizations, OrganizationsNew []Organization }
	if json.Unmarshal(data.Profile, &profile) != nil {
		return nil, ErrProtocol
	}
	if len(profile.Organizations) > 1024 || len(profile.OrganizationsNew) > 2048 || len(data.Collections) > 100000 {
		return nil, ErrProtocol
	}
	result := &organizationVault{keys: map[string][]byte{}, documents: map[string]CipherDocument{}, collectionOwners: map[string]string{}}
	for _, document := range documents {
		var id struct{ ID string }
		_ = json.Unmarshal(document.JSON, &id)
		result.documents[id.ID] = document
	}
	fail := func(err error) (*organizationVault, error) { result.close(); return nil, err }
	seen, members := map[string]bool{}, map[string]bool{}
	for _, org := range profile.Organizations {
		isolated := false
		for _, id := range vault.QuarantinedOrganizations {
			if id == org.ID {
				isolated = true
			}
		}
		if isolated {
			continue
		}
		if !validObjectID(org.ID) || !validObjectID(org.OrganizationUserID) || org.UserID != s.account || org.OrganizationUserID == s.account || seen[org.ID] || members[org.OrganizationUserID] {
			return fail(ErrIdentity)
		}
		seen[org.ID], members[org.OrganizationUserID] = true, true
		if profile.OrganizationsNew != nil {
			matches := 0
			for _, other := range profile.OrganizationsNew {
				if other.ID == org.ID {
					matches++
					if !reflect.DeepEqual(org, other) {
						return fail(ErrIdentity)
					}
				}
			}
			if matches != 1 {
				return fail(ErrIdentity)
			}
		}
		if org.Status != 2 || !org.Enabled {
			continue
		}
		// Explicit supported roles; never infer authority from numeric ordering.
		if org.Type != 0 && org.Type != 1 && org.Type != 2 && org.Type != 4 {
			return fail(ErrPermission)
		}
		result.organizations = append(result.organizations, org)
	}
	if len(result.organizations) == 0 {
		return result, nil
	}
	private, err := accountPrivateKey(data.Profile, s.key)
	if err != nil {
		return fail(err)
	}
	defer func() {
		private.D.SetInt64(0)
		for _, prime := range private.Primes {
			prime.SetInt64(0)
		}
		private.Precomputed = rsa.PrecomputedValues{}
	}()
	for i := range result.organizations {
		org := &result.organizations[i]
		key, err := unwrapOrganizationKey(org.Key, private)
		if err != nil {
			return fail(err)
		}
		result.keys[org.ID] = key
		org.Key = "" // Public metadata must not carry the wrapped key either.
	}
	seen = map[string]bool{}
	for _, raw := range data.Collections {
		var collection Collection
		var flags struct{ ReadOnly, HidePasswords, Manage *bool }
		if json.Unmarshal(raw, &collection) != nil || json.Unmarshal(raw, &flags) != nil || flags.ReadOnly == nil || flags.HidePasswords == nil || flags.Manage == nil {
			return fail(ErrProtocol)
		}
		if !validObjectID(collection.ID) || seen[collection.ID] {
			return fail(ErrProtocol)
		}
		seen[collection.ID] = true
		result.collectionOwners[collection.ID] = collection.OrganizationID
		key, ok := result.keys[collection.OrganizationID]
		if !ok {
			continue
		}
		plain, err := DecryptString(collection.Name, key)
		if err != nil {
			return fail(err)
		}
		if len(plain) == 0 || len(plain) > 4096 {
			clear(plain)
			return fail(ErrProtocol)
		}
		collection.Name = string(plain)
		clear(plain)
		result.collections = append(result.collections, collection)
	}
	return result, nil
}

func (s *Session) Organizations(vault *VaultData) ([]Organization, []Collection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, nil, err
	}
	defer data.close()
	if !s.itemSessionActiveLocked() {
		return nil, nil, ErrExpired
	}
	return data.organizations, data.collections, nil
}

func (s *Session) organizationDocumentLocked(vault *VaultData, id string, data *organizationVault) (CipherDocument, []byte, error) {
	document, ok := data.documents[id]
	if !ok {
		return CipherDocument{}, nil, ErrNotFound
	}
	var m struct {
		OrganizationID     *string
		CollectionIDs      []string
		Edit, ViewPassword *bool
		Reprompt           int
	}
	if json.Unmarshal(document.JSON, &m) != nil {
		return CipherDocument{}, nil, ErrProtocol
	}
	if m.OrganizationID == nil || m.Edit == nil || m.ViewPassword == nil || !*m.ViewPassword || m.Reprompt < 0 || m.Reprompt > 1 {
		return CipherDocument{}, nil, ErrPermission
	}
	key := data.keys[*m.OrganizationID]
	if key == nil {
		return CipherDocument{}, nil, ErrPermission
	}
	// Server cipher flags include full-access groups and its direct-user-over-
	// group collection resolution. Collection flags gate destination writes;
	// recombining group grants locally would incorrectly override direct denies.
	for _, cid := range m.CollectionIDs {
		if owner, ok := data.collectionOwners[cid]; ok && owner != *m.OrganizationID {
			return CipherDocument{}, nil, ErrIdentity
		}
	}
	return document, key, nil
}

func (s *Session) ReadOrganizationCipher(vault *VaultData, id string, grant *ItemAuthorization) (CipherDocument, CipherFields, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return CipherDocument{}, CipherFields{}, err
	}
	defer data.close()
	document, key, err := s.organizationDocumentLocked(vault, id, data)
	if err != nil {
		return CipherDocument{}, CipherFields{}, err
	}
	var m struct{ Reprompt int }
	_ = json.Unmarshal(document.JSON, &m)
	if m.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
		return CipherDocument{}, CipherFields{}, ErrPermission
	}
	fields, err := DecryptCipherDocument(document, key)
	if !s.itemSessionActiveLocked() {
		return CipherDocument{}, CipherFields{}, ErrExpired
	}
	return document, fields, err
}

func (s *Session) OrganizationEntries(vault *VaultData) ([]VaultEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	documents, err := vault.Documents(vault.Scope)
	if err != nil {
		return nil, err
	}
	var entries []VaultEntry
	for _, document := range documents {
		var m struct {
			ID                        string
			OrganizationID            *string
			CollectionIDs             []string
			FolderID                  *string
			Type, Reprompt            int
			Favorite                  bool
			ArchivedDate, DeletedDate *string
		}
		if json.Unmarshal(document.JSON, &m) != nil {
			return nil, ErrProtocol
		}
		if m.OrganizationID == nil || data.keys[*m.OrganizationID] == nil {
			continue
		}
		entry := VaultEntry{ID: m.ID, OrganizationID: *m.OrganizationID, CollectionIDs: m.CollectionIDs, Type: m.Type, Title: "受保护或暂不支持的组织项目", Favorite: m.Favorite, Archived: m.ArchivedDate != nil, Deleted: m.DeletedDate != nil}
		if m.FolderID != nil {
			entry.FolderID = *m.FolderID
		}
		authorized, key, err := s.organizationDocumentLocked(vault, m.ID, data)
		if err == nil {
			if m.Reprompt == 1 {
				entry.RequiresPassword = true
			} else if fields, err := DecryptCipherDocument(authorized, key); err == nil {
				entry.Title, entry.Editable, entry.Readable = fields.Name, fields.Edit, true
				entry.Username, _ = fields.Login["username"].(string)
				if uris, ok := fields.Login["uris"].([]any); ok && len(uris) > 0 {
					if uri, ok := uris[0].(map[string]any); ok {
						entry.URL, _ = uri["uri"].(string)
					}
				}
			}
		}
		entries = append(entries, entry)
	}
	if !s.itemSessionActiveLocked() {
		return nil, ErrExpired
	}
	return entries, nil
}

// The snapshot and original document are supplied together so organization
// ownership and current membership cannot be changed in an editor DTO.
func (s *Session) UpdateOrganizationCipher(ctx context.Context, vault *VaultData, document CipherDocument, fields CipherFields, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (CipherDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return CipherDocument{}, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return CipherDocument{}, err
	}
	defer data.close()
	original, key, err := s.organizationDocumentLocked(vault, fields.ID, data)
	if err != nil {
		return CipherDocument{}, err
	}
	if !bytes.Equal(original.JSON, document.JSON) {
		return CipherDocument{}, ErrConflict
	}
	var m struct{ Reprompt int }
	_ = json.Unmarshal(document.JSON, &m)
	revision, epoch := s.authorizationRevision, s.authorizationEpoch
	guard := func() error {
		if !s.itemSessionActiveLocked() || revision == "" || revision != s.authorizationRevision || epoch != s.authorizationEpoch {
			return ErrExpired
		}
		if m.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, document) {
			return ErrPermission
		}
		return nil
	}
	if err := guard(); err != nil {
		return CipherDocument{}, err
	}
	encrypted, err := encryptCipherDocument(document, fields, key, s.account, s.validItemAuthorizationLocked(grant, document))
	if err != nil {
		return CipherDocument{}, err
	}
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodPut, "/api/ciphers/"+fields.ID, "application/json", string(encrypted.JSON), persist, guard)
	if err != nil {
		return CipherDocument{}, err
	}
	if status != http.StatusOK {
		return CipherDocument{}, cipherUpdateStatusError(status, body)
	}
	result := CipherDocument{JSON: body}
	updated, err := DecryptCipherDocument(result, key)
	if err != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: err}
	}
	if updated.ID != fields.ID || !sameOptional(updated.OrganizationID, fields.OrganizationID) {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return CipherDocument{}, &MutationUncertainError{Cause: ErrCancelled}
	}
	return result, nil
}
