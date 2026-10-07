// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"
	"reflect"
)

// OrganizationMember.ID is a membership ID; UserID is the global account ID.
type OrganizationMember struct {
	ID, UserID, Name, Email string
	Type, Status            int
}

// MemberDirectory is an authenticated, revision-bound view. Callers receive
// copies of rows and cannot replace the identities used to dispatch mutations.
type MemberDirectory struct {
	organizationID, revision string
	scope                    Scope
	rows                     []OrganizationMember
}

func (d *MemberDirectory) Members() []OrganizationMember {
	if d == nil {
		return nil
	}
	return append([]OrganizationMember(nil), d.rows...)
}
func (d *MemberDirectory) Clone() *MemberDirectory {
	if d == nil {
		return nil
	}
	clone := *d
	clone.rows = d.Members()
	return &clone
}
func (d *MemberDirectory) Close() {
	if d != nil {
		clear(d.rows)
		*d = MemberDirectory{}
	}
}

func (s *Session) memberAdministratorLocked(vault *VaultData, orgID string) (Organization, error) {
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return Organization{}, err
	}
	defer data.close()
	for _, org := range data.organizations {
		if org.ID == orgID && (org.Type == 0 || org.Type == 1) {
			return org, nil
		}
	}
	return Organization{}, ErrPermission
}

func (s *Session) membersLocked(ctx context.Context, org Organization, persist func(SessionCheckpoint) error) ([]OrganizationMember, error) {
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/organizations/"+org.ID+"/users", "", "", persist, s.organizationManagementGuardLocked(s.authorizationRevision))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, cipherUpdateStatusError(status, body)
	}
	var list struct {
		Data              []OrganizationMember
		ContinuationToken *string
	}
	if json.Unmarshal(body, &list) != nil || list.Data == nil || list.ContinuationToken != nil || len(list.Data) > 100000 {
		return nil, ErrProtocol
	}
	members, users, current := map[string]bool{}, map[string]bool{}, false
	for _, row := range list.Data {
		if !validObjectID(row.ID) || !validObjectID(row.UserID) || row.ID == row.UserID || members[row.ID] || users[row.UserID] || (row.UserID == s.account) != (row.ID == org.OrganizationUserID) {
			return nil, ErrIdentity
		}
		if row.Status < -1 || row.Status > 2 || (row.Type != 0 && row.Type != 1 && row.Type != 2 && row.Type != 4) {
			return nil, ErrProtocol
		}
		if row.ID == org.OrganizationUserID {
			if row.Status != 2 || row.Type != org.Type {
				return nil, ErrPermission
			}
			current = true
		}
		members[row.ID], users[row.UserID] = true, true
	}
	if !current {
		return nil, ErrIdentity
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return list.Data, nil
}

func (s *Session) OrganizationMembers(ctx context.Context, vault *VaultData, orgID string, persist func(SessionCheckpoint) error) (*MemberDirectory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	org, err := s.memberAdministratorLocked(vault, orgID)
	if err != nil {
		return nil, err
	}
	rows, err := s.membersLocked(ctx, org, persist)
	if err != nil {
		return nil, err
	}
	return &MemberDirectory{organizationID: orgID, revision: s.authorizationRevision, scope: vault.Scope, rows: rows}, nil
}

func (s *Session) memberDirectoryLocked(vault *VaultData, directory *MemberDirectory) (Organization, error) {
	if directory == nil || vault == nil || directory.scope != vault.Scope || directory.revision == "" || directory.revision != s.authorizationRevision {
		return Organization{}, ErrExpired
	}
	return s.memberAdministratorLocked(vault, directory.organizationID)
}
func memberIn(rows []OrganizationMember, id string) (OrganizationMember, bool) {
	for _, row := range rows {
		if row.ID == id {
			return row, true
		}
	}
	return OrganizationMember{}, false
}
func (s *Session) freshMemberLocked(ctx context.Context, org Organization, directory *MemberDirectory, id string, persist func(SessionCheckpoint) error) (OrganizationMember, error) {
	prior, found := memberIn(directory.rows, id)
	if !found {
		return OrganizationMember{}, ErrIdentity
	}
	rows, err := s.membersLocked(ctx, org, persist)
	if err != nil {
		return OrganizationMember{}, err
	}
	current, found := memberIn(rows, id)
	if !found || !reflect.DeepEqual(current, prior) {
		return OrganizationMember{}, ErrConflict
	}
	return current, nil
}
func (s *Session) memberWriteLocked(ctx context.Context, method, path string, payload any, persist func(SessionCheckpoint) error) error {
	encoded := ""
	if payload != nil {
		body, err := json.Marshal(payload)
		if err != nil {
			return ErrProtocol
		}
		encoded = string(body)
	}
	status, body, err := s.authenticatedGuardedLocked(ctx, method, path, "application/json", encoded, persist, s.organizationManagementGuardLocked(s.authorizationRevision))
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, body)}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}

// InviteOrganizationMember sends one invitation, avoiding the server's partially
// applied multi-email loop. Collection assignments are configured separately.
func (s *Session) InviteOrganizationMember(ctx context.Context, vault *VaultData, directory *MemberDirectory, email string, role int, persist func(SessionCheckpoint) error) error {
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 320 || (role != 0 && role != 1 && role != 2 && role != 4) {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	org, err := s.memberDirectoryLocked(vault, directory)
	if err != nil {
		return err
	}
	if role != 2 && org.Type != 0 {
		return ErrPermission
	}
	if _, err = s.membersLocked(ctx, org, persist); err != nil {
		return err
	}
	return s.memberWriteLocked(ctx, http.MethodPost, "/api/organizations/"+org.ID+"/users/invite", map[string]any{"emails": []string{email}, "type": role, "collections": []any{}, "groups": []string{}, "permissions": map[string]bool{}}, persist)
}

// ChangeOrganizationMember handles explicit one-member lifecycle transitions.
// Removing the current membership requires durable local isolation before HTTP.
func (s *Session) ChangeOrganizationMember(ctx context.Context, vault *VaultData, directory *MemberDirectory, id, operation string, isolate, persist func(SessionCheckpoint) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	org, err := s.memberDirectoryLocked(vault, directory)
	if err != nil {
		return err
	}
	row, found := memberIn(directory.rows, id)
	if !found {
		return ErrIdentity
	}
	method, suffix := http.MethodPut, "/"+operation
	switch operation {
	case "reinvite":
		if row.Status != 0 {
			return ErrValidation
		}
		method = http.MethodPost
	case "remove":
		if row.Type != 2 && org.Type != 0 {
			return ErrPermission
		}
		method, suffix = http.MethodDelete, ""
	case "revoke", "restore":
		if row.UserID == s.account || (row.Type == 0 && org.Type != 0) {
			return ErrPermission
		}
		if (operation == "revoke" && row.Status < 0) || (operation == "restore" && row.Status != -1) {
			return ErrValidation
		}
	default:
		return ErrValidation
	}
	if row.UserID == s.account && operation == "remove" {
		if isolate == nil || s.checkpointLocked(isolate) != nil {
			return ErrCheckpoint
		}
	}
	if _, err = s.freshMemberLocked(ctx, org, directory, id, persist); err != nil {
		return err
	}
	return s.memberWriteLocked(ctx, method, "/api/organizations/"+org.ID+"/users/"+id+suffix, nil, persist)
}

// MemberConfirmation retains no organization key. The full canonical DER/SPKI
// must be verified through a trusted channel before sharing the organization key.
type MemberConfirmation struct {
	directory *MemberDirectory
	member    OrganizationMember
	publicKey string
}

func (c *MemberConfirmation) PublicKey() string {
	if c == nil {
		return ""
	}
	return c.publicKey
}
func (c *MemberConfirmation) Member() OrganizationMember {
	if c == nil {
		return OrganizationMember{}
	}
	return c.member
}
func (c *MemberConfirmation) Clone() *MemberConfirmation {
	if c == nil {
		return nil
	}
	clone := *c
	clone.directory = c.directory.Clone()
	return &clone
}
func (c *MemberConfirmation) Close() {
	if c != nil {
		c.directory.Close()
		*c = MemberConfirmation{}
	}
}
func parseMemberPublicKey(encoded string) (*rsa.PublicKey, error) {
	if len(encoded) > 4096 {
		return nil, ErrEncryption
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, ErrEncryption
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, ErrEncryption
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok || public.N.BitLen() < 2048 || public.N.BitLen() > 4096 || public.E != 65537 {
		return nil, ErrEncryption
	}
	canonical, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || base64.StdEncoding.EncodeToString(canonical) != encoded {
		return nil, ErrEncryption
	}
	return public, nil
}
func (s *Session) memberPublicKeyLocked(ctx context.Context, member OrganizationMember, persist func(SessionCheckpoint) error) (string, error) {
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/users/"+member.UserID+"/public-key", "", "", persist, s.organizationManagementGuardLocked(s.authorizationRevision))
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", cipherUpdateStatusError(status, body)
	}
	var response struct{ UserID, PublicKey string }
	if json.Unmarshal(body, &response) != nil || response.UserID != member.UserID {
		return "", ErrIdentity
	}
	if _, err := parseMemberPublicKey(response.PublicKey); err != nil {
		return "", err
	}
	return response.PublicKey, nil
}
func (s *Session) PrepareMemberConfirmation(ctx context.Context, vault *VaultData, directory *MemberDirectory, id string, persist func(SessionCheckpoint) error) (*MemberConfirmation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	org, err := s.memberDirectoryLocked(vault, directory)
	if err != nil {
		return nil, err
	}
	member, err := s.freshMemberLocked(ctx, org, directory, id, persist)
	if err != nil {
		return nil, err
	}
	if member.Status != 1 || (member.Type != 2 && org.Type != 0) {
		return nil, ErrPermission
	}
	public, err := s.memberPublicKeyLocked(ctx, member, persist)
	if err != nil {
		return nil, err
	}
	return &MemberConfirmation{directory: directory.Clone(), member: member, publicKey: public}, nil
}
func (s *Session) ConfirmOrganizationMember(ctx context.Context, vault *VaultData, confirmation *MemberConfirmation, verifiedSPKI string, persist func(SessionCheckpoint) error) error {
	if confirmation == nil || verifiedSPKI == "" || verifiedSPKI != confirmation.publicKey {
		return ErrIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	org, err := s.memberDirectoryLocked(vault, confirmation.directory)
	if err != nil {
		return err
	}
	member, err := s.freshMemberLocked(ctx, org, confirmation.directory, confirmation.member.ID, persist)
	if err != nil {
		return err
	}
	if member.Status != 1 || (member.Type != 2 && org.Type != 0) {
		return ErrPermission
	}
	current, err := s.memberPublicKeyLocked(ctx, member, persist)
	if err != nil {
		return err
	}
	if current != verifiedSPKI {
		return ErrConflict
	}
	public, err := parseMemberPublicKey(current)
	if err != nil {
		return err
	}
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	key := data.keys[org.ID]
	if len(key) != 64 {
		return ErrEncryption
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, key, nil)
	if err != nil {
		return ErrEncryption
	}
	return s.memberWriteLocked(ctx, http.MethodPost, "/api/organizations/"+org.ID+"/users/"+member.ID+"/confirm", map[string]string{"key": "3." + base64.StdEncoding.EncodeToString(wrapped)}, persist)
}
