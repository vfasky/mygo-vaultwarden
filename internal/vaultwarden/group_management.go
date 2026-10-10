// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"reflect"
	"strings"
)

var ErrGroupsDisabled = errors.New(i18n.T("服务器未启用群组，无法读取或修改群组"))

// GroupScope has an explicit unset state: Vaultwarden 1.37.4 never returns
// accessAll, although every group PUT overwrites it.
type GroupScope int

const (
	GroupScopeUnset GroupScope = iota
	GroupSelectedCollections
	GroupAllCollections
)

type GroupEntry struct{ ID, Name string }

// GroupAssignment identifies a membership or a collection in this organization.
// Collection names are decrypted for display; group names remain server plaintext.
type GroupAssignment struct {
	ID, Label                                 string
	Collection                                bool
	Assigned, ReadOnly, HidePasswords, Manage bool
}

func (a GroupAssignment) key() string {
	if a.Collection {
		return "collections/" + a.ID
	}
	return "users/" + a.ID
}

type GroupDraft struct {
	Name                         string
	AccessScope                  GroupScope
	Access                       []GroupAssignment
	id, organizationID, revision string
	scope                        Scope
	raw                          map[string]json.RawMessage
	originalAccess               map[string]GroupAssignment
	members                      []OrganizationMember
}
type GroupConsent struct{ draft *GroupDraft }

func (d *GroupDraft) ID() string {
	if d == nil {
		return ""
	}
	return d.id
}
func (d *GroupDraft) Clone() *GroupDraft {
	if d == nil {
		return nil
	}
	c := *d
	c.Access = append([]GroupAssignment(nil), d.Access...)
	c.members = append([]OrganizationMember(nil), d.members...)
	c.raw = map[string]json.RawMessage{}
	for k, v := range d.raw {
		c.raw[k] = append(json.RawMessage(nil), v...)
	}
	c.originalAccess = map[string]GroupAssignment{}
	for k, v := range d.originalAccess {
		c.originalAccess[k] = v
	}
	return &c
}
func (d *GroupDraft) Close() {
	if d != nil {
		*d = GroupDraft{}
	}
}
func (c *GroupConsent) Close() {
	if c != nil {
		c.draft.Close()
		c.draft = nil
	}
}
func (c *GroupConsent) Clone() *GroupConsent {
	if c == nil {
		return nil
	}
	return &GroupConsent{draft: c.draft.Clone()}
}

// Confirm binds the whole displayed form and its authenticated original state.
func (d *GroupDraft) Confirm() *GroupConsent {
	if d == nil || (d.AccessScope != GroupSelectedCollections && d.AccessScope != GroupAllCollections) {
		return nil
	}
	return &GroupConsent{draft: d.Clone()}
}
func (s *Session) groupsLocked(ctx context.Context, org Organization, persist func(SessionCheckpoint) error) ([]GroupEntry, error) {
	if !org.UseGroups {
		return nil, ErrGroupsDisabled
	}
	var list struct {
		Data              []struct{ ID, Name, OrganizationID string }
		ContinuationToken *string
	}
	if err := s.memberReadLocked(ctx, "/api/organizations/"+org.ID+"/groups", &list, persist); err != nil {
		return nil, err
	}
	if list.Data == nil || list.ContinuationToken != nil || len(list.Data) > 10000 {
		return nil, ErrProtocol
	}
	rows := []GroupEntry{}
	seen := map[string]bool{}
	for _, r := range list.Data {
		if !validObjectID(r.ID) || r.OrganizationID != org.ID || seen[r.ID] {
			return nil, ErrIdentity
		}
		seen[r.ID] = true
		rows = append(rows, GroupEntry{r.ID, r.Name})
	}
	return rows, nil
}
func (s *Session) OrganizationGroups(ctx context.Context, vault *VaultData, orgID string, persist func(SessionCheckpoint) error) ([]GroupEntry, error) {
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
	return s.groupsLocked(ctx, org, persist)
}
func (s *Session) groupDraftLocked(ctx context.Context, vault *VaultData, org Organization, id string, orgKey []byte, persist func(SessionCheckpoint) error) (*GroupDraft, error) {
	if !org.UseGroups {
		return nil, ErrGroupsDisabled
	}
	if id != "" && !validObjectID(id) {
		return nil, ErrValidation
	}
	path := "/api/organizations/" + org.ID
	d := &GroupDraft{id: id, organizationID: org.ID, scope: vault.Scope, revision: s.authorizationRevision, raw: map[string]json.RawMessage{"collections": json.RawMessage(`[]`), "users": json.RawMessage(`[]`), "externalId": json.RawMessage(`null`)}, originalAccess: map[string]GroupAssignment{}}
	var err error
	d.members, err = s.membersLocked(ctx, org, persist)
	if err != nil {
		return nil, err
	}
	if id != "" {
		d.raw = nil
		if err = s.memberReadLocked(ctx, path+"/groups/"+id+"/details", &d.raw, persist); err != nil {
			return nil, err
		}
		var gotID, gotOrg string
		if json.Unmarshal(d.raw["id"], &gotID) != nil || json.Unmarshal(d.raw["organizationId"], &gotOrg) != nil || gotID != id || gotOrg != org.ID {
			return nil, ErrIdentity
		}
		if json.Unmarshal(d.raw["name"], &d.Name) != nil {
			return nil, ErrProtocol
		}
		var users []string
		if err = s.memberReadLocked(ctx, path+"/groups/"+id+"/users", &users, persist); err != nil {
			return nil, err
		}
		if users == nil || len(users) > 100000 {
			return nil, ErrProtocol
		}
		seen := map[string]bool{}
		for _, mid := range users {
			if _, ok := memberIn(d.members, mid); !ok || seen[mid] {
				return nil, ErrIdentity
			}
			seen[mid] = true
		}
		d.raw["users"], _ = json.Marshal(users)
	}
	if err = validateCollectionAccess(d.raw["collections"]); err != nil {
		return nil, err
	}
	var assigned []GroupAssignment
	_ = json.Unmarshal(d.raw["collections"], &assigned)
	var users []string
	if json.Unmarshal(d.raw["users"], &users) != nil {
		return nil, ErrProtocol
	}
	for _, m := range d.members {
		a := GroupAssignment{ID: m.ID, Label: m.Name + " · " + m.Email}
		for _, mid := range users {
			if mid == m.ID {
				a.Assigned = true
			}
		}
		d.Access = append(d.Access, a)
		d.originalAccess[a.key()] = a
	}
	var cols struct {
		Data              []struct{ ID, OrganizationID, Name string }
		ContinuationToken *string
	}
	if err = s.memberReadLocked(ctx, path+"/collections", &cols, persist); err != nil {
		return nil, err
	}
	if cols.Data == nil || cols.ContinuationToken != nil || len(cols.Data) > 10000 {
		return nil, ErrProtocol
	}
	if len(orgKey) != 64 {
		return nil, ErrPermission
	}
	seen := map[string]bool{}
	for _, col := range cols.Data {
		if !validObjectID(col.ID) || col.OrganizationID != org.ID || seen[col.ID] {
			return nil, ErrIdentity
		}
		seen[col.ID] = true
		plain, err := vaultcrypto.DecryptString(col.Name, orgKey)
		if err != nil {
			return nil, err
		}
		a := GroupAssignment{ID: col.ID, Label: string(plain), Collection: true, ReadOnly: true, HidePasswords: true}
		clear(plain)
		for _, prior := range assigned {
			if prior.ID == col.ID {
				a.Assigned = true
				a.ReadOnly = prior.ReadOnly
				a.HidePasswords = prior.HidePasswords
				a.Manage = prior.Manage
			}
		}
		d.Access = append(d.Access, a)
		d.originalAccess[a.key()] = a
	}
	for _, a := range assigned {
		if !seen[a.ID] {
			return nil, ErrIdentity
		}
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return d, nil
}
func (s *Session) GroupDetails(ctx context.Context, vault *VaultData, orgID, id string, persist func(SessionCheckpoint) error) (*GroupDraft, error) {
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
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	return s.groupDraftLocked(ctx, vault, org, id, data.keys[org.ID], persist)
}
func (d *GroupDraft) body() (map[string]json.RawMessage, error) {
	if d == nil || strings.TrimSpace(d.Name) == "" || len(d.Name) > 1000 || (d.AccessScope != GroupAllCollections && d.AccessScope != GroupSelectedCollections) {
		return nil, ErrValidation
	}
	if len(d.Access) != len(d.originalAccess) {
		return nil, ErrIdentity
	}
	body := map[string]json.RawMessage{}
	for k, v := range d.raw {
		body[k] = v
	}
	var old []map[string]json.RawMessage
	_ = json.Unmarshal(d.raw["collections"], &old)
	users := []string{}
	cols := []map[string]json.RawMessage{}
	seen := map[string]bool{}
	for _, a := range d.Access {
		if _, ok := d.originalAccess[a.key()]; !ok || seen[a.key()] {
			return nil, ErrIdentity
		}
		seen[a.key()] = true
		if !a.Assigned {
			continue
		}
		if !a.Collection {
			users = append(users, a.ID)
			continue
		}
		if a.Manage && (a.ReadOnly || a.HidePasswords) {
			return nil, ErrValidation
		}
		row := map[string]json.RawMessage{}
		for _, prior := range old {
			var id string
			_ = json.Unmarshal(prior["id"], &id)
			if id == a.ID {
				for k, v := range prior {
					row[k] = v
				}
			}
		}
		row["id"], _ = json.Marshal(a.ID)
		setCollectionRights(row, CollectionAccess{ReadOnly: a.ReadOnly, HidePasswords: a.HidePasswords, Manage: a.Manage})
		cols = append(cols, row)
	}
	body["name"], _ = json.Marshal(d.Name)
	body["accessAll"], _ = json.Marshal(d.AccessScope == GroupAllCollections)
	body["users"], _ = json.Marshal(users)
	body["collections"], _ = json.Marshal(cols)
	return body, nil
}
func (s *Session) SaveGroup(ctx context.Context, vault *VaultData, d *GroupDraft, consent *GroupConsent, isolate, persist func(SessionCheckpoint) error) error {
	if consent == nil || !reflect.DeepEqual(d, consent.draft) {
		return ErrValidation
	}
	body, err := d.body()
	if err != nil {
		return err
	}
	consent.Close()
	return s.mutateGroup(ctx, vault, d, body, false, isolate, persist)
}
func (s *Session) DeleteGroup(ctx context.Context, vault *VaultData, d *GroupDraft, isolate, persist func(SessionCheckpoint) error) error {
	if d == nil || d.id == "" {
		return ErrValidation
	}
	return s.mutateGroup(ctx, vault, d, nil, true, isolate, persist)
}
func (s *Session) mutateGroup(ctx context.Context, vault *VaultData, d *GroupDraft, body any, remove bool, isolate, persist func(SessionCheckpoint) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if vault == nil || d.scope != vault.Scope || d.revision == "" || d.revision != s.authorizationRevision {
		return ErrExpired
	}
	org, err := s.memberAdministratorLocked(vault, d.organizationID)
	if err != nil {
		return err
	}
	if !org.UseGroups {
		return ErrGroupsDisabled
	}
	// Hold the already-authorized key only for this operation. Isolation revokes
	// offline access before the directory recheck; it cannot reauthorize reads.
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	// All existing-group writes may change undisclosed accessAll. Quarantine the
	// target organization durably before reads or a possibly partial mutation.
	if d.id != "" && (isolate == nil || s.checkpointLocked(isolate) != nil) {
		return ErrCheckpoint
	}
	fresh, err := s.groupDraftLocked(ctx, vault, org, d.id, data.keys[org.ID], persist)
	if err != nil {
		return err
	}
	defer fresh.Close()
	if !reflect.DeepEqual(d.raw, fresh.raw) || !reflect.DeepEqual(d.originalAccess, fresh.originalAccess) || !reflect.DeepEqual(d.members, fresh.members) {
		return ErrConflict
	}
	path := "/api/organizations/" + org.ID + "/groups"
	method := http.MethodPost
	if d.id != "" {
		path += "/" + d.id
		method = http.MethodPut
	}
	if remove {
		method = http.MethodDelete
	}
	if remove {
		return s.memberWriteLocked(ctx, method, path, body, persist)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return ErrProtocol
	}
	status, response, err := s.authenticatedGuardedLocked(ctx, method, path, "application/json", string(encoded), persist, s.organizationManagementGuardLocked(s.authorizationRevision))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	var saved struct{ ID, OrganizationID, Name string }
	if json.Unmarshal(response, &saved) != nil || !validObjectID(saved.ID) || (d.id != "" && saved.ID != d.id) || saved.OrganizationID != org.ID || saved.Name != d.Name {
		return &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
