// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"reflect"
	"sort"
)

var ErrMemberRoleGroupsDisabled = errors.New("服务器未启用群组，无法无损保留隐藏的群组关联；请联系服务器管理员启用群组后重新加载成员角色")

// MemberRoleDraft captures direct assignments from collection/user endpoints.
// Admin member details alone omit them when a group grants full access.
type MemberRoleDraft struct {
	Role                 int
	ManageAllCollections bool
	directory            *MemberDirectory
	member               OrganizationMember
	collections          []map[string]json.RawMessage
	groups               []string
	permissions          map[string]json.RawMessage
	assignedCollections  []MemberRoleCollection
}

type MemberRoleCollection struct {
	ID, Name                        string
	ReadOnly, HidePasswords, Manage bool
}

type MemberRoleConsent struct{ draft *MemberRoleDraft }

func (d *MemberRoleDraft) ResetsCollections() bool {
	return d != nil && len(d.collections) > 0 && (d.Role == 0 || d.Role == 1 || (d.Role == 4 && d.ManageAllCollections))
}
func (d *MemberRoleDraft) ResetCollections() []MemberRoleCollection {
	if !d.ResetsCollections() {
		return nil
	}
	return append([]MemberRoleCollection(nil), d.assignedCollections...)
}

// ConfirmCollectionReset must be called only after displaying the affected
// collections and obtaining explicit consent. It binds the entire loaded plan.
func (d *MemberRoleDraft) ConfirmCollectionReset() *MemberRoleConsent {
	if !d.ResetsCollections() || len(d.assignedCollections) != len(d.collections) {
		return nil
	}
	return &MemberRoleConsent{draft: d.Clone()}
}
func (c *MemberRoleConsent) Close() {
	if c != nil {
		c.draft.Close()
		c.draft = nil
	}
}
func (c *MemberRoleConsent) Clone() *MemberRoleConsent {
	if c == nil {
		return nil
	}
	return &MemberRoleConsent{draft: c.draft.Clone()}
}

func (d *MemberRoleDraft) Member() OrganizationMember {
	if d == nil {
		return OrganizationMember{}
	}
	return d.member
}
func (d *MemberRoleDraft) Clone() *MemberRoleDraft {
	if d == nil {
		return nil
	}
	copy := *d
	copy.directory = d.directory.Clone()
	return &copy
}
func (d *MemberRoleDraft) Close() {
	if d != nil {
		d.directory.Close()
		*d = MemberRoleDraft{}
	}
}
func (s *Session) memberReadLocked(ctx context.Context, path string, result any, persist func(SessionCheckpoint) error) error {
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, path, "", "", persist, s.organizationManagementGuardLocked(s.authorizationRevision))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return cipherUpdateStatusError(status, body)
	}
	if json.Unmarshal(body, result) != nil {
		return ErrProtocol
	}
	return nil
}
func (s *Session) memberRoleLocked(ctx context.Context, vault *VaultData, org Organization, directory *MemberDirectory, id string, persist func(SessionCheckpoint) error) (*MemberRoleDraft, error) {
	member, err := s.freshMemberLocked(ctx, org, directory, id, persist)
	if err != nil {
		return nil, err
	}
	if !org.UseGroups {
		return nil, ErrMemberRoleGroupsDisabled
	}
	if member.Type == 0 && org.Type != 0 {
		return nil, ErrPermission
	}
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	path := "/api/organizations/" + org.ID
	var detail struct {
		ID, UserID  string
		Permissions map[string]json.RawMessage
	}
	if err = s.memberReadLocked(ctx, path+"/users/"+id, &detail, persist); err != nil {
		return nil, err
	}
	if detail.ID != id || detail.UserID != member.UserID {
		return nil, ErrIdentity
	}
	draft := &MemberRoleDraft{Role: member.Type, directory: directory.Clone(), member: member, collections: []map[string]json.RawMessage{}, groups: []string{}, permissions: detail.Permissions}
	draft.ManageAllCollections = string(detail.Permissions["createNewCollections"]) == "true" && string(detail.Permissions["editAnyCollection"]) == "true" && string(detail.Permissions["deleteAnyCollection"]) == "true"
	for _, kind := range []string{"collections", "groups"} {
		if kind == "groups" && !org.UseGroups {
			continue
		}
		var list struct {
			Data              []struct{ ID, OrganizationID, Name string }
			ContinuationToken *string
		}
		if err = s.memberReadLocked(ctx, path+"/"+kind, &list, persist); err != nil {
			return nil, err
		}
		if list.Data == nil || list.ContinuationToken != nil || len(list.Data) > 10000 {
			return nil, ErrProtocol
		}
		sort.Slice(list.Data, func(i, j int) bool { return list.Data[i].ID < list.Data[j].ID })
		seen := map[string]bool{}
		for _, entry := range list.Data {
			if !validObjectID(entry.ID) || entry.OrganizationID != org.ID || seen[entry.ID] {
				return nil, ErrIdentity
			}
			seen[entry.ID] = true
			if kind == "groups" {
				var memberships []string
				if err = s.memberReadLocked(ctx, path+"/groups/"+entry.ID+"/users", &memberships, persist); err != nil {
					return nil, err
				}
				if memberships == nil || len(memberships) > 100000 {
					return nil, ErrProtocol
				}
				members := map[string]bool{}
				for _, mid := range memberships {
					if _, known := memberIn(directory.rows, mid); !known {
						return nil, ErrIdentity
					}
					if !validObjectID(mid) || members[mid] {
						return nil, ErrIdentity
					}
					members[mid] = true
					if mid == id {
						draft.groups = append(draft.groups, entry.ID)
					}
				}
			} else {
				var raw json.RawMessage
				if err = s.memberReadLocked(ctx, path+"/collections/"+entry.ID+"/users", &raw, persist); err != nil {
					return nil, err
				}
				if err = validateCollectionAccess(raw); err != nil {
					return nil, err
				}
				var users []map[string]json.RawMessage
				_ = json.Unmarshal(raw, &users)
				for _, user := range users {
					var mid string
					_ = json.Unmarshal(user["id"], &mid)
					if _, known := memberIn(directory.rows, mid); !known {
						return nil, ErrIdentity
					}
					if mid == id {
						user["id"], _ = json.Marshal(entry.ID)
						draft.collections = append(draft.collections, user)
						plain, err := vaultcrypto.DecryptString(entry.Name, data.keys[org.ID])
						if err != nil {
							return nil, err
						}
						var rights MemberRoleCollection
						encoded, _ := json.Marshal(user)
						if json.Unmarshal(encoded, &rights) != nil {
							clear(plain)
							return nil, ErrProtocol
						}
						rights.Name = string(plain)
						clear(plain)
						draft.assignedCollections = append(draft.assignedCollections, rights)
					}
				}
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return draft, nil
}
func (s *Session) PrepareMemberRole(ctx context.Context, vault *VaultData, directory *MemberDirectory, id string, persist func(SessionCheckpoint) error) (*MemberRoleDraft, error) {
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
	return s.memberRoleLocked(ctx, vault, org, directory, id, persist)
}
func (s *Session) SaveMemberRole(ctx context.Context, vault *VaultData, draft *MemberRoleDraft, consent *MemberRoleConsent, isolate, persist func(SessionCheckpoint) error) error {
	if draft == nil || (draft.Role != 0 && draft.Role != 1 && draft.Role != 2 && draft.Role != 4) {
		return ErrValidation
	}
	if consent != nil && !reflect.DeepEqual(consent.draft, draft) {
		return ErrConflict
	}
	if draft.ResetsCollections() && consent == nil {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	org, err := s.memberDirectoryLocked(vault, draft.directory)
	if err != nil {
		return err
	}
	if !org.UseGroups {
		return ErrMemberRoleGroupsDisabled
	}
	if org.Type != 0 && (draft.member.Type == 0 || (draft.Role != draft.member.Type && (draft.Role == 0 || draft.Role == 1 || draft.member.Type == 1))) {
		return ErrPermission
	}
	// A role change to the current account can revoke local access. Its durable
	// isolation must precede even the conflict reads; other member drafts survive
	// a conflict without revoking this account's unrelated local authority.
	if draft.member.UserID == s.account && (isolate == nil || s.checkpointLocked(isolate) != nil) {
		return ErrCheckpoint
	}
	fresh, err := s.memberRoleLocked(ctx, vault, org, draft.directory, draft.member.ID, persist)
	if err != nil {
		return err
	}
	defer fresh.Close()
	if !reflect.DeepEqual(fresh.assignedCollections, draft.assignedCollections) || !reflect.DeepEqual(fresh.collections, draft.collections) || !reflect.DeepEqual(fresh.groups, draft.groups) || !reflect.DeepEqual(fresh.permissions, draft.permissions) {
		return ErrConflict
	}
	permissions := map[string]json.RawMessage{}
	for name, value := range draft.permissions {
		permissions[name] = value
	}
	for _, name := range []string{"createNewCollections", "editAnyCollection", "deleteAnyCollection"} {
		permissions[name], _ = json.Marshal(draft.Role == 4 && draft.ManageAllCollections)
	}
	return s.memberWriteLocked(ctx, http.MethodPut, "/api/organizations/"+org.ID+"/users/"+draft.member.ID, map[string]any{"type": draft.Role, "permissions": permissions, "collections": draft.collections, "groups": draft.groups}, persist)
}
