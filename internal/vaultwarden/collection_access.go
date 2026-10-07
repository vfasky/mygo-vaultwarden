// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
)

// ID always denotes an organization membership or group, never a global user.
// Labels are display-only. Choices are checked against the authenticated directory.
type CollectionAccess struct {
	ID, Label                                 string
	Group                                     bool
	Assigned, ReadOnly, HidePasswords, Manage bool
}

func (a CollectionAccess) key() string {
	if a.Group {
		return "groups/" + a.ID
	}
	return "users/" + a.ID
}
func (a CollectionAccess) sameRights(b CollectionAccess) bool {
	return a.Assigned == b.Assigned && a.ReadOnly == b.ReadOnly && a.HidePasswords == b.HidePasswords && a.Manage == b.Manage
}

// CollectionAccessDetails obtains friendly identities from mini-details, which
// is available to collection managers without exposing full member admin data.
func (s *Session) CollectionAccessDetails(ctx context.Context, vault *VaultData, source *CollectionDraft, persist func(SessionCheckpoint) error) (*CollectionDraft, error) {
	if source == nil {
		return nil, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if vault == nil || source.scope != vault.Scope || source.revision == "" || source.revision != s.authorizationRevision {
		return nil, ErrExpired
	}
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	if err := collectionManager(data, source.organizationID, source.id); err != nil {
		return nil, err
	}
	draft := source.Clone()
	draft.Access = nil
	draft.originalAccess = map[string]CollectionAccess{}
	currentMembership := ""
	for _, org := range data.organizations {
		if org.ID == source.organizationID {
			draft.GroupsEnabled = org.UseGroups
			currentMembership = org.OrganizationUserID
		}
	}
	guard := s.organizationManagementGuardLocked(source.revision)
	for _, group := range []bool{false, true} {
		if group && !draft.GroupsEnabled {
			continue
		}
		suffix, field := "/users/mini-details", "users"
		if group {
			suffix, field = "/groups", "groups"
		}
		status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/organizations/"+source.organizationID+suffix, "", "", persist, guard)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, cipherUpdateStatusError(status, body)
		}
		var list struct {
			Data              []struct{ ID, UserID, OrganizationID, Name, Email string }
			ContinuationToken *string
		}
		if json.Unmarshal(body, &list) != nil || list.Data == nil || list.ContinuationToken != nil || len(list.Data) > 100000 {
			return nil, ErrProtocol
		}
		var assigned []struct {
			ID                              string
			ReadOnly, HidePasswords, Manage bool
		}
		if json.Unmarshal(source.raw[field], &assigned) != nil {
			return nil, ErrProtocol
		}
		seenUsers := map[string]bool{}
		for _, row := range list.Data {
			if !validObjectID(row.ID) || (!group && (!validObjectID(row.UserID) || row.UserID == row.ID)) || (group && row.OrganizationID != source.organizationID) {
				return nil, ErrIdentity
			}
			if !group {
				if seenUsers[row.UserID] || (row.UserID == s.account) != (row.ID == currentMembership) {
					return nil, ErrIdentity
				}
				seenUsers[row.UserID] = true
			}
			option := CollectionAccess{ID: row.ID, Label: row.Name, Group: group, ReadOnly: true, HidePasswords: true}
			if !group {
				option.Label = row.Name + " · " + row.Email
			}
			if _, duplicate := draft.originalAccess[option.key()]; duplicate {
				return nil, ErrIdentity
			}
			for _, prior := range assigned {
				if prior.ID == row.ID {
					option.Assigned, option.ReadOnly, option.HidePasswords, option.Manage = true, prior.ReadOnly, prior.HidePasswords, prior.Manage
				}
			}
			draft.Access = append(draft.Access, option)
			draft.originalAccess[option.key()] = option
		}
	}
	if ctx.Err() != nil {
		draft.Close()
		return nil, ErrCancelled
	}
	draft.AccessLoaded = true
	return draft, nil
}

func (d *CollectionDraft) AccessChanged() bool {
	if d == nil {
		return false
	}
	for _, option := range d.Access {
		if original, ok := d.originalAccess[option.key()]; !ok || !option.sameRights(original) {
			return true
		}
	}
	return false
}

func (d *CollectionDraft) collectionWriteBody() (map[string]json.RawMessage, bool, error) {
	body := make(map[string]json.RawMessage, len(d.raw))
	for key, value := range d.raw {
		body[key] = value
	}
	if !d.AccessLoaded {
		if len(d.Access) != 0 {
			return nil, false, ErrIdentity
		}
		return body, false, nil
	}
	if len(d.Access) != len(d.originalAccess) {
		return nil, false, ErrIdentity
	}
	changes := map[string]CollectionAccess{}
	seen := map[string]bool{}
	for _, option := range d.Access {
		original, ok := d.originalAccess[option.key()]
		if !ok || seen[option.key()] {
			return nil, false, ErrIdentity
		}
		seen[option.key()] = true
		if option.sameRights(original) {
			continue
		}
		// Manage cannot be paired with a read-only or hidden-password restriction.
		if option.Assigned && option.Manage && (option.ReadOnly || option.HidePasswords) {
			return nil, false, ErrValidation
		}
		changes[option.key()] = option
	}
	if len(changes) == 0 {
		return body, false, nil
	}
	for _, field := range []string{"users", "groups"} {
		var entries []map[string]json.RawMessage
		if json.Unmarshal(d.raw[field], &entries) != nil {
			return nil, false, ErrProtocol
		}
		result := make([]map[string]json.RawMessage, 0, len(entries))
		handled := map[string]bool{}
		for _, entry := range entries {
			var id string
			if json.Unmarshal(entry["id"], &id) != nil {
				return nil, false, ErrProtocol
			}
			option, changed := changes[field+"/"+id]
			if !changed {
				result = append(result, entry)
				continue
			}
			handled[id] = true
			if !option.Assigned {
				continue
			}
			updated := make(map[string]json.RawMessage, len(entry))
			for key, value := range entry {
				updated[key] = value
			}
			setCollectionRights(updated, option)
			result = append(result, updated)
		}
		// Keep directory order for deterministic request bodies.
		for _, option := range d.Access {
			if (field == "groups") != option.Group || handled[option.ID] || !option.Assigned {
				continue
			}
			if _, changed := changes[option.key()]; !changed {
				continue
			}
			entry := map[string]json.RawMessage{}
			entry["id"], _ = json.Marshal(option.ID)
			setCollectionRights(entry, option)
			result = append(result, entry)
		}
		body[field], _ = json.Marshal(result)
	}
	return body, true, nil
}

func setCollectionRights(entry map[string]json.RawMessage, option CollectionAccess) {
	entry["readOnly"], _ = json.Marshal(option.ReadOnly)
	entry["hidePasswords"], _ = json.Marshal(option.HidePasswords)
	entry["manage"], _ = json.Marshal(option.Manage)
}
