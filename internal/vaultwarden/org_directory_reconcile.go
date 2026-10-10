// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"reflect"
	"sort"
	"strings"
)

type OrganizationDirectoryMemberObservation struct {
	ID, UserID, Email string
	ExternalID        *string
	Status, Type      int
}
type OrganizationDirectoryGroupObservation struct {
	ID, OrganizationID, Name string
	ExternalID               *string
	MemberIDs                []string
}
type OrganizationDirectorySnapshot struct {
	Members []OrganizationDirectoryMemberObservation
	Groups  []OrganizationDirectoryGroupObservation
}
type OrganizationDirectoryRowResult struct {
	ExternalID, Kind, Reason string
	Verified                 bool
}
type OrganizationDirectoryReconciliation struct {
	Before, After *OrganizationDirectorySnapshot
	Rows          []OrganizationDirectoryRowResult
}

// Called only inside this operation after persistent isolation and with the
// original authenticated owner identity. These management reads do not publish
// an offline receipt or accept a sync snapshot.
func (s *Session) organizationDirectorySnapshotLocked(ctx context.Context, org Organization) (*OrganizationDirectorySnapshot, error) {
	var members struct {
		Data              []OrganizationDirectoryMemberObservation
		ContinuationToken *string
	}
	if err := s.memberReadLocked(ctx, "/api/organizations/"+org.ID+"/users", &members, nil); err != nil {
		return nil, err
	}
	if members.Data == nil || members.ContinuationToken != nil || len(members.Data) > 100000 {
		return nil, ErrProtocol
	}
	found := false
	seen := map[string]bool{}
	users := map[string]bool{}
	for _, m := range members.Data {
		// Pending invitations may not yet have a global user ID.
		if !validObjectID(m.ID) || seen[m.ID] || (m.UserID != "" && (!validObjectID(m.UserID) || m.ID == m.UserID)) {
			return nil, ErrIdentity
		}
		if m.Status < -1 || m.Status > 2 || (m.Type != 0 && m.Type != 1 && m.Type != 2 && m.Type != 4) {
			return nil, ErrProtocol
		}
		if m.UserID != "" {
			if users[m.UserID] || (m.UserID == s.account) != (m.ID == org.OrganizationUserID) {
				return nil, ErrIdentity
			}
			users[m.UserID] = true
		}
		seen[m.ID] = true
		if m.ID == org.OrganizationUserID && m.UserID == s.account && m.Type == 0 && m.Status == 2 {
			found = true
		}
	}
	if !found {
		return nil, ErrPermission
	}
	r := &OrganizationDirectorySnapshot{Members: members.Data}
	if !org.UseGroups {
		return r, nil
	}
	var groups struct {
		Data              []OrganizationDirectoryGroupObservation
		ContinuationToken *string
	}
	if err := s.memberReadLocked(ctx, "/api/organizations/"+org.ID+"/groups", &groups, nil); err != nil {
		return nil, err
	}
	if groups.Data == nil || groups.ContinuationToken != nil || len(groups.Data) > 10000 {
		return nil, ErrProtocol
	}
	memberIDs := seen
	seen = map[string]bool{}
	for i := range groups.Data {
		g := &groups.Data[i]
		if !validObjectID(g.ID) || g.OrganizationID != org.ID || seen[g.ID] {
			return nil, ErrIdentity
		}
		seen[g.ID] = true
		if err := s.memberReadLocked(ctx, "/api/organizations/"+org.ID+"/groups/"+g.ID+"/users", &g.MemberIDs, nil); err != nil {
			return nil, err
		}
		if g.MemberIDs == nil {
			return nil, ErrProtocol
		}
		relations := map[string]bool{}
		for _, id := range g.MemberIDs {
			if !memberIDs[id] || relations[id] {
				return nil, ErrIdentity
			}
			relations[id] = true
		}
		sort.Strings(g.MemberIDs)
	}
	r.Groups = groups.Data
	return r, nil
}
func reconcileOrganizationDirectory(input OrganizationDirectoryImport, before, after *OrganizationDirectorySnapshot) *OrganizationDirectoryReconciliation {
	r := &OrganizationDirectoryReconciliation{Before: before, After: after}
	for _, want := range input.Members {
		row := OrganizationDirectoryRowResult{Kind: "member", ExternalID: want.ExternalID, Reason: i18n.T("server.directory.status_member_unverified")}
		matches := []OrganizationDirectoryMemberObservation{}
		if after != nil {
			for _, m := range after.Members {
				if m.ExternalID != nil && *m.ExternalID == want.ExternalID {
					matches = append(matches, m)
				}
			}
		}
		if len(matches) == 1 && strings.EqualFold(matches[0].Email, want.Email) && ((want.Deleted && matches[0].Status == -1) || (!want.Deleted && matches[0].Status >= 0)) {
			row.Verified = true
			row.Reason = i18n.T("server.directory.status_member_verified")
		}
		r.Rows = append(r.Rows, row)
	}
	for _, want := range input.Groups {
		row := OrganizationDirectoryRowResult{Kind: "group", ExternalID: want.ExternalID, Reason: i18n.T("server.directory.status_group_unverified")}
		if after != nil {
			ids := []string{}
			complete := true
			for _, external := range want.MemberExternalIDs {
				matches := []string{}
				for _, m := range after.Members {
					if m.ExternalID != nil && *m.ExternalID == external {
						matches = append(matches, m.ID)
					}
				}
				if len(matches) != 1 {
					complete = false
					break
				}
				ids = append(ids, matches[0])
			}
			sort.Strings(ids)
			count := 0
			for _, g := range after.Groups {
				if g.ExternalID != nil && *g.ExternalID == want.ExternalID {
					count++
					if complete && g.Name == want.Name && reflect.DeepEqual(ids, g.MemberIDs) {
						row.Verified = true
						row.Reason = i18n.T("server.directory.status_group_verified")
					}
				}
			}
			if count != 1 {
				row.Verified = false
				row.Reason = i18n.T("server.directory.err_group_external_id_ambiguous")
			}
		}
		r.Rows = append(r.Rows, row)
	}
	// Overwrite may revoke absent external members. Include them explicitly.
	if input.OverwriteExisting && before != nil {
		included := map[string]bool{}
		for _, m := range input.Members {
			included[m.ExternalID] = true
		}
		for _, old := range before.Members {
			if old.ExternalID == nil || included[*old.ExternalID] {
				continue
			}
			row := OrganizationDirectoryRowResult{Kind: "overwrite", ExternalID: *old.ExternalID, Reason: i18n.T("server.directory.status_revocation_unverified")}
			if after != nil {
				for _, m := range after.Members {
					if m.ID == old.ID && m.Status == -1 {
						row.Verified = true
						row.Reason = i18n.T("server.directory.status_revocation_verified")
					}
				}
			}
			r.Rows = append(r.Rows, row)
		}
	}
	return r
}
