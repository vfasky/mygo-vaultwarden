// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
)

type OrganizationDirectoryMember struct {
	Email      string `json:"email"`
	ExternalID string `json:"externalId"`
	Deleted    bool   `json:"deleted"`
}
type OrganizationDirectoryGroup struct {
	Name              string   `json:"name"`
	ExternalID        string   `json:"externalId"`
	MemberExternalIDs []string `json:"memberExternalIds"`
}
type OrganizationDirectoryImport struct {
	Members           []OrganizationDirectoryMember `json:"members"`
	Groups            []OrganizationDirectoryGroup  `json:"groups"`
	OverwriteExisting bool                          `json:"overwriteExisting"`
}

// The official endpoint supplies no per-item outcomes. Even HTTP 200 may skip a
// policy-disallowed restore or missing group member. Reconciliation reports a
// fresh authenticated management read; unmatched rows remain unknown.
type OrganizationDirectoryResult struct {
	RequestAccepted                     bool
	ReconcileRequired                   bool
	MemberExternalIDs, GroupExternalIDs []string
	Reconciliation                      *OrganizationDirectoryReconciliation
}

func validateOrganizationDirectory(input OrganizationDirectoryImport) error {
	if len(input.Members) > 2000 || len(input.Groups) > 2000 || len(input.Members)+len(input.Groups) == 0 {
		return ErrValidation
	}
	external, emails := map[string]bool{}, map[string]bool{}
	for _, m := range input.Members {
		email := strings.ToLower(strings.TrimSpace(m.Email))
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email || email != m.Email || len(email) > 320 || m.ExternalID == "" || len(m.ExternalID) > 1024 || external[m.ExternalID] || emails[email] {
			return ErrValidation
		}
		external[m.ExternalID], emails[email] = true, true
	}
	groups := map[string]bool{}
	for _, g := range input.Groups {
		if strings.TrimSpace(g.Name) == "" || len(g.Name) > 1024 || g.ExternalID == "" || len(g.ExternalID) > 1024 || groups[g.ExternalID] || len(g.MemberExternalIDs) > 2000 {
			return ErrValidation
		}
		groups[g.ExternalID] = true
		seen := map[string]bool{}
		for _, id := range g.MemberExternalIDs {
			if !external[id] || seen[id] {
				return ErrValidation
			}
			seen[id] = true
		}
	}
	return nil
}

// ImportOrganizationDirectory uses only Vaultwarden's registered Public import
// route. API secrets are borrowed and never persisted here. The caller supplies
// a separately confirmed overwrite choice; true removes absent external members.
// No retries and no user access token are sent to this organization-token route.
func (s *Session) ImportOrganizationDirectory(ctx context.Context, vault *VaultData, orgID string, secret []byte, input OrganizationDirectoryImport, confirmed bool, isolate func(SessionCheckpoint) error) (OrganizationDirectoryResult, error) {
	var result OrganizationDirectoryResult
	if !confirmed || !validObjectID(orgID) || len(secret) == 0 || len(secret) > 4096 {
		return result, ErrValidation
	}
	if err := validateOrganizationDirectory(input); err != nil {
		return result, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return result, err
	}
	defer data.close()
	owner := false
	var ownerOrganization Organization
	for _, org := range data.organizations {
		if org.ID == orgID && org.Type == 0 && (len(input.Groups) == 0 || org.UseGroups) {
			owner = true
			ownerOrganization = org
		}
	}
	if !owner {
		return result, ErrPermission
	}
	if ctx.Err() != nil {
		return result, ErrCancelled
	}
	if isolate == nil {
		return result, ErrCheckpoint
	}
	if err := s.checkpointLocked(isolate); err != nil {
		return result, ErrCheckpoint
	}
	guard := s.orgOperationGuardLocked()
	if err := guard(); err != nil {
		return result, err
	}
	before, err := s.organizationDirectorySnapshotLocked(ctx, ownerOrganization)
	if err != nil {
		return result, err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api.organization"}, "client_id": {"organization." + orgID}, "client_secret": {string(secret)}}
	status, response, err := s.client.request(ctx, http.MethodPost, "/identity/connect/token", "application/x-www-form-urlencoded", form.Encode(), "")
	if err != nil {
		return result, err
	}
	defer clear(response)
	if status != http.StatusOK {
		return result, statusError(status)
	}
	var token tokenReply
	if json.Unmarshal(response, &token) != nil || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn <= 0 {
		return result, ErrProtocol
	}
	if err := guard(); err != nil {
		return result, err
	}
	if input.Members == nil {
		input.Members = []OrganizationDirectoryMember{}
	}
	if input.Groups == nil {
		input.Groups = []OrganizationDirectoryGroup{}
	}
	body, err := json.Marshal(input)
	if err != nil {
		return result, ErrProtocol
	}
	for _, m := range input.Members {
		result.MemberExternalIDs = append(result.MemberExternalIDs, m.ExternalID)
	}
	for _, g := range input.Groups {
		result.GroupExternalIDs = append(result.GroupExternalIDs, g.ExternalID)
	}
	result.ReconcileRequired = true
	status, response, err = s.client.request(ctx, http.MethodPost, "/api/public/organization/import", "application/json", string(body), token.AccessToken)
	token.AccessToken = ""
	after, _ := s.organizationDirectorySnapshotLocked(ctx, ownerOrganization)
	result.Reconciliation = reconcileOrganizationDirectory(input, before, after)
	if err != nil {
		return result, &MutationUncertainError{Cause: err}
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return result, &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	if ctx.Err() != nil {
		return result, &MutationUncertainError{Cause: ErrCancelled}
	}
	result.RequestAccepted = true
	return result, nil
}
