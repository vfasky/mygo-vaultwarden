// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
)

// operationPolicies is created only from an authenticated full /sync response.
// It is never exported, serialized, or constructed from caller-owned VaultData.
// Local organization quarantine must not filter these server membership rules.
type operationPolicies struct {
	scope                   Scope
	revision                string
	epoch                   uint64
	defaultURIMatch         int
	personalOwnership       bool
	singleOrganization      bool
	restrictedPersonal      map[int]bool
	restrictedOrganizations map[string]map[int]bool
	memberships             map[string]policyMembership
	ciphers                 []json.RawMessage
}

type policyMembership struct {
	ID          string          `json:"id"`
	MemberID    string          `json:"organizationUserId"`
	UserID      string          `json:"userId"`
	Type        *int            `json:"type"`
	Status      *int            `json:"status"`
	Enabled     *bool           `json:"enabled"`
	UsePolicies *bool           `json:"usePolicies"`
	Permissions map[string]bool `json:"permissions"`
}

type syncPolicy struct {
	ID             string          `json:"id"`
	OrganizationID string          `json:"organizationId"`
	Type           *int            `json:"type"`
	Enabled        *bool           `json:"enabled"`
	Data           json.RawMessage `json:"data"`
}

// parseOperationPolicies does not confer authority on its own. Only the private
// authenticated read below may install its result in the current operation.
func parseOperationPolicies(body []byte, scope Scope, email, wrapped string) (*operationPolicies, error) {
	if strictJSON(body) != nil {
		return nil, ErrProtocol
	}
	var data struct {
		Profile struct {
			ID, Email, Key string
			Organizations  []policyMembership
		}
		Ciphers     []json.RawMessage
		Policies    []syncPolicy
		PoliciesNew []syncPolicy
	}
	if len(body) == 0 || len(body) > maxResponse || json.Unmarshal(body, &data) != nil || data.Ciphers == nil || data.Policies == nil || data.PoliciesNew == nil || data.Profile.Organizations == nil {
		return nil, ErrProtocol
	}
	if data.Profile.ID != scope.Account || vaultcrypto.NormalizeEmail(data.Profile.Email) != email {
		return nil, ErrIdentity
	}
	if data.Profile.Key != wrapped || wrapped == "" {
		return nil, ErrExpired
	}
	if len(data.Profile.Organizations) > 1024 || len(data.Policies) > 32768 || len(data.PoliciesNew) > 32768 || len(data.Ciphers) > 100000 {
		return nil, ErrProtocol
	}
	orgs := map[string]policyMembership{}
	members := map[string]bool{}
	for _, o := range data.Profile.Organizations {
		if !validObjectID(o.ID) || !validObjectID(o.MemberID) || o.UserID != scope.Account || members[o.MemberID] {
			return nil, ErrIdentity
		}
		if _, exists := orgs[o.ID]; exists {
			return nil, ErrIdentity
		}
		if o.Type == nil || (*o.Type != 0 && *o.Type != 1 && *o.Type != 2 && *o.Type != 4) || o.Status == nil || (*o.Status < -1 || *o.Status > 2) || o.Enabled == nil || o.UsePolicies == nil || !*o.UsePolicies || o.Permissions == nil {
			return nil, ErrProtocol
		}
		// 1.37.4 does not implement arbitrary custom policy-management roles.
		canManage, hasManage := o.Permissions["managePolicies"]
		if !hasManage || canManage {
			return nil, ErrProtocol
		}
		members[o.MemberID], orgs[o.ID] = true, o
	}
	parse := func(rows []syncPolicy, accepted bool) (map[string]syncPolicy, error) {
		out := map[string]syncPolicy{}
		seen := map[string]map[int]bool{}
		for _, p := range rows {
			o, found := orgs[p.OrganizationID]
			if !found || !validObjectID(p.ID) {
				return nil, ErrIdentity
			}
			if p.Type == nil || p.Enabled == nil || len(p.Data) == 0 {
				return nil, ErrProtocol
			}
			if *o.Status != 2 && !(accepted && *o.Status == 1) {
				return nil, ErrIdentity
			}
			if _, exists := out[p.ID]; exists {
				return nil, ErrIdentity
			}
			if seen[o.ID] == nil {
				seen[o.ID] = map[int]bool{}
			}
			if seen[o.ID][*p.Type] {
				return nil, ErrProtocol
			}
			seen[o.ID][*p.Type] = true
			switch *p.Type {
			case 0, 1, 2, 3, 5, 6, 7, 8, 14, 15, 16, 20:
			default:
				return nil, ErrProtocol
			}
			out[p.ID] = p
		}
		return out, nil
	}
	confirmed, err := parse(data.Policies, false)
	if err != nil {
		return nil, err
	}
	newer, err := parse(data.PoliciesNew, true)
	if err != nil {
		return nil, err
	}
	// Both arrays are emitted by the same fixed server sync; confirmed entries
	// must agree. A missing counterpart is not permission to drop a restriction.
	for id, p := range newer {
		if *orgs[p.OrganizationID].Status != 2 {
			continue
		}
		q, found := confirmed[id]
		if !found || q.OrganizationID != p.OrganizationID || *q.Type != *p.Type || *q.Enabled != *p.Enabled || !rawJSONEqual(q.Data, p.Data) {
			return nil, ErrProtocol
		}
	}
	for id := range confirmed {
		if _, found := newer[id]; !found {
			return nil, ErrProtocol
		}
	}
	result := &operationPolicies{scope: scope, restrictedPersonal: map[int]bool{}, restrictedOrganizations: map[string]map[int]bool{}, memberships: orgs, ciphers: data.Ciphers}
	// Preserve wire order: fixed clients policiesByType$ -> getFirstPolicy does
	// not sort or combine URI defaults. Owners/admins can manage policies and
	// are exempt. Disabled organizations are not a role exemption.
	for _, p := range data.Policies {
		o := orgs[p.OrganizationID]
		if *p.Type != 16 || !*p.Enabled || *o.Type == 0 || *o.Type == 1 || *o.Status < 1 {
			continue
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(p.Data, &fields) == nil {
			var match float64 // JavaScript enum membership uses JSON Number semantics.
			if raw := fields["uriMatchDetection"]; len(raw) != 0 && string(raw) != "null" && json.Unmarshal(raw, &match) == nil && match >= 0 && match <= 5 && match == float64(int(match)) {
				result.defaultURIMatch = int(match)
			}
		}
		break // Invalid/null first policy falls back, not to a later policy.
	}
	for _, p := range confirmed {
		o := orgs[p.OrganizationID]
		if !*p.Enabled || !*o.UsePolicies {
			continue
		}
		// An organization being locally isolated or server-disabled must not turn
		// confirmed membership into a PersonalOwnership bypass (server helper uses
		// membership status and role). The sync endpoint still supplies its policy.
		switch *p.Type {
		case 3:
			if *o.Type != 0 && *o.Type != 1 {
				result.singleOrganization = true
			}
		case 5:
			if *o.Type != 0 && *o.Type != 1 {
				result.personalOwnership = true
			}
		case 15:
			kinds := []int{3} // fixed clients RestrictedItemTypesService null default
			if string(p.Data) != "null" {
				if json.Unmarshal(p.Data, &kinds) != nil || kinds == nil || len(kinds) > 8 {
					return nil, ErrProtocol
				}
			}
			seen := map[int]bool{}
			result.restrictedOrganizations[o.ID] = seen
			for _, kind := range kinds {
				if kind < 1 || kind > 8 || seen[kind] {
					return nil, ErrProtocol
				}
				seen[kind], result.restrictedPersonal[kind] = true, true
			}
		}
	}
	return result, nil
}

// restricts keeps personal union and each organization's own restrictions
// separate. PersonalOwnership applies to writes, never existing-item reads.
func (p *operationPolicies) restricts(orgID *string, kind int) bool {
	if orgID == nil || *orgID == "" {
		return p.restrictedPersonal[kind]
	}
	return p.restrictedOrganizations[*orgID][kind]
}

// organizationCipherPolicyGuardLocked applies only the destination's type policy.
// The policy read cannot grant collection access or lift local quarantine; those
// checks and the decrypted key remain owned by organizationVaultLocked.
func (s *Session) organizationCipherPolicyGuardLocked(ctx context.Context, data *organizationVault, orgID string, kind int, persist func(SessionCheckpoint) error, guard func() error) (func() error, error) {
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return nil, err
	}
	member, found := policies.memberships[orgID]
	if !found || *member.Status != 2 || !*member.Enabled {
		return nil, ErrPermission
	}
	matched := false
	for _, local := range data.organizations {
		if local.ID == orgID {
			if local.OrganizationUserID != member.MemberID || local.UserID != member.UserID || local.Type != *member.Type {
				return nil, ErrExpired
			}
			matched = true
		}
	}
	if !matched || data.keys[orgID] == nil {
		return nil, ErrPermission
	}
	if policies.restrictedOrganizations[orgID][kind] {
		return nil, fmt.Errorf(i18n.T("目标组织策略限制此项目类型，不能保存或共享：%w"), ErrPermission)
	}
	return func() error {
		if err := s.checkOperationPoliciesLocked(ctx, policies); err != nil {
			return err
		}
		if guard != nil {
			return guard()
		}
		return nil
	}, nil
}

// personalCipherStatePolicyLocked authorizes the exact server record for state
// changes. Caller-provided documents cannot disguise a restricted type or move a
// shared item into a personal-only route. Type 5 does not prohibit these actions.
func (s *Session) personalCipherStatePolicyLocked(ctx context.Context, ids []string, grant *ItemAuthorization, persist func(SessionCheckpoint) error) error {
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	found := make(map[string]bool, len(ids))
	for _, raw := range policies.ciphers {
		var meta struct {
			ID                 string
			Type               *int
			OrganizationID     *string
			Edit, ViewPassword *bool
			Reprompt           *int
		}
		if json.Unmarshal(raw, &meta) != nil {
			return ErrProtocol
		}
		if !wanted[meta.ID] {
			continue
		}
		if found[meta.ID] || meta.Type == nil || *meta.Type < 1 || *meta.Type > 8 {
			return ErrProtocol
		}
		if meta.Edit == nil || meta.ViewPassword == nil || meta.Reprompt == nil || *meta.Reprompt < 0 || *meta.Reprompt > 1 {
			return ErrProtocol
		}
		if meta.OrganizationID != nil || !*meta.Edit || !*meta.ViewPassword {
			return ErrPermission
		}
		if *meta.Reprompt != 0 && !s.validItemAuthorizationLocked(grant, CipherDocument{JSON: raw}) {
			return ErrPermission
		}
		if policies.restrictedPersonal[*meta.Type] {
			return fmt.Errorf(i18n.T("组织策略限制此项目类型，不能修改其状态：%w"), ErrPermission)
		}
		found[meta.ID] = true
	}
	if len(found) != len(wanted) {
		return ErrConflict
	}
	return s.checkOperationPoliciesLocked(ctx, policies)
}

func rawJSONEqual(a, b json.RawMessage) bool {
	var left, right any
	// Keep unknown large integers exact; do not round through float64.
	l, r := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	l.UseNumber()
	r.UseNumber()
	if l.Decode(&left) != nil || r.Decode(&right) != nil {
		return false
	}
	x, _ := json.Marshal(left)
	y, _ := json.Marshal(right)
	return string(x) == string(y)
}

func (s *Session) operationPoliciesLocked(ctx context.Context, persist func(SessionCheckpoint) error) (*operationPolicies, error) {
	if !s.itemSessionActiveLocked() {
		return nil, ErrExpired
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	if s.writePolicies != nil {
		if err := s.checkOperationPoliciesLocked(ctx, s.writePolicies); err != nil {
			return nil, err
		}
		return s.writePolicies, nil
	}
	status, body, err := s.authenticatedLocked(ctx, http.MethodGet, "/api/sync", "", "", persist)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if status != http.StatusOK {
		return nil, statusError(status)
	}
	scope := Scope{Server: s.client.base.String(), Account: s.account}
	policies, err := parseOperationPolicies(body, scope, s.email, s.wrapped)
	if err != nil {
		return nil, err
	}
	applyPendingPolicies(policies, s.pendingPolicyMutations)
	policies.revision, policies.epoch = s.authorizationRevision, s.authorizationEpoch
	if err := s.checkOperationPoliciesLocked(ctx, policies); err != nil {
		return nil, err
	}
	s.writePolicies = policies
	return policies, nil
}

func (s *Session) checkOperationPoliciesLocked(ctx context.Context, p *operationPolicies) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if !s.itemSessionActiveLocked() || p == nil || p.epoch != s.authorizationEpoch || p.revision != s.authorizationRevision {
		return ErrExpired
	}
	return s.requireScopeLocked(p.scope)
}

// personalCipherPolicyGuardLocked runs before encryption is dispatched and is
// composed with the item's existing reprompt guard. Only type 5 and 15 govern
// these personal save operations; they do not ban unrelated reads/deletions.
func (s *Session) personalCipherPolicyGuardLocked(ctx context.Context, kind int, persist func(SessionCheckpoint) error, guard func() error) (func() error, error) {
	policies, err := s.operationPoliciesLocked(ctx, persist)
	if err != nil {
		return nil, err
	}
	if policies.personalOwnership {
		return nil, fmt.Errorf(i18n.T("组织策略禁止保存到个人密码库，请选择允许的组织：%w"), ErrPermission)
	}
	if policies.restrictedPersonal[kind] {
		return nil, fmt.Errorf(i18n.T("组织策略限制此项目类型，不能保存到个人密码库：%w"), ErrPermission)
	}
	return func() error {
		if err := s.checkOperationPoliciesLocked(ctx, policies); err != nil {
			return err
		}
		if guard != nil {
			return guard()
		}
		return nil
	}, nil
}
