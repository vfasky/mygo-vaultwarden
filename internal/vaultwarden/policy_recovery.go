// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"reflect"
	"strconv"
)

// PolicyRecoveryReview contains no credentials or vault secrets. It binds the
// explicitly displayed current policy and role, then requires another fresh sync.
type PolicyRecoveryReview struct {
	session              *Session
	sourceEpoch          uint64
	sourceDigest         [32]byte
	revision             string
	epoch, recoveryEpoch uint64
	validated            bool
	record               PendingPolicyMutation
	scope                Scope
	row                  policyRecord
	restoreOrganization  bool
	member               Organization
}

func (p *PolicyRecoveryReview) Clone() *PolicyRecoveryReview {
	if p == nil {
		return nil
	}
	q := *p
	q.row.Data = append(json.RawMessage(nil), p.row.Data...)
	if p.row.Type != nil {
		v := *p.row.Type
		q.row.Type = &v
	}
	if p.row.Enabled != nil {
		v := *p.row.Enabled
		q.row.Enabled = &v
	}
	return &q
}
func (p *PolicyRecoveryReview) Close() {
	if p != nil {
		*p = PolicyRecoveryReview{}
	}
}
func (p *PolicyRecoveryReview) Record() PendingPolicyMutation {
	if p == nil {
		return PendingPolicyMutation{}
	}
	return p.record
}
func (p *PolicyRecoveryReview) Enabled() bool {
	return p != nil && p.row.Enabled != nil && *p.row.Enabled
}
func (p *PolicyRecoveryReview) Summary() []string {
	if p == nil {
		return nil
	}
	def, _ := policyDefinition(p.record.PolicyType)
	role := i18n.T("policy.recovery.no_membership")
	if p.member.ID != "" {
		role = map[int]string{0: i18n.T("role.owner"), 1: i18n.T("role.admin"), 2: i18n.T("role.member"), 4: i18n.T("role.manager")}[p.member.Type]
	}
	rows := []string{def.Name, i18n.Tf("policy.recovery.current_role", role)}
	if !p.restoreOrganization {
		rows = append(rows, i18n.T("policy.recovery.quarantine_hint"))
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(p.row.Data, &fields) == nil {
		for _, f := range def.Fields {
			value := i18n.T("common.default")
			if v := fields[f.Key]; len(v) > 0 && string(v) != "null" {
				value = i18n.T("policy.value.server_extension")
				if f.Kind == "bool" {
					if string(v) == "true" {
						value = i18n.T("common.yes")
					} else if string(v) == "false" {
						value = i18n.T("common.no")
					}
				} else if f.Kind == "generator" {
					var text string
					if json.Unmarshal(v, &text) == nil {
						if text == "password" {
							value = i18n.T("common.password")
						} else if text == "passphrase" {
							value = i18n.T("policy.value.passphrase")
						}
					}
				} else if n, err := strconv.Atoi(string(v)); err == nil {
					value = strconv.Itoa(n)
					if f.Kind == "uri" && n >= 0 && n <= 5 {
						value = []string{i18n.T("urimatch.base_domain"), i18n.T("urimatch.host"), i18n.T("urimatch.starts_with"), i18n.T("urimatch.exact"), i18n.T("urimatch.regular_expression"), i18n.T("urimatch.never")}[n]
					}
				}
			}
			rows = append(rows, fmt.Sprintf("%s：%s", f.Label, value))
		}
	}
	if p.record.PolicyType == 15 {
		kinds := []int{3}
		if string(p.row.Data) != "null" {
			_ = json.Unmarshal(p.row.Data, &kinds)
		}
		for _, kind := range kinds {
			name := map[int]string{1: i18n.T("itemtype.login"), 2: i18n.T("itemtype.note"), 3: i18n.T("policy.restricted_item_types.card"), 4: i18n.T("itemtype.identity"), 5: i18n.T("itemtype.ssh_key"), 6: i18n.T("itemtype.bank"), 7: i18n.T("itemtype.license"), 8: i18n.T("itemtype.passport")}[kind]
			rows = append(rows, i18n.Tf("policy.recovery.restricted_item_type", name))
		}
	}
	return rows
}
func (p *PolicyRecoveryReview) CanRestoreOrganization() bool {
	return p != nil && p.restoreOrganization
}
func (s *Session) ReviewPendingPolicy(result SyncResult, record PendingPolicyMutation) (*PolicyRecoveryReview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateSyncCandidateLocked(result); err != nil {
		return nil, err
	}
	found := false
	for _, pending := range s.pendingPolicyMutations {
		if pending == record {
			found = true
		}
	}
	if !found {
		return nil, ErrExpired
	}
	var data struct {
		Policies []policyRecord
		Profile  struct{ OrganizationsNew []Organization }
	}
	if json.Unmarshal(result.Vault.Sync, &data) != nil {
		return nil, ErrProtocol
	}
	kind, enabled := record.PolicyType, false
	review := &PolicyRecoveryReview{session: s, sourceEpoch: s.authorizationEpoch, sourceDigest: sha256.Sum256(result.Vault.Sync), record: record, scope: result.Scope, row: policyRecord{OrganizationID: record.OrganizationID, Type: &kind, Enabled: &enabled, Data: json.RawMessage("null")}}
	for _, row := range data.Policies {
		if row.OrganizationID == record.OrganizationID && row.Type != nil && *row.Type == kind {
			review.row = row
		}
	}
	for _, org := range result.candidate.organizations {
		if org == record.OrganizationID {
			review.restoreOrganization = true
		}
	}
	for _, member := range data.Profile.OrganizationsNew {
		if member.ID == record.OrganizationID {
			review.member = member
		}
	}
	return review, nil
}

// BindPolicyRecoveryReview requires an already authenticated preview publication.
// It never installs snapshot authority or accepts a caller-supplied sync as proof.
func (s *Session) BindPolicyRecoveryReview(review *PolicyRecoveryReview, vault *VaultData, revision string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if review == nil || vault == nil || review.session != s || review.scope != vault.Scope || revision != s.authorizationRevision || review.revision != "" || s.authorizationEpoch != review.sourceEpoch+1 {
		return ErrExpired
	}
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return err
	}
	if !vault.HasPendingPolicy(review.record) || sha256.Sum256(vault.Sync) != review.sourceDigest {
		return ErrIdentity
	}
	review.revision = revision
	review.epoch = s.authorizationEpoch
	return nil
}

// SyncForPolicyRecovery consumes the currently displayed confirmation while
// holding the session lock, then obtains its own new network candidate.
func (s *Session) SyncForPolicyRecovery(ctx context.Context, vault *VaultData, review *PolicyRecoveryReview, persist func(SessionCheckpoint) error) (SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	defer finish()
	if review == nil || review.session != s || review.revision == "" || review.revision != s.authorizationRevision || review.epoch != s.authorizationEpoch || review.recoveryEpoch != 0 || review.validated {
		return SyncResult{}, ErrExpired
	}
	if _, err = s.snapshotPoliciesLocked(vault); err != nil {
		return SyncResult{}, err
	}
	if !vault.HasPendingPolicy(review.record) {
		return SyncResult{}, ErrIdentity
	}
	result, err := s.syncLocked(ctx, persist)
	if err == nil {
		review.recoveryEpoch = result.candidate.epoch
	}
	return result, err
}
func (s *Session) ValidatePolicyRecovery(result SyncResult, review *PolicyRecoveryReview) error {
	if review == nil || review.session != s || review.revision == "" || review.recoveryEpoch == 0 || result.candidate == nil || review.recoveryEpoch != result.candidate.epoch || review.validated {
		return ErrValidation
	}
	fresh, err := s.ReviewPendingPolicy(result, review.record)
	if err != nil {
		return err
	}
	defer fresh.Close()
	if fresh.record != review.record || fresh.scope != review.scope || fresh.restoreOrganization != review.restoreOrganization || !equalPolicyRecords([]policyRecord{fresh.row}, []policyRecord{review.row}) || !reflect.DeepEqual(fresh.member, review.member) {
		return ErrConflict
	}
	review.validated = true
	return nil
}
