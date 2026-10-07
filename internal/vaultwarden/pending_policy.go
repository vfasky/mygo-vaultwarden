// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

// PendingPolicyMutation is authenticated local write-ahead state, never server
// data. A regular sync, token checkpoint or organization restore must retain it.
type PendingPolicyMutation struct {
	OrganizationID string `json:"organizationId"`
	PolicyType     int    `json:"policyType"`
	MutationID     string `json:"mutationId"`
}

func (v *VaultData) validatePendingPolicies() error {
	if len(v.PendingPolicyMutations) > 1024 {
		return ErrProtocol
	}
	seenMutations := map[string]bool{}
	seen := map[string]bool{}
	for _, p := range v.PendingPolicyMutations {
		if !validObjectID(p.OrganizationID) || !validObjectID(p.MutationID) || seen[p.OrganizationID] || seenMutations[p.MutationID] {
			return ErrProtocol
		}
		if _, ok := policyDefinition(p.PolicyType); !ok {
			return ErrProtocol
		}
		seen[p.OrganizationID], seenMutations[p.MutationID] = true, true
	}
	return nil
}
func applyPendingPolicies(p *operationPolicies, pending []PendingPolicyMutation) {
	for _, entry := range pending {
		if entry.PolicyType == 15 {
			for kind := 1; kind <= 8; kind++ {
				p.restrictedPersonal[kind] = true
			}
		}
		if entry.PolicyType == 16 {
			// The unknown PUT may narrow the inherited rule. Until the dedicated
			// recovery clears this exact record, never fill an inherited URI.
			p.defaultURIMatch = 5
		}
		if entry.PolicyType == 3 {
			// An uncertain policy PUT may forbid creating another organization.
			// Keep this barrier until the dedicated policy recovery clears it.
			p.singleOrganization = true
		}
		if entry.PolicyType == 5 {
			p.personalOwnership = true
		}
	}
}
func (v *VaultData) HasPendingPolicy(record PendingPolicyMutation) bool {
	if v != nil {
		for _, p := range v.PendingPolicyMutations {
			if p == record {
				return true
			}
		}
	}
	return false
}
func (v *VaultData) PreservesPendingPolicies(prior *VaultData) bool {
	if prior != nil {
		for _, p := range prior.PendingPolicyMutations {
			if !v.HasPendingPolicy(p) {
				return false
			}
		}
	}
	return true
}
