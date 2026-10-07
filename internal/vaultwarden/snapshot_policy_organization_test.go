// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/json"
	"errors"
	"testing"
)

// This fixture extends the authenticated organization receipt fixture with a
// complete type15 policy. It never installs policy by public revision binding.
func snapshotOrganizationFixture(t *testing.T) (*Session, *VaultData) {
	t.Helper()
	s, v, key, _ := organizationFixture(t, "https://snapshot.example.invalid")
	clear(key)
	v = changeOrganizationFixture(t, v, func(d map[string]any) {
		p := d["profile"].(map[string]any)
		p["email"], p["key"] = s.email, s.wrapped
		for _, field := range []string{"organizations", "organizationsNew"} {
			org := p[field].([]any)[0].(map[string]any)
			org["UsePolicies"] = true
			org["Permissions"] = map[string]any{"managePolicies": false}
		}
		policy := map[string]any{"id": "policy-1", "organizationId": "org-1", "type": 15, "enabled": true, "data": []int{1}}
		d["policies"], d["policiesNew"] = []any{policy}, []any{policy}
	})
	return s, v
}

func TestAuthenticatedSnapshotOrganizationAndQuarantinePolicy(t *testing.T) {
	s, v := snapshotOrganizationFixture(t)
	defer s.Close()
	if err := s.AcceptAuthenticatedSnapshot(v, "first"); err != nil {
		t.Fatal(err)
	}
	if !s.offlinePolicies.policies.restrictedPersonal[1] || !s.offlinePolicies.policies.restrictedOrganizations["org-1"][1] {
		t.Fatal("type15 scope lost")
	}
	v.QuarantinedOrganizations = []string{"org-1"}
	if err := s.ValidateAuthenticatedSnapshot(v, "first"); !errors.Is(err, ErrExpired) {
		t.Fatal("quarantine did not change hash", err)
	}
	if err := s.AcceptAuthenticatedSnapshot(v, "quarantined"); err != nil {
		t.Fatal(err)
	}
	if !s.offlinePolicies.policies.restrictedPersonal[1] {
		t.Fatal("local isolation removed server policy")
	}
	otherOrg := "other-org"
	if s.offlinePolicies.policies.restricts(&otherOrg, 1) {
		t.Fatal("organization inherited personal union")
	}
	// New profile rows are validated even when quarantine would otherwise skip
	// organization decryption. A failed receipt cannot retain old capabilities.
	bad := changeOrganizationFixture(t, v, func(d map[string]any) {
		d["profile"].(map[string]any)["organizationsNew"].([]any)[0].(map[string]any)["UserID"] = "other-account"
	})
	bad.QuarantinedOrganizations = []string{"org-1"}
	if err := s.AcceptAuthenticatedSnapshot(bad, "bad"); !errors.Is(err, ErrIdentity) {
		t.Fatal("isolated mixed identity accepted", err)
	}
	if err := s.ValidateAuthenticatedSnapshot(v, "quarantined"); !errors.Is(err, ErrExpired) {
		t.Fatal("failed receipt retained partial authority", err)
	}
	// Explicit authenticated recovery reparses the entire original server policy.
	v.QuarantinedOrganizations = nil
	if err := s.AcceptAuthenticatedSnapshot(v, "restored"); err != nil {
		t.Fatal(err)
	}
	if !s.offlinePolicies.policies.restrictedPersonal[1] {
		t.Fatal("restoration dropped policy")
	}
}

func TestOrganizationProjectionFiltersBeforeDecryptingCipher(t *testing.T) {
	s, v := snapshotOrganizationFixture(t)
	defer s.Close()
	v = changeOrganizationFixture(t, v, func(d map[string]any) {
		d["ciphers"].([]any)[0].(map[string]any)["name"] = "invalid-ciphertext"
	})
	policies, err := parseOperationPolicies(v.Sync, v.Scope, s.email, s.wrapped)
	if err != nil {
		t.Fatal(err)
	}
	result := SyncResult{Vault: v}
	if err := s.appendOrganizationCredentialsLocked(&result, policies); err != nil || len(result.Credentials) != 0 {
		t.Fatal("restricted organization ciphertext decrypted", err)
	}
	// Different organization policies do not hide this cipher or mask corruption.
	delete(policies.restrictedOrganizations, "org-1")
	if err := s.appendOrganizationCredentialsLocked(&result, policies); !errors.Is(err, ErrEncryption) {
		t.Fatal("cross-organization restriction applied", err)
	}
	if err := s.appendOrganizationCredentialsLocked(&result, nil); !errors.Is(err, ErrPermission) {
		t.Fatal("missing projection policy accepted", err)
	}
}

func TestAuthenticatedSnapshotMissingNewMembershipArray(t *testing.T) {
	s, v, saved, config := authenticatedSnapshotFixture(t)
	defer s.Close()
	defer clear(saved)
	var data map[string]any
	_ = json.Unmarshal(v.Sync, &data)
	delete(data["profile"].(map[string]any), "organizationsNew")
	v.Sync, _ = json.Marshal(data)
	if restored, err := RestoreSessionFromAuthenticatedSnapshot(saved, v.Scope, &config, v, "r"); !errors.Is(err, ErrProtocol) || restored != nil {
		t.Fatal("incomplete membership accepted", err)
	}
}
