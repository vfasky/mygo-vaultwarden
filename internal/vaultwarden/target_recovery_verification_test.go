// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func freshTargetFixture(t *testing.T, providers []int, remembered string) (*Session, *TargetRecoveryInspection, RecoveryDispatch) {
	t.Helper()
	original, vault := accountFixture(t, func(w http.ResponseWriter, r *http.Request, owner *Session, _ *VaultData) {
		switch r.URL.Path {
		case "/api/version":
			json.NewEncoder(w).Encode("1.37.4")
		case "/api/config":
			json.NewEncoder(w).Encode(map[string]any{"gitHash": rotationGit1374, "server": map[string]string{"name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden"}})
		case "/identity/accounts/prelogin":
			json.NewEncoder(w).Encode(owner.passwordUnlock.Config.KDF)
		case "/identity/connect/token":
			r.ParseForm()
			master, err := DeriveMaster(accountTestPassword, owner.email, owner.passwordUnlock.Config.KDF)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			defer clear(master)
			if r.Form.Get("grant_type") != "password" || r.Form.Get("username") != owner.email || r.Form.Get("password") != AuthorizationHash(master, accountTestPassword) {
				t.Error("not a fresh password grant")
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh-target-access", "refresh_token": "fresh-target-refresh", "expires_in": 3600, "token_type": "Bearer", "key": owner.wrapped})
		case "/api/two-factor":
			rows := []any{}
			for _, provider := range providers {
				rows = append(rows, map[string]any{"type": provider, "enabled": true, "object": "twoFactorProvider"})
			}
			json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": rows})
		default:
			t.Error("unexpected route", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	client, err := NewClient(vault.Scope.Server, "fresh-target-test-device")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.LoginMFA(context.Background(), original.email, accountTestPassword, remembered, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := result.Session
	t.Cleanup(s.Close)
	p, err := s.InspectFreshTargetRecovery(context.Background())
	if remembered != "" {
		if err == nil || p != nil {
			t.Fatal("remembered grant minted fresh recovery proof")
		}
		return s, nil, RecoveryDispatch{}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	expectation, err := recoveryExpectation("administrator-recovery", original.key, original.wrapped, true, true)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := RecoveryDispatch{OperationID: strings.Repeat("a", 32), Actor: Scope{Server: vault.Scope.Server, Account: "administrator"}, Target: vault.Scope, Kind: "administrator-recovery", ResourceID: "member-a", OrganizationID: "org-a", MembershipID: "member-a", PreviousRevision: "prepared-actor-revision", AuthorizationEpoch: 1, RequireTargetLogin: true, Verification: expectation}
	return s, p, dispatch
}
func verifyTargetFixture(s *Session, p *TargetRecoveryInspection, d RecoveryDispatch, origin TargetRecoveryOriginalResult) (TargetRecoveryEvidence, error) {
	raw, _ := json.Marshal(d)
	return s.VerifyTargetRecovery(p, d, origin, recoveryWitness(raw), d.OperationID)
}
func TestTargetRecoveryObservedEffectsAndNoDispatchMatrix(t *testing.T) {
	for _, test := range []struct {
		name, phase                               string
		providers                                 []int
		password, mfa, takeover, newWrapper, pass bool
	}{
		{name: "both-confirmed", phase: "confirmed", password: true, mfa: true, pass: true},
		{name: "password-only-preserves-mfa", phase: "unknown", providers: []int{0}, password: true, pass: true},
		{name: "mfa-only", phase: "unknown", mfa: true, pass: true},
		{name: "confirmed-email-fallback", phase: "confirmed", providers: []int{1}, password: true, mfa: true, pass: true},
		{name: "unknown-old-email", phase: "unknown", providers: []int{1}, password: true, mfa: true},
		{name: "missing-origin-old-email", providers: []int{1}, password: true, mfa: true},
		{name: "confirmed-other-provider", phase: "confirmed", providers: []int{0, 1}, password: true, mfa: true},
		{name: "takeover-empty", phase: "confirmed", password: true, mfa: true, takeover: true, pass: true},
		{name: "takeover-email-not-exempt", phase: "confirmed", providers: []int{1}, password: true, mfa: true, takeover: true},
		{name: "nondispatch-future-wrapper-absent-mfa-retained", phase: "not-dispatched", providers: []int{0, 1}, password: true, mfa: true, newWrapper: true, pass: true},
		{name: "unknown-future-wrapper-absent", phase: "unknown", password: true, mfa: true, newWrapper: true},
		{name: "confirmed-future-wrapper-absent", phase: "confirmed", password: true, mfa: true, newWrapper: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, p, d := freshTargetFixture(t, test.providers, "")
			d.Verification.ResetPassword, d.Verification.ResetMFA = test.password, test.mfa
			if !test.password {
				d.Verification.ExpectedMasterWrapperSHA256 = ""
			}
			if test.newWrapper {
				d.Verification.ExpectedMasterWrapperSHA256 = recoveryWitness([]byte("this request was never sent"))
			}
			if test.takeover {
				d.Kind = "emergency-takeover"
				d.EmergencyType = 1
				d.CounterpartyID = d.Target.Account
				d.Verification.RemoveNonOwnerMemberships = true
			}
			origin := TargetRecoveryOriginalResult{}
			if test.phase != "" {
				origin = TargetRecoveryOriginalResult{1, test.phase}
			}
			evidence, err := verifyTargetFixture(s, p, d, origin)
			if (err == nil) != test.pass {
				t.Fatalf("pass=%v err=%v", test.pass, err)
			}
			if !test.pass {
				return
			}
			if evidence.Kind == TargetEvidenceDiscovery || evidence.AuthenticationEpoch == 0 {
				t.Fatal("discovery/empty proof resolved operation")
			}
			if test.phase == "not-dispatched" && evidence.Kind != TargetEvidenceNoDispatch {
				t.Fatal("nondispatch misreported as remote execution")
			}
			if test.name == "confirmed-email-fallback" && !strings.Contains(strings.Join(evidence.Notes, " "), "Email回退仍启用") {
				t.Fatal("fallback status hidden")
			}
		})
	}
}
func TestTargetRecoveryRejectsMaterialMutationAndWrongBinding(t *testing.T) {
	for _, mode := range []string{"credentials", "unlock-config", "scope", "session", "vault", "legacy", "version", "illegal-flags", "key", "operation", "summary", "confirmation", "origin-version", "origin-phase", "deadline", "ordinary-adoption"} {
		t.Run(mode, func(t *testing.T) {
			s, p, d := freshTargetFixture(t, nil, "")
			origin := TargetRecoveryOriginalResult{1, "confirmed"}
			switch mode {
			case "credentials":
				p.Fresh.Credentials = append(p.Fresh.Credentials, Credential{})
			case "unlock-config":
				p.Fresh.PasswordUnlock.Config.Email = "other@example.invalid"
			case "scope":
				p.Fresh.Scope.Account = "other-account"
			case "session":
				p.Fresh.Session = append(p.Fresh.Session, ' ')
			case "vault":
				p.Fresh.Vault.QuarantinedOrganizations = append(p.Fresh.Vault.QuarantinedOrganizations, "forged-isolation")
			case "legacy":
				d.Verification = RecoveryVerificationExpectation{}
			case "version":
				d.Verification.Version = 2
			case "illegal-flags":
				d.Verification.RemoveNonOwnerMemberships = true
			case "key":
				expectation := d.Verification
				expectation.ExpectedUserKeySHA256 = strings.Repeat("0", 64)
				d.Verification = expectation
			case "operation":
				d.OperationID = strings.Repeat("z", 32)
			case "origin-version":
				origin.Version = 2
			case "origin-phase":
				origin.Phase = "prepared"
			case "deadline":
				s.freshRecoveryDeadline = time.Now().Add(-time.Second)
				p.deadline = s.freshRecoveryDeadline
			case "ordinary-adoption":
				if err := s.AcceptAuthenticatedSnapshot(p.Fresh.Vault, "ordinary"); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(d)
			hash, confirmation := recoveryWitness(raw), d.OperationID
			if mode == "summary" {
				hash = strings.Repeat("0", 64)
			}
			if mode == "confirmation" {
				confirmation = "confirmed"
			}
			if _, err := s.VerifyTargetRecovery(p, d, origin, hash, confirmation); err == nil {
				t.Fatal("forged/stale verification accepted")
			}
		})
	}
}
func TestTargetRecoveryFreshLoginAndDiscoveryAreDistinct(t *testing.T) {
	freshTargetFixture(t, nil, "previous-remembered-token")
	s, p, d := freshTargetFixture(t, nil, "")
	discovery, err := s.TargetRecoveryDiscoveryEvidence(p, strings.Repeat("b", 32))
	if err != nil || discovery.Kind != TargetEvidenceDiscovery {
		t.Fatal(err)
	}
	effects, err := verifyTargetFixture(s, p, d, TargetRecoveryOriginalResult{1, "confirmed"})
	if err != nil {
		t.Fatal(err)
	}
	if effects.ConfirmationHash == discovery.ConfirmationHash || effects.MFAHash == discovery.MFAHash || effects.KeyHash == discovery.KeyHash {
		t.Fatal("inspection facts passed off as effect verification")
	}
}
