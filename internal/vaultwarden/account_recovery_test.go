// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdministratorRecoveryRolesCryptoAndChangedDetails(t *testing.T) {
	for _, mode := range []string{"owner", "admin-member", "admin-owner", "member", "custom", "wrong-public", "cross-member", "changed-details", "partial", "barrier"} {
		t.Run(mode, func(t *testing.T) {
			actorRole, targetRole := 0, 2
			if strings.HasPrefix(mode, "admin-") {
				actorRole = 1
			}
			if mode == "admin-owner" {
				targetRole = 0
			}
			if mode == "member" {
				actorRole = 2
			}
			if mode == "custom" {
				actorRole = 4
			}
			var pair organizationKeyPair
			var resetKey string
			changed := false
			writes := 0
			targetKey := bytes.Repeat([]byte{93}, 64)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/version":
					json.NewEncoder(w).Encode("1.37.4")
				case "/api/config":
					json.NewEncoder(w).Encode(map[string]any{"gitHash": rotationGit1374, "server": map[string]string{"name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden"}})
				case "/api/organizations/org-1/users":
					writeMembers(w, []OrganizationMember{{ID: "member-1", UserID: "account-a", Email: "owner@example.invalid", Type: actorRole, Status: 2}, {ID: "member-2", UserID: "account-b", Email: "member@example.invalid", Type: targetRole, Status: 2}})
				case "/api/organizations/org-1/users/member-2/reset-password-details":
					id := "member-2"
					if mode == "cross-member" {
						id = "other-member"
					}
					wrapper := resetKey
					if changed {
						wrapper = "3.changed"
					}
					_ = json.NewEncoder(w).Encode(accountRecoveryDetails{Object: "organizationUserResetPasswordDetails", OrganizationUserID: id, KDF: 0, Iterations: 100000, ResetPasswordKey: wrapper, EncryptedPrivateKey: pair.EncryptedPrivateKey})
				case "/api/organizations/org-1/public-key":
					_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": pair.PublicKey})
				case "/api/organizations/org-1/policies/master-password":
					_, _ = w.Write([]byte(`{"organizationId":"org-1","type":1,"enabled":true,"data":{"minLength":12,"requireNumbers":true}}`))
				case "/api/organizations/org-1/users/member-2/recover-account":
					writes++
					var request struct {
						Key, NewMasterPasswordHash          string
						ResetMasterPassword, ResetTwoFactor bool
					}
					_ = json.NewDecoder(r.Body).Decode(&request)
					master, _ := DeriveMaster([]byte("New-recovered-password-92!"), "member@example.invalid", KDF{Type: 0, Iterations: 100000})
					defer clear(master)
					stretched, _ := StretchMaster(master)
					defer clear(stretched)
					key, err := DecryptString(request.Key, stretched)
					defer clear(key)
					if err != nil || !bytes.Equal(key, targetKey) || request.NewMasterPasswordHash != AuthorizationHash(master, []byte("New-recovered-password-92!")) || !request.ResetMasterPassword || !request.ResetTwoFactor {
						t.Error("wrong password/user key/KDF flags", err)
					}
					if mode == "partial" {
						w.WriteHeader(503)
					}
				default:
					t.Error("unexpected route", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			s, v, orgKey, _ := organizationFixture(t, server.URL)
			defer s.Close()
			v = acceptedOwnerVault(t, s, v)
			var root map[string]any
			_ = json.Unmarshal(v.Sync, &root)
			profile := root["profile"].(map[string]any)
			for _, field := range []string{"organizations", "organizationsNew"} {
				for _, row := range profile[field].([]any) {
					row.(map[string]any)["type"] = actorRole
				}
			}
			v.Sync, _ = json.Marshal(root)
			installFixtureSnapshot(t, s, v, "recovery-revision")
			var err error
			pair, err = makeOrganizationKeyPair(orgKey)
			if err != nil {
				t.Fatal(err)
			}
			resetKey, err = recoveryWrapUserKey(pair.PublicKey, targetKey)
			if err != nil {
				t.Fatal(err)
			}
			trusted := pair.PublicKey
			if mode == "wrong-public" {
				trusted = "wrong"
			}
			p, err := s.PrepareAdministratorRecovery(context.Background(), v, "org-1", "member-2", trusted, []byte("New-recovered-password-92!"), true, true, nil)
			switch mode {
			case "admin-owner", "member", "custom", "wrong-public", "cross-member":
				if err == nil || writes != 0 {
					t.Fatal("permission/identity bypass", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if mode == "changed-details" {
				changed = true
			}
			result, err := s.CommitRecoveryOperation(context.Background(), p, p.ConfirmationText(), nil, func(d RecoveryDispatch) error {
				if d.Target.Account != "account-b" || d.Actor.Account != "account-a" || d.OrganizationID != "org-1" || d.MembershipID != "member-2" || !d.RequireTargetLogin {
					t.Error("target confused with actor")
				}
				if mode == "barrier" {
					return ErrConflict
				}
				return nil
			})
			switch mode {
			case "changed-details", "barrier":
				if err == nil || writes != 0 {
					t.Fatal("guard failure", err)
				}
			case "partial":
				if err == nil || !result.Unknown || writes != 1 {
					t.Fatal(result, err)
				}
			default:
				if err != nil || !result.Confirmed || writes != 1 {
					t.Fatal(result, err)
				}
			}
			if s.closed || len(s.key) != 64 {
				t.Fatal("administrator incorrectly logged out as target")
			}
		})
	}
}
func TestRecoveryPasswordKDFAndPolicy(t *testing.T) {
	for _, kdf := range []KDF{{Type: 0, Iterations: 100000}, {Type: 1, Iterations: 2, Memory: 16, Parallelism: 1}} {
		key := bytes.Repeat([]byte{18}, 64)
		password := []byte("Valid-new-password-572!")
		hash, wrapped, err := recoveryPasswordPayload(context.Background(), password, "target@example.invalid", kdf, key, AccountPasswordPolicy{RequireNumbers: true, RequireSpecial: true})
		if err != nil || hash == "" {
			t.Fatal(err)
		}
		master, _ := DeriveMaster(password, "target@example.invalid", kdf)
		defer clear(master)
		stretched, _ := StretchMaster(master)
		defer clear(stretched)
		decoded, err := DecryptString(wrapped, stretched)
		defer clear(decoded)
		if err != nil || !bytes.Equal(decoded, key) {
			t.Fatal("wrong rewrap", err)
		}
	}
	if _, _, err := recoveryPasswordPayload(context.Background(), []byte("short"), "target@example.invalid", KDF{Type: 0, Iterations: 100000}, make([]byte, 64), AccountPasswordPolicy{}); err == nil {
		t.Fatal("short password")
	}
}
