// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckpointPolicyContinuationRequiresSameContentReceipt(t *testing.T) {
	for _, scenario := range []string{"same", "content", "scope", "previous", "same-revision", "missing", "disk", "generic"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/identity/connect/token" {
					t.Error("unexpected request")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "rotated-access", "refresh_token": "rotated-refresh", "expires_in": 3600, "token_type": "Bearer"})
			}))
			defer server.Close()
			s, v, _ := protectedItemFixture(t, server.URL)
			grant, err := s.AuthorizePersonalItem(context.Background(), v, "local-revision", "item-1", []byte("test-master"))
			if err != nil {
				t.Fatal(err)
			}
			callback := func(c SessionCheckpoint) error {
				var saved savedSession
				if json.Unmarshal(c.Session, &saved) != nil || (scenario != "generic" && saved.RefreshToken != "rotated-refresh") {
					t.Fatal("token not checkpointed")
				}
				if scenario == "missing" {
					return nil
				}
				if scenario == "disk" {
					return errors.New("fixture disk failure")
				}
				copy := *v
				previous, revision := "local-revision", "checkpoint-2"
				switch scenario {
				case "content":
					copy.QuarantinedOrganizations = []string{"org-a"}
				case "scope":
					copy.Scope.Account = "other"
				case "previous":
					previous = "stale"
				case "same-revision":
					revision = previous
				}
				return c.AcceptAuthenticatedReceipt(&copy, previous, revision)
			}
			s.mu.Lock()
			if scenario == "generic" {
				err = s.checkpointLocked(callback)
			} else {
				err = s.refreshAndCheckpointLocked(context.Background(), callback)
			}
			s.mu.Unlock()
			if scenario == "same" {
				if err != nil || s.ValidateAuthenticatedSnapshot(v, "checkpoint-2") != nil {
					t.Fatal("same content did not continue", err)
				}
				if _, _, err = s.ReadPersonalCipherAuthorized(v, "item-1", grant); err != ErrPermission {
					t.Fatal("old item grant resurrected", err)
				}
				if _, err = s.AuthorizePersonalItem(context.Background(), v, "checkpoint-2", "item-1", []byte("test-master")); err != nil {
					t.Fatal("fresh grant", err)
				}
			} else if scenario == "generic" {
				if err != nil || s.ValidateAuthenticatedSnapshot(v, "checkpoint-2") == nil || s.ValidateAuthenticatedSnapshot(v, "local-revision") == nil {
					t.Fatal("generic isolation retained offline permission", err)
				}
			} else {
				if scenario != "missing" && err == nil {
					t.Fatal("bad receipt accepted")
				}
				if s.ValidateAuthenticatedSnapshot(v, "local-revision") == nil || s.ValidateAuthenticatedSnapshot(v, "checkpoint-2") == nil {
					t.Fatal("failure retained authority")
				}
			}
		})
	}
}

func TestSyncRecoveryCandidateCannotAuthorizeOfflineReads(t *testing.T) {
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sync" {
			t.Error("unexpected request")
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	body = v.Sync
	result, err := s.SyncWithCheckpoint(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(result.Session)
	if result.PasswordUnlock != nil {
		defer clear(result.PasswordUnlock.Key)
	}
	if err := s.ValidateOrganizationRecoveryCandidate(result, "org-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Organizations(result.Vault); err != ErrExpired {
		t.Fatal("unpublished sync granted offline read", err)
	}
	forged := result
	copyVault := *result.Vault
	copyVault.QuarantinedOrganizations = []string{"org-1"}
	forged.Vault = &copyVault
	if err := s.ValidateOrganizationRecoveryCandidate(forged, "org-1"); err != ErrExpired {
		t.Fatal("mutated candidate", err)
	}
	if err := s.AcceptAuthenticatedSnapshot(result.Vault, "published"); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateOrganizationRecoveryCandidate(result, "org-1"); err != ErrExpired {
		t.Fatal("old candidate epoch", err)
	}
	if _, _, err := s.Organizations(result.Vault); err != nil {
		t.Fatal("published read", err)
	}
}

func TestOfflineReadChainsApplyPolicyBeforeSecrets(t *testing.T) {
	s, v := snapshotOrganizationFixture(t)
	defer s.Close()
	personal, err := NewPersonalCipher(CipherFields{Type: 1, Name: "private", Login: map[string]any{"password": "secret"}}, s.key, s.account)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := documentObject(personal)
	object["id"], object["edit"], object["viewPassword"] = "personal", true, true
	personal.JSON, _ = json.Marshal(object)
	var body map[string]json.RawMessage
	_ = json.Unmarshal(v.Sync, &body)
	var docs []json.RawMessage
	_ = json.Unmarshal(body["ciphers"], &docs)
	docs = append(docs, personal.JSON)
	body["ciphers"], _ = json.Marshal(docs)
	v.Sync, _ = json.Marshal(body)
	if err = s.AcceptAuthenticatedSnapshot(v, "restricted"); err != nil {
		t.Fatal(err)
	}
	if entries, err := s.PersonalEntries(v); err != nil || len(entries) != 0 {
		t.Fatal("personal projection", err)
	}
	if entries, err := s.OrganizationEntries(v); err != nil || len(entries) != 0 {
		t.Fatal("organization projection", err)
	}
	if _, _, err = s.ReadPersonalCipher(v, "personal"); err != ErrPermission {
		t.Fatal("personal read", err)
	}
	if _, _, err = s.ReadOrganizationCipher(v, "item-org", nil); err != ErrPermission {
		t.Fatal("organization read", err)
	}
	if _, err = s.ExportPersonalBackup(context.Background(), v, []string{"personal"}, MyGoBackup); err != ErrPermission {
		t.Fatal("export", err)
	}
	if err = s.ChangePersonalCiphers(context.Background(), v.Scope, v, []string{"personal"}, CipherTrash, nil, nil); err != ErrPermission {
		t.Fatal("bulk", err)
	}
	if _, err = s.AuthorizePersonalItem(context.Background(), v, "restricted", "personal", []byte("fixture")); err != ErrPermission {
		t.Fatal("reprompt", err)
	}
	if err = s.WithPersonalSecret(v, "restricted", "personal", "password", nil, func(string, []byte, time.Time) error { t.Fatal("secret reached callback"); return nil }); err != ErrPermission {
		t.Fatal("secret", err)
	}
	s.RevokeItemAuthorizations()
	if _, err = s.PersonalFolders(v); err != ErrExpired {
		t.Fatal("folder without authority", err)
	}
	if _, _, err = s.Organizations(v); err != ErrExpired {
		t.Fatal("org metadata without authority", err)
	}
	if _, err = s.IsolatedOrganizations(v); err != ErrExpired {
		t.Fatal("isolated metadata without authority", err)
	}
}
