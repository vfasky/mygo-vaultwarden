// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestPendingType15SurvivesUnknownResultFailedSyncAndSessionRestart(t *testing.T) {
	for _, mode := range []string{"unknown", "cancel-after-checkpoint"} {
		t.Run(mode, func(t *testing.T) {
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/sync" {
					w.WriteHeader(503)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/users") {
					writeMembers(w, memberRows())
					return
				}
				if r.Method == "PUT" {
					writes++
					w.WriteHeader(503)
					return
				}
				row := map[string]any{"id": "policy-1", "organizationId": "org-1", "type": 15, "enabled": false, "data": nil}
				if strings.HasSuffix(r.URL.Path, "/policies") {
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{row}})
				} else {
					_ = json.NewEncoder(w).Encode(row)
				}
			}))
			defer server.Close()
			s, v, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			v = acceptedGroupsVault(t, s, ownerVault(t, v))
			document, err := NewPersonalCipher(CipherFields{Type: 1, Name: "personal", Login: map[string]any{"username": "fixture", "password": "fixture-only"}}, s.key, s.account)
			if err != nil {
				t.Fatal(err)
			}
			object, _ := documentObject(document)
			object["id"] = "personal-1"
			object["edit"], object["viewPassword"] = true, true
			document.JSON, _ = json.Marshal(object)
			var data map[string]json.RawMessage
			_ = json.Unmarshal(v.Sync, &data)
			var ciphers []json.RawMessage
			_ = json.Unmarshal(data["ciphers"], &ciphers)
			data["ciphers"], _ = json.Marshal(append(ciphers, document.JSON))
			v.Sync, _ = json.Marshal(data)
			if err = s.AcceptAuthenticatedSnapshot(v, "before"); err != nil {
				t.Fatal(err)
			}
			if _, _, err = s.ReadPersonalCipher(v, "personal-1"); err != nil {
				t.Fatal(err)
			}
			draft, err := s.OrganizationPolicy(context.Background(), v, "org-1", 15, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer draft.Close()
			draft.Enabled = true
			isolated := *v
			isolated.Version = 2
			isolated.PendingPolicyMutations = []PendingPolicyMutation{draft.PendingMutation()}
			isolated.QuarantinedOrganizations = []string{"org-1"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var saved []byte
			err = s.SaveOrganizationPolicy(ctx, v, draft, draft.Confirm(), func(cp SessionCheckpoint) error {
				saved = append([]byte(nil), cp.Session...)
				if mode == "cancel-after-checkpoint" {
					cancel()
				}
				return nil
			}, nil)
			defer clear(saved)
			if err == nil {
				t.Fatal("unknown/cancel hidden")
			}
			want := 1
			if mode != "unknown" {
				want = 0
			}
			if writes != want {
				t.Fatal(writes, want)
			}
			if err = s.AcceptAuthenticatedSnapshot(&isolated, "isolated"); err != nil {
				t.Fatal(err)
			}
			if _, _, err = s.ReadPersonalCipher(&isolated, "personal-1"); !errors.Is(err, ErrPermission) {
				t.Fatal("pending read", err)
			}
			if _, err = s.Sync(context.Background()); err == nil {
				t.Fatal("failed sync")
			}
			if _, _, err = s.ReadPersonalCipher(&isolated, "personal-1"); err == nil {
				t.Fatal("sync failure restored read")
			}
			config := s.passwordUnlock.Config
			s.Close()
			reopened, err := RestoreSessionFromAuthenticatedSnapshot(saved, v.Scope, &config, &isolated, "reopened")
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if _, _, err = reopened.ReadPersonalCipher(&isolated, "personal-1"); !errors.Is(err, ErrPermission) {
				t.Fatal("restart restored read", err)
			}
			if reopened.refresh != "refresh-old" || len(reopened.key) != 64 {
				t.Fatal("session lost")
			}
		})
	}
}

func TestPolicyNontransactionalRevocationFailureRetainsBarrier(t *testing.T) {
	for _, kind := range []int{0, 3} {
		t.Run(strconv.Itoa(kind), func(t *testing.T) {
			checkpointed, writes, revocations := false, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/users") {
					writeMembers(w, memberRows())
					return
				}
				if r.Method == "PUT" {
					writes++
					if !checkpointed {
						t.Error("revocation before persistence")
					}
					revocations++
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				row := map[string]any{"id": "policy-1", "organizationId": "org-1", "type": kind, "enabled": false, "data": nil}
				if strings.HasSuffix(r.URL.Path, "/policies") {
					_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{row}})
				} else {
					_ = json.NewEncoder(w).Encode(row)
				}
			}))
			defer server.Close()
			s, v, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			v = acceptedGroupsVault(t, s, ownerVault(t, v))
			d, err := s.OrganizationPolicy(context.Background(), v, "org-1", kind, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.Enabled = true
			consent := d.Confirm()
			defer consent.Close()
			err = s.SaveOrganizationPolicy(context.Background(), v, d, consent, func(SessionCheckpoint) error { checkpointed = true; return nil }, nil)
			var uncertain *MutationUncertainError
			if !errors.As(err, &uncertain) || writes != 1 || revocations != 1 || len(s.pendingPolicyMutations) != 1 {
				t.Fatal("partial result hidden", err, writes, revocations)
			}
			if err = s.SaveOrganizationPolicy(context.Background(), v, d, consent, func(SessionCheckpoint) error { return nil }, nil); err != ErrValidation || writes != 1 {
				t.Fatal("retried partial policy")
			}
			if s.ValidateAuthenticatedSnapshot(v, s.authorizationRevision) == nil {
				t.Fatal("old offline authorization survived")
			}
		})
	}
}
