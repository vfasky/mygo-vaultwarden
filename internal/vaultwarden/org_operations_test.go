// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOrgOperationsRoutesAndUncertainBatch(t *testing.T) {
	for _, action := range []CipherAction{CipherTrash, CipherRestore, CipherArchive, CipherUnarchive, CipherDeletePermanently} {
		t.Run(string(action), func(t *testing.T) {
			var live json.RawMessage
			var writes atomic.Int32
			fail := false
			method, path, _ := organizationStateRoute(action)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/sync" {
					data := organizationPolicySyncFixture()
					data["ciphers"] = []json.RawMessage{live}
					_ = json.NewEncoder(w).Encode(data)
					return
				}
				writes.Add(1)
				if r.Method != method || r.URL.Path != path {
					t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
				}
				var body struct{ IDs []string }
				if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.IDs) != 1 || body.IDs[0] != "item-org" {
					t.Error("IDs lost")
				}
				if fail {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			s, v, _, doc := organizationFixture(t, server.URL)
			defer s.Close()
			if action == CipherDeletePermanently {
				v = changeOrganizationFixture(t, v, func(d map[string]any) {
					d["ciphers"].([]any)[0].(map[string]any)["deletedDate"] = "2026-06-02T00:00:00Z"
				})
				installFixtureSnapshot(t, s, v, "revision-1")
				docs, _ := v.Documents(v.Scope)
				doc = docs[0]
			}
			live = doc.JSON
			result, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, action, nil, nil)
			if err != nil || !result.Applied || result.ReconcileRequired || writes.Load() != 1 {
				t.Fatalf("result %+v err %v writes %d", result, err, writes.Load())
			}
			fail = true
			result, err = s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, action, nil, nil)
			var uncertain *MutationUncertainError
			if !errors.As(err, &uncertain) || result.Applied || !result.ReconcileRequired || writes.Load() != 2 {
				t.Fatalf("uncertain %+v %v", result, err)
			}
		})
	}
}

func TestOrgOperationsRejectBeforeMutation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(map[string]any)
		liveOnly bool
	}{
		{"readonly", func(m map[string]any) { m["edit"] = false }, false},
		{"hidden", func(m map[string]any) { m["viewPassword"] = false }, false},
		{"reprompt", func(m map[string]any) { m["reprompt"] = 1 }, false},
		{"live-revocation", func(m map[string]any) { m["edit"] = false }, true},
		{"live-new-revision", func(m map[string]any) { m["revisionDate"] = "new" }, true},
		{"live-other-org", func(m map[string]any) { m["organizationId"] = "org-other" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var live json.RawMessage
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/sync" {
					data := organizationPolicySyncFixture()
					data["ciphers"] = []json.RawMessage{live}
					_ = json.NewEncoder(w).Encode(data)
					return
				}
				writes.Add(1)
			}))
			defer server.Close()
			s, v, _, doc := organizationFixture(t, server.URL)
			defer s.Close()
			m, _ := documentObject(doc)
			tc.change(m)
			live, _ = json.Marshal(m)
			if !tc.liveOnly {
				v = changeOrganizationFixture(t, v, func(d map[string]any) { d["ciphers"] = []json.RawMessage{live} })
				installFixtureSnapshot(t, s, v, "revision-1")
			}
			result, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, CipherTrash, nil, nil)
			if err == nil || result.Applied || writes.Load() != 0 {
				t.Fatalf("permission leak %+v %v", result, err)
			}
		})
	}
}

func TestOrgOperationsValidationAndCancellation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	for _, ids := range [][]string{nil, {"item-org", "item-org"}, {"../other"}} {
		if _, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", ids, CipherTrash, nil, nil); err != ErrValidation {
			t.Fatal(err)
		}
	}
	if _, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, CipherMove, nil, nil); err != ErrValidation {
		t.Fatal(err)
	}
	if _, err := s.ChangeOrganizationCiphers(context.Background(), v, "org-1", []string{"item-org"}, CipherDeletePermanently, nil, nil); err != ErrPermission {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ChangeOrganizationCiphers(ctx, v, "org-1", []string{"item-org"}, CipherTrash, nil, nil); err == nil {
		t.Fatal("cancel accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request dispatched")
	}
}
