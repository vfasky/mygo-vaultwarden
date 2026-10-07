// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestAttachmentUploadPreflightBarriers(t *testing.T) {
	for _, scenario := range []string{"readonly", "hidden", "reprompt", "deleted", "quarantine", "pending", "wrong-scope", "public-vault", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writes.Add(1); w.WriteHeader(500) }))
			defer server.Close()
			s, vault, _, doc := organizationFixture(t, server.URL)
			defer s.Close()
			object, _ := documentObject(doc)
			switch scenario {
			case "readonly":
				object["edit"] = false
			case "hidden":
				object["viewPassword"] = false
			case "reprompt":
				object["reprompt"] = 1
			case "deleted":
				object["deletedDate"] = "2026-07-01T00:00:00Z"
			case "quarantine":
				vault.QuarantinedOrganizations = []string{"org-1"}
			case "pending":
				vault.QuarantinedOrganizations = []string{"org-1"}
				vault.Version = 2
				vault.PendingPolicyMutations = []PendingPolicyMutation{{OrganizationID: "org-1", PolicyType: 15, MutationID: "pending-attachment"}}
			}
			doc.JSON, _ = json.Marshal(object)
			var raw map[string]json.RawMessage
			_ = json.Unmarshal(vault.Sync, &raw)
			raw["ciphers"], _ = json.Marshal([]json.RawMessage{doc.JSON})
			vault.Sync, _ = json.Marshal(raw)
			installFixtureSnapshot(t, s, vault, "attachment-revision")
			if scenario == "wrong-scope" {
				vault.Scope.Account = "other"
			}
			if scenario == "public-vault" {
				vault.Sync = append(vault.Sync, ' ')
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel" {
				cancel()
			}
			file, err := os.CreateTemp(t.TempDir(), "input-")
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.UploadAttachment(ctx, vault, "item-org", "fixture.txt", file, nil, nil)
			if err == nil || result.MetadataCreated || writes.Load() != 0 {
				t.Fatal("barrier bypass", result, err, writes.Load())
			}
			if _, err := file.Stat(); err == nil {
				t.Fatal("input ownership not closed")
			}
		})
	}
}

func TestAttachmentRefreshCheckpointAndGETRetryGuard(t *testing.T) {
	for _, scenario := range []string{"missing-callback", "failed-checkpoint", "cancel-checkpoint", "retry-guard"} {
		t.Run(scenario, func(t *testing.T) {
			var requests, refresh atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/identity/connect/token" {
					refresh.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"})
					return
				}
				requests.Add(1)
				w.WriteHeader(401)
			}))
			defer server.Close()
			s, vault, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			diskFailure := errors.New("fixture checkpoint failed")
			var persist func(SessionCheckpoint) error
			switch scenario {
			case "failed-checkpoint":
				persist = func(SessionCheckpoint) error { return diskFailure }
			case "cancel-checkpoint":
				persist = func(SessionCheckpoint) error { cancel(); return nil }
			case "retry-guard":
				persist = func(SessionCheckpoint) error { return nil }
			}
			if scenario == "retry-guard" {
				// The first authorized GET gets 401; checkpoint revokes the prior epoch.
				// Guard must run again before a credentialed retry of attachment metadata.
				epoch := s.authorizationEpoch
				guard := func() error {
					if epoch != s.authorizationEpoch {
						return ErrExpired
					}
					return nil
				}
				_, _, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/ciphers/item-org/attachment/id", "", "", persist, guard)
				if !errors.Is(err, ErrExpired) || requests.Load() != 1 || refresh.Load() != 1 {
					t.Fatal("stale GET retried", err, requests.Load(), refresh.Load())
				}
				return
			}
			s.expires = time.Now()
			file, err := os.CreateTemp(t.TempDir(), "input-")
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.UploadAttachment(ctx, vault, "item-org", "fixture.txt", file, nil, persist)
			if err == nil || result.MetadataCreated || requests.Load() != 0 {
				t.Fatal("checkpoint bypass", result, err)
			}
			expectedRefresh := int32(1)
			if scenario == "missing-callback" {
				expectedRefresh = 0
			}
			if refresh.Load() != expectedRefresh {
				t.Fatal("unexpected refresh count", refresh.Load())
			}
			if scenario == "failed-checkpoint" && !errors.Is(err, diskFailure) {
				t.Fatal("lost checkpoint error", err)
			}
		})
	}
}

func TestAttachmentCloseCancelsAuthorizedTransfer(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" {
			close(entered)
			<-release
			w.WriteHeader(200)
			return
		}
		writes.Add(1)
		w.WriteHeader(500)
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	file, err := os.CreateTemp(t.TempDir(), "input-")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.UploadAttachment(context.Background(), vault, "item-org", "fixture.txt", file, nil, nil)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("operation did not start")
	}
	s.Close()
	close(release)
	select {
	case err := <-done:
		if err == nil || writes.Load() != 0 {
			t.Fatal("close allowed upload", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("input not closed after lock")
	}
}
