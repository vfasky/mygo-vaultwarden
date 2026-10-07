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

func TestOrgCollectionAssignmentIsolationAndPartialFailure(t *testing.T) {
	var live json.RawMessage
	var calls atomic.Int32
	isolated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !isolated {
			t.Error("HTTP before isolation")
		}
		if r.URL.Path == "/api/sync" {
			data := organizationPolicySyncFixture()
			data["ciphers"] = []json.RawMessage{live}
			_ = json.NewEncoder(w).Encode(data)
			return
		}
		if r.URL.Path != "/api/ciphers/item-org/collections" || r.Method != "PUT" {
			t.Error("wrong route")
		}
		var body struct{ CollectionIDs []string }
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.CollectionIDs == nil || len(body.CollectionIDs) != 0 {
			t.Error("empty selection must be []")
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	s, v, _, doc := organizationFixture(t, server.URL)
	defer s.Close()
	live = doc.JSON
	err := s.AssignOrganizationCipherCollections(context.Background(), v, "org-1", "item-org", nil, nil, func(SessionCheckpoint) error { return ErrCheckpoint }, nil)
	if err != ErrCheckpoint || calls.Load() != 0 {
		t.Fatal("isolation failure sent HTTP", err)
	}
	s.Close()
	s, v, _, doc = organizationFixture(t, server.URL)
	defer s.Close()
	live = doc.JSON
	err = s.AssignOrganizationCipherCollections(context.Background(), v, "org-1", "item-org", nil, nil, func(SessionCheckpoint) error { isolated = true; return nil }, nil)
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) || calls.Load() != 2 || !isolated {
		t.Fatal("partial failure", err, calls.Load())
	}
}
