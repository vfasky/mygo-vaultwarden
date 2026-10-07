// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func orgEventQuery() OrganizationEventQuery {
	return OrganizationEventQuery{OrganizationID: "org-1", Start: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)}
}
func TestOrgEventsPagingAndRoles(t *testing.T) {
	var calls atomic.Int32
	query := orgEventQuery()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/api/organizations/org-1/users/member-other/events" || r.URL.Query().Get("start") == "" || r.URL.Query().Get("end") == "" {
			t.Error("wrong route", r.URL)
		}
		token := "2026-06-02T00:00:00Z"
		_ = json.NewEncoder(w).Encode(OrganizationEventPage{Data: []OrganizationEvent{{Type: 9999, Date: token, OrganizationID: &query.OrganizationID}}, ContinuationToken: &token})
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	query.MemberID = "member-other"
	if _, err := s.OrganizationEvents(context.Background(), v, query, nil); err != ErrPermission || calls.Load() != 0 {
		t.Fatal("member audit allowed", err)
	}
	v = changeOrganizationFixture(t, v, func(d map[string]any) {
		p := d["profile"].(map[string]any)
		for _, name := range []string{"organizations", "organizationsNew"} {
			p[name].([]any)[0].(map[string]any)["Type"] = 0
		}
	})
	installFixtureSnapshot(t, s, v, "revision-1")
	// A malformed envelope must not silently appear as an empty log.
	if _, err := s.OrganizationEvents(context.Background(), v, query, nil); err != ErrProtocol {
		t.Fatal("missing list envelope", err)
	}
}
func TestOrgEventsResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"valid", `{"object":"list","data":[{"type":9999,"date":"2026-06-02T00:00:00Z","organizationId":"org-1"}],"continuationToken":"2026-06-02T00:00:00Z"}`, nil},
		{"cross-org", `{"object":"list","data":[{"type":1107,"date":"2026-06-02T00:00:00Z","organizationId":"other"}]}`, ErrIdentity},
		{"null", `{"object":"list","data":null}`, ErrProtocol},
		{"bad-token", `{"object":"list","data":[],"continuationToken":"../../../"}`, ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
			defer server.Close()
			s, v, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			v = changeOrganizationFixture(t, v, func(d map[string]any) {
				p := d["profile"].(map[string]any)
				for _, name := range []string{"organizations", "organizationsNew"} {
					p[name].([]any)[0].(map[string]any)["Type"] = 1
				}
			})
			installFixtureSnapshot(t, s, v, "revision-1")
			page, err := s.OrganizationEvents(context.Background(), v, orgEventQuery(), nil)
			if err != tc.want {
				t.Fatal(err, tc.want)
			}
			if tc.want == nil && (len(page.Data) != 1 || page.Data[0].Type != 9999) {
				t.Fatal("unknown event discarded")
			}
		})
	}
}
func TestOrgEventPathsAndCollect(t *testing.T) {
	q := orgEventQuery()
	q.CipherID = "item-org"
	path, err := organizationEventPath(q)
	if err != nil || !strings.HasPrefix(path, "/api/ciphers/item-org/events?") {
		t.Fatal(path, err)
	}
	q.MemberID = "member-1"
	if _, err = organizationEventPath(q); err != ErrValidation {
		t.Fatal("mixed filters", err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/events/collect" {
			t.Error("wrong collect endpoint", r.URL)
		}
		var events []OrganizationClientEvent
		if json.NewDecoder(r.Body).Decode(&events) != nil || len(events) != 1 || events[0].Type != 1107 {
			t.Error("bad event body")
		}
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	event := OrganizationClientEvent{Type: 1107, Date: time.Now(), OrganizationID: "org-1", CipherID: "item-org"}
	if err := s.CollectOrganizationEvents(context.Background(), v, []OrganizationClientEvent{event}, nil); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []int{1100, 1500, 1600, 1007} {
		event.Type = kind
		if err := s.CollectOrganizationEvents(context.Background(), v, []OrganizationClientEvent{event}, nil); err != ErrValidation {
			t.Fatal("server event accepted", kind, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("invalid event dispatched")
	}
}
