// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckpointCannotBeBypassedBySyncWithoutCallback(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	defer session.Close()
	session.checkpointPending = true
	if _, err := session.Sync(context.Background()); err != ErrCheckpoint {
		t.Fatalf("got %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("pending durable checkpoint bypassed")
	}
	session.checkpointPending = false
	session.expires = time.Time{}
	if _, err := session.Sync(context.Background()); err != ErrCheckpoint {
		t.Fatalf("got %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("token rotated without durable checkpoint hook")
	}
}

func TestSyncStatusErrorsDoNotExposeServerBody(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{{400, ErrValidation}, {403, ErrPermission}, {404, ErrNotFound}, {409, ErrConflict}, {412, ErrConflict}, {422, ErrValidation}, {429, ErrRateLimited}, {500, ErrNetwork}} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("secret server error token"))
			}))
			defer server.Close()
			session, _ := resumableFixture(t, server.URL)
			defer session.Close()
			if _, err := session.Sync(context.Background()); !errors.Is(err, tc.want) {
				t.Fatalf("got %v; want %v", err, tc.want)
			}
		})
	}
}

func TestCloseCancelsInFlightSync(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	done := make(chan error, 1)
	go func() { _, err := session.Sync(context.Background()); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	closed := make(chan struct{})
	go func() { session.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel request")
	}
	if err := <-done; err != ErrCancelled {
		t.Fatalf("got %v", err)
	}
	if _, err := session.Sync(context.Background()); err != ErrExpired {
		t.Fatalf("closed session revived: %v", err)
	}
}

func TestAuthenticatedMutationTransportFailureIsUncertain(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	defer session.Close()
	_, _, err := session.authenticatedLocked(context.Background(), http.MethodPost, "/api/ciphers", "application/json", "{}", nil)
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) || !errors.Is(err, ErrNetwork) || requests.Load() != 1 {
		t.Fatalf("lost uncertain outcome or retried write: %v (%d requests)", err, requests.Load())
	}
}

func TestAuthenticatedMutationNeverRetries401(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(401) }))
	defer server.Close()
	session, _ := resumableFixture(t, server.URL)
	defer session.Close()
	status, _, err := session.authenticatedLocked(context.Background(), http.MethodPost, "/api/ciphers", "application/json", "{}", func(SessionCheckpoint) error { return nil })
	if err != nil || status != 401 || requests.Load() != 1 {
		t.Fatalf("mutation retried: status %d, err %v, requests %d", status, err, requests.Load())
	}
}
