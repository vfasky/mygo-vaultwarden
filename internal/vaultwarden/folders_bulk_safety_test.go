// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestFolderAndBulkCannotBypassCheckpoint(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	s.checkpointPending = true
	scope := Scope{Server: server.URL, Account: "account-a"}
	for _, work := range []func() error{
		func() error { _, err := s.SaveFolder(context.Background(), scope, "", "private", nil); return err },
		func() error { return s.DeleteFolder(context.Background(), scope, "folder-1", nil) },
		func() error {
			return s.ChangePersonalCiphers(context.Background(), scope, bulkFixture(scope, false), []string{"item-1"}, CipherTrash, nil, nil)
		},
	} {
		if err := work(); !errors.Is(err, ErrCheckpoint) {
			t.Fatal("checkpoint bypass", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("checkpoint failure dispatched request")
	}
}

func TestCloseCancelsBulkWithoutRetry(t *testing.T) {
	entered := make(chan struct{})
	var requests atomic.Int32
	server := newPersonalStatePolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	s, _ := resumableFixture(t, server.URL)
	defer s.Close()
	scope := Scope{Server: server.URL, Account: "account-a"}
	done := make(chan error, 1)
	go func() {
		done <- s.ChangePersonalCiphers(context.Background(), scope, bulkFixture(scope, false), []string{"item-1"}, CipherTrash, nil, nil)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request not started")
	}
	s.Close()
	select {
	case err := <-done:
		var unknown *MutationUncertainError
		if !errors.As(err, &unknown) || !errors.Is(err, ErrCancelled) || requests.Load() != 1 {
			t.Fatal("lost cancelled unknown result", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("close did not cancel")
	}
}
