// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncWindowFixture serves /api/sync, holding the first download until release.
type syncWindowFixture struct {
	s        *Session
	v        *VaultData
	scope    Scope
	requests atomic.Int32
	arrived  chan struct{}
	gate     chan struct{}
	once     sync.Once
	status   int
}

func newSyncWindowFixture(t *testing.T) *syncWindowFixture {
	t.Helper()
	f := &syncWindowFixture{arrived: make(chan struct{}, 4), gate: make(chan struct{}), status: http.StatusOK}
	raw, _ := json.Marshal(emptyPolicySyncFixture())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/connect/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access-new", "refresh_token": "refresh-new", "expires_in": 3600, "token_type": "Bearer"})
		case r.URL.Path == "/api/sync":
			if f.requests.Add(1) == 1 {
				f.arrived <- struct{}{}
				select {
				case <-f.gate:
				case <-r.Context().Done():
					return
				}
			}
			if f.status != http.StatusOK {
				w.WriteHeader(f.status)
				return
			}
			w.Write(raw)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(f.release)
	f.s, _ = resumableFixture(t, server.URL)
	t.Cleanup(f.s.Close)
	f.scope = Scope{Server: server.URL, Account: f.s.account}
	f.v = &VaultData{Version: 1, Scope: f.scope, Sync: raw}
	if err := f.s.AcceptAuthenticatedSnapshot(f.v, "r"); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *syncWindowFixture) release() { f.once.Do(func() { close(f.gate) }) }

// start runs SyncWithWindow and returns once its download reached the server.
func (f *syncWindowFixture) start(t *testing.T, persist func(SessionCheckpoint) error, window SyncWindow) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := f.s.SyncWithWindow(context.Background(), persist, window)
		done <- err
	}()
	select {
	case <-f.arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("download did not start")
	}
	return done
}

// withinDeadline fails instead of hanging when call waits for the Session lock.
func withinDeadline(t *testing.T, what string, call func() error) error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- call() }()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal(what + " waited for the sync download")
		return nil
	}
}

func waitSync(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("sync did not finish")
		return nil
	}
}

func TestSyncWithWindowKeepsSnapshotReadableDuringDownload(t *testing.T) {
	f := newSyncWindowFixture(t)
	var opened, closedAuthorized atomic.Bool
	done := f.start(t, nil, SyncWindow{
		Open: func() { opened.Store(true) },
		Close: func(context.Context) {
			// Reads stop here; the old authority is revoked only afterwards.
			closedAuthorized.Store(f.s.ValidateAuthenticatedSnapshot(f.v, "r") == nil)
		},
	})
	if !opened.Load() {
		t.Fatal("window not opened before the download")
	}
	if err := withinDeadline(t, "snapshot read", func() error { return f.s.ValidateAuthenticatedSnapshot(f.v, "r") }); err != nil {
		t.Fatal("adopted snapshot unreadable during download", err)
	}
	if err := withinDeadline(t, "entry read", func() error { _, err := f.s.PersonalEntries(f.v); return err }); err != nil {
		t.Fatal("entries unreadable during download", err)
	}
	f.release()
	if err := waitSync(t, done); err != nil {
		t.Fatal(err)
	}
	if !closedAuthorized.Load() {
		t.Fatal("authority revoked before the window closed")
	}
	if err := f.s.ValidateAuthenticatedSnapshot(f.v, "r"); !errors.Is(err, ErrExpired) {
		t.Fatal("sync retained old capability", err)
	}
	if f.requests.Load() != 1 {
		t.Fatalf("downloads=%d", f.requests.Load())
	}
}

func TestSyncWithWindowRefetchesAfterAuthorityChange(t *testing.T) {
	f := newSyncWindowFixture(t)
	done := f.start(t, nil, SyncWindow{})
	// A revision bind advances the authorization epoch while the lock is free.
	if err := withinDeadline(t, "revision bind", func() error { return f.s.BindSnapshotRevision(f.scope, "r2") }); err != nil {
		t.Fatal(err)
	}
	f.release()
	if err := waitSync(t, done); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != 2 {
		t.Fatalf("stale response used: downloads=%d", f.requests.Load())
	}
}

func TestSyncWithWindowCloseDuringDownloadCancels(t *testing.T) {
	f := newSyncWindowFixture(t)
	done := f.start(t, nil, SyncWindow{})
	withinDeadline(t, "close", func() error { f.s.Close(); return nil })
	err := waitSync(t, done)
	if !errors.Is(err, ErrCancelled) {
		t.Fatal("closing must cancel, not expire, the sync", err)
	}
}

func TestSyncWithWindowFailureStillRevokes(t *testing.T) {
	f := newSyncWindowFixture(t)
	f.status = http.StatusServiceUnavailable
	done := f.start(t, nil, SyncWindow{})
	f.release()
	if err := waitSync(t, done); err == nil {
		t.Fatal("failed download succeeded")
	}
	if err := f.s.ValidateAuthenticatedSnapshot(f.v, "r"); !errors.Is(err, ErrExpired) {
		t.Fatal("failed sync retained old capability", err)
	}
}

func TestSyncWithWindowOpensAfterCheckpoint(t *testing.T) {
	f := newSyncWindowFixture(t)
	f.s.expires = time.Now() // the request must refresh and checkpoint first
	var order []string
	var mu sync.Mutex
	record := func(event string) { mu.Lock(); order = append(order, event); mu.Unlock() }
	done := f.start(t, func(SessionCheckpoint) error { record("checkpoint"); return nil }, SyncWindow{
		Open:  func() { record("open") },
		Close: func(context.Context) { record("close") },
	})
	f.release()
	if err := waitSync(t, done); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != "checkpoint,open,close" {
		t.Fatalf("order %v", order)
	}
}

func TestSyncWithWindowCloseCancelsAfterAnotherOperationBegan(t *testing.T) {
	f := newSyncWindowFixture(t)
	done := f.start(t, nil, SyncWindow{})
	// Notification connection preparation registers and finishes an
	// operation of its own while the sync download holds no lock.
	f.otherOperation(t)
	withinDeadline(t, "close", func() error { f.s.Close(); return nil })
	// The download is still held by the server: only cancellation ends it.
	if err := waitSync(t, done); !errors.Is(err, ErrCancelled) {
		t.Fatal("close did not cancel the sync download", err)
	}
}

// syncApplyCloseContext snapshots a successful cancellation check, then lets
// Close cancel the registered operation before that check returns. This fixes
// the interleaving between applySyncLocked's check and its organization read.
type syncApplyCloseContext struct {
	context.Context
	once       sync.Once
	afterCheck func()
}

func (c *syncApplyCloseContext) Err() error {
	err := c.Context.Err()
	c.once.Do(c.afterCheck)
	return err
}

func TestSyncApplyCloseAfterCancellationCheck(t *testing.T) {
	f := newSyncWindowFixture(t)
	closed := make(chan struct{})
	err := func() error {
		f.s.mu.Lock()
		defer f.s.mu.Unlock()
		ctx, finish, err := f.s.beginOperationLocked(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer finish()
		check := &syncApplyCloseContext{Context: ctx, afterCheck: func() {
			go func() { f.s.Close(); close(closed) }()
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("close did not cancel the active sync")
			}
		}}
		f.s.revokeForSyncLocked()
		result, err := f.s.applySyncLocked(check, http.StatusOK, f.v.Sync, nil)
		if result.Vault != nil || result.Session != nil || result.PasswordUnlock != nil || len(result.Credentials) != 0 {
			t.Fatal("cancelled sync returned credentials or session state")
		}
		return err
	}()
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("close after cancellation check must cancel, not expire: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not finish after sync released the lock")
	}
}

func TestSyncApplyPreservesExpiry(t *testing.T) {
	f := newSyncWindowFixture(t)
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	// A runtime-only session can expire without the owner cancelling it.
	f.s.runtimeOnly = true
	f.s.expires = time.Now().Add(-time.Second)
	f.s.revokeForSyncLocked()
	_, err := f.s.applySyncLocked(context.Background(), http.StatusOK, f.v.Sync, nil)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("uncancelled runtime expiry must remain expired: %v", err)
	}
}

func TestSyncWithWindowDownloadReturnRacesClose(t *testing.T) {
	for i := 0; i < 20; i++ {
		f := newSyncWindowFixture(t)
		done := f.start(t, nil, SyncWindow{})
		f.otherOperation(t)
		closed := make(chan struct{})
		go func() { f.s.Close(); close(closed) }()
		f.release()
		if err := waitSync(t, done); err != nil && !errors.Is(err, ErrCancelled) {
			t.Fatal("close during apply must cancel, not expire", err)
		}
		<-closed
	}
}

// otherOperation begins and finishes a Session operation the way notification
// connection preparation does, while the sync download holds no lock.
func (f *syncWindowFixture) otherOperation(t *testing.T) {
	t.Helper()
	withinDeadline(t, "notification preparation", func() error {
		f.s.mu.Lock()
		defer f.s.mu.Unlock()
		_, finish, err := f.s.beginOperationLocked(context.Background())
		if err == nil {
			finish()
		}
		return err
	})
}
