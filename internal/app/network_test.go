// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type testVaultSession struct {
	closed chan struct{}
	once   sync.Once
}

func (s *testVaultSession) Close() { s.once.Do(func() { close(s.closed) }) }
func (s *testVaultSession) SyncWithWindow(context.Context, func(vaultwarden.SessionCheckpoint) error, vaultwarden.SyncWindow) (vaultwarden.SyncResult, error) {
	panic("revoked session must never sync")
}
func onlineTestApp() (*app, *testVaultSession) {
	scope := vaultwarden.Scope{Server: "https://vault.example.com", Account: "account-a"}
	session := &testVaultSession{closed: make(chan struct{})}
	return &app{session: session, liveScope: &scope, sessionRevision: "authorized-r1",
		snapshot: &localstore.SnapshotStatus{Revision: "authorized-r1", Available: true, Scope: &scope},
		items:    []localstore.DisplayCredential{{ID: "old-entry"}}, itemsRevision: "authorized-r1"}, session
}
func assertSessionRevoked(t *testing.T, a *app, s *testVaultSession) {
	t.Helper()
	if a.session != nil || a.liveScope != nil || a.sessionRevision != "" || len(a.items) != 0 || a.itemsRevision != "" {
		t.Fatal("old session or metadata survived revocation")
	}
	select {
	case <-s.closed:
	case <-time.After(time.Second):
		t.Fatal("session secrets not closed")
	}
	// Repeating the real Sync action must not reacquire the newly observed revision.
	a.syncVault(false)
	a.syncVault(false)
	if a.pending != 0 || a.sessionOwnsSnapshot() {
		t.Fatal("revoked session regained write authority")
	}
}
func TestEmptyVaultPublicationEncodesExplicitArray(t *testing.T) {
	for _, credentials := range [][]vaultwarden.Credential{nil, {}} {
		request := localstore.Request{Operation: "publishVault", ExpectedRevision: "r", Credentials: credentials,
			Scope: &vaultwarden.Scope{Server: "https://vault.example.com", Account: "account-a"}}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err = json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		if string(wire["credentials"]) != "[]" {
			t.Fatalf("empty replacement omitted or null: %s", wire["credentials"])
		}
	}
}
func TestStalePublicationCannotRebaseRevokedSession(t *testing.T) {
	for _, reason := range []string{"logout", "lock", "account_switch", "same_account_replacement", "missing_state"} {
		t.Run(reason, func(t *testing.T) {
			a, s := onlineTestApp()
			state := &localstore.SnapshotStatus{Revision: "external-r2", Available: true, Scope: a.liveScope}
			switch reason {
			case "logout":
				state.Available = false
				state.Scope = nil
			case "account_switch":
				state.Scope = &vaultwarden.Scope{Server: a.liveScope.Server, Account: "account-b"}
			case "missing_state":
				state = nil
			}
			reply := localstore.Reply{Code: "stale_revision", Message: "状态已变化", State: state}
			err := reply.Failure()
			var failure *localstore.Failure
			if !errors.As(err, &failure) || failure.Code != "stale_revision" {
				t.Fatal("bridge error code lost")
			}
			a.syncFailed(reply, err)
			assertSessionRevoked(t, a, s)
		})
	}
}
func TestStateRefreshCannotRenewOnlineWriteAuthority(t *testing.T) {
	a, s := onlineTestApp()
	a.observeSnapshot(&localstore.SnapshotStatus{Revision: "external-r2", Available: true, Scope: a.liveScope})
	assertSessionRevoked(t, a, s)
}
func TestDirectRevisionAdoptionIsRejectedBeforeNetwork(t *testing.T) {
	a, s := onlineTestApp()
	a.snapshot = &localstore.SnapshotStatus{Revision: "external-r2", Available: true, Scope: a.liveScope}
	a.syncVault(false)
	assertSessionRevoked(t, a, s)
}
func TestUnchangedStatusAndNetworkFailureKeepSession(t *testing.T) {
	a, s := onlineTestApp()
	defer s.Close()
	a.observeSnapshot(&localstore.SnapshotStatus{Revision: "authorized-r1", Available: true, Scope: a.liveScope, IndexPending: false})
	a.syncFailed(localstore.Reply{}, vaultwarden.ErrNetwork)
	if !a.sessionOwnsSnapshot() || len(a.items) != 1 {
		t.Fatal("ordinary network failure discarded unchanged offline state")
	}
}
