// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func savedUIFixture(t *testing.T, a *app) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"version": 1, "scope": a.snapshot.Scope, "email": a.snapshot.PasswordUnlock.Email,
		"deviceID": "fixture-device-00000001", "refreshToken": "fixture-refresh", "wrappedKey": "fixture-wrapped-key",
		"userKey":        bytes.Repeat([]byte{4}, 64),
		"passwordUnlock": &vaultwarden.PasswordUnlock{Config: *a.snapshot.PasswordUnlock, Key: bytes.Repeat([]byte{8}, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAuthenticatedUnlockRestoresSyncAndWipesTransport(t *testing.T) {
	for _, operation := range []string{"listPassword", "list"} {
		t.Run(operation, func(t *testing.T) {
			a := passwordLockedApp()
			a.epoch, a.pending = 2, 1
			request := storageRequest{Operation: operation, ExpectedRevision: a.snapshot.Revision, Scope: a.snapshot.Scope}
			data := savedUIFixture(t, a)
			a.completeStorage(request, a.epoch, storageReply{OK: true, State: a.snapshot, Session: data, Items: []displayCredential{{ID: "one"}}})
			if !a.unlocked() || !a.sessionOwnsSnapshot() || a.sessionRevision != request.ExpectedRevision {
				t.Fatal("authenticated unlock did not restore sync authority")
			}
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Fatal("session transport buffer was retained")
			}
			tt := ui.NewTester(a.view, 1060, 700)
			if !tt.HasText("可同步") || !tt.HasText("同步") {
				t.Fatal("restored session missing from UI")
			}
			a.lockInterface()
			if a.session != nil || a.sessionRevision != "" || a.unlocked() {
				t.Fatal("locking retained active session authority")
			}
		})
	}
}

func TestLateOrUnauthenticatedReceiptNeverRestoresSession(t *testing.T) {
	for _, scenario := range []string{"late", "failed", "wrong-revision", "wrong-scope", "status", "malformed-session"} {
		t.Run(scenario, func(t *testing.T) {
			a := passwordLockedApp()
			a.epoch, a.pending = 2, 1
			request := storageRequest{Operation: "listPassword", ExpectedRevision: a.snapshot.Revision, Scope: a.snapshot.Scope}
			state := *a.snapshot
			data := savedUIFixture(t, a)
			reply := storageReply{OK: true, State: &state, Session: data}
			epoch := a.epoch
			switch scenario {
			case "late":
				a.epoch++
			case "failed":
				reply.OK = false
			case "wrong-revision":
				state.Revision = "another"
			case "wrong-scope":
				state.Scope = &vaultwarden.Scope{Server: a.snapshot.Scope.Server, Account: "other"}
			case "status":
				request.Operation = "status"
			case "malformed-session":
				clear(data)
			}
			a.completeStorage(request, epoch, reply)
			if a.session != nil || a.sessionOwnsSnapshot() {
				t.Fatal("unauthorized session restoration")
			}
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Fatal("discarded reply retained credentials")
			}
		})
	}
}

func TestLegacyUnlockSyncButtonOpensLoginWithoutDeletingVault(t *testing.T) {
	a := passwordLockedApp()
	a.pending, a.epoch = 1, 1
	a.completeStorage(storageRequest{Operation: "list", ExpectedRevision: a.snapshot.Revision, Scope: a.snapshot.Scope}, 1,
		storageReply{OK: true, State: a.snapshot, Items: []displayCredential{{ID: "one"}}})
	tt := ui.NewTester(a.view, 1060, 700)
	clickUI(t, tt, "同步")
	if !a.showLogin || !a.unlocked() || a.pending != 0 || !tt.HasText("登录服务器") {
		t.Fatal("legacy sync stayed disabled or deleted the vault on navigation")
	}
}

func TestRefreshCheckpointAdoptionPreservesMetadataWithoutRebasingRevokedSession(t *testing.T) {
	a, session := onlineTestApp()
	defer session.Close()
	a.snapshot.SnapshotID = "snapshot-a"
	checkpoint := vaultwarden.SessionCheckpoint{Scope: *a.liveScope, Session: []byte("encrypted-by-storage"), UnlockKey: make([]byte, 32)}
	state := *a.snapshot
	state.Revision = "checkpoint-r2"
	reply, err := saveSessionCheckpoint(a.snapshot, checkpoint, func(request storageRequest) storageReply {
		if request.Operation != "saveSession" || request.ExpectedRevision != "authorized-r1" {
			t.Fatal("checkpoint borrowed wrong CAS revision")
		}
		return storageReply{OK: true, State: &state}
	})
	if err != nil || !a.adoptSessionCheckpoint(reply.State) || !a.sessionOwnsSnapshot() || a.itemsRevision != state.Revision || len(a.items) != 1 {
		t.Fatal("refresh persistence discarded unchanged offline metadata")
	}
	a.syncFailed(reply, vaultwarden.ErrNetwork)
	if !a.sessionOwnsSnapshot() || !a.unlocked() {
		t.Fatal("network failure after checkpoint lost sync session")
	}
	a.lockInterface()
	if a.adoptSessionCheckpoint(reply.State) || a.sessionOwnsSnapshot() {
		t.Fatal("checkpoint resurrected a locked session")
	}
}

func TestRefreshCheckpointRejectsInvalidReceipts(t *testing.T) {
	for _, scenario := range []string{"failure", "nil", "unavailable", "same-revision", "wrong-scope", "different-snapshot"} {
		t.Run(scenario, func(t *testing.T) {
			a, session := onlineTestApp()
			defer session.Close()
			a.snapshot.SnapshotID = "snapshot-a"
			state := *a.snapshot
			state.Revision = "checkpoint-r2"
			reply := storageReply{OK: true, State: &state}
			switch scenario {
			case "failure":
				reply.OK = false
			case "nil":
				reply.State = nil
			case "unavailable":
				state.Available = false
			case "same-revision":
				state.Revision = a.snapshot.Revision
			case "wrong-scope":
				state.Scope = &vaultwarden.Scope{Server: a.snapshot.Scope.Server, Account: "other"}
			case "different-snapshot":
				state.SnapshotID = "replacement"
			}
			if _, err := saveSessionCheckpoint(a.snapshot, vaultwarden.SessionCheckpoint{Scope: *a.liveScope}, func(storageRequest) storageReply { return reply }); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
			if a.sessionRevision != "authorized-r1" {
				t.Fatal("checkpoint failure adopted observed revision")
			}
		})
	}
}
