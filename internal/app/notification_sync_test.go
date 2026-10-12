// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"net/http"
	"testing"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

var (
	ownSyncHint   = vaultwarden.NotificationEvent{Kind: vaultwarden.NotificationSync, FromThisDevice: true}
	otherSyncHint = vaultwarden.NotificationEvent{Kind: vaultwarden.NotificationSync}
)

func countSyncDownloads(f *resourceControllerFixture) *int {
	count := new(int)
	f.additional = func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/sync" {
			*count++
		}
		return false
	}
	return count
}

func TestOwnChangeEchoDuringSyncDoesNotSyncAgain(t *testing.T) {
	f := newResourceControllerFixture(t)
	downloads := countSyncDownloads(f)
	// A hint queued before the sync starts is covered by that download.
	f.a.notificationSyncPending = true
	f.refresh()
	if f.a.notificationSyncPending || f.a.syncEpoch != f.a.epoch {
		t.Fatal("starting sync did not take over the queued hint")
	}
	f.a.notificationSync(ownSyncHint, f.dispatch, f.storage)
	f.drain()
	if *downloads != 1 || f.a.notificationSyncPending || f.a.syncEpoch != 0 {
		t.Fatalf("downloads=%d pending=%v epoch=%d", *downloads, f.a.notificationSyncPending, f.a.syncEpoch)
	}
}

func TestOtherDeviceChangeDuringSyncStillSyncsAgain(t *testing.T) {
	f := newResourceControllerFixture(t)
	downloads := countSyncDownloads(f)
	f.refresh()
	// Another device may have committed after this download was sent.
	f.a.notificationSync(otherSyncHint, f.dispatch, f.storage)
	if !f.a.notificationSyncPending {
		t.Fatal("foreign hint was dropped")
	}
	f.drain()
	if *downloads != 2 || f.a.notificationSyncPending {
		t.Fatalf("downloads=%d pending=%v", *downloads, f.a.notificationSyncPending)
	}
}

func TestOwnEchoAfterDetachedSyncIsKept(t *testing.T) {
	f := newResourceControllerFixture(t)
	f.refresh()
	// A notification checkpoint advanced the epoch: the in-flight result is void.
	f.a.advanceEpoch()
	f.a.notificationSync(ownSyncHint, f.dispatch, f.storage)
	f.drain()
	if !f.a.notificationSyncPending {
		t.Fatal("echo dropped although the covering sync was detached")
	}
}

type failingSyncSession struct{ syncs int }

func (s *failingSyncSession) Close() {}
func (s *failingSyncSession) SyncWithCheckpoint(context.Context, func(vaultwarden.SessionCheckpoint) error) (vaultwarden.SyncResult, error) {
	s.syncs++
	return vaultwarden.SyncResult{}, vaultwarden.ErrNetwork
}

func failingSyncApp() (*app, *failingSyncSession, chan func()) {
	a, _ := onlineTestApp()
	session := &failingSyncSession{}
	a.session = session
	return a, session, make(chan func(), 8)
}

func TestFailedSyncHandsBackCoveredHint(t *testing.T) {
	a, session, q := failingSyncApp()
	a.notificationSyncPending = true
	a.syncVaultWith(false, func(fn func()) { q <- fn }, func(localstore.Request) localstore.Reply { return localstore.Reply{} })
	if a.notificationSyncPending {
		t.Fatal("hint not taken over")
	}
	(<-q)()
	if a.pending != 0 || session.syncs != 1 || !a.notificationSyncPending || a.syncEpoch != 0 {
		t.Fatalf("pending=%d syncs=%d hint=%v epoch=%d", a.pending, session.syncs, a.notificationSyncPending, a.syncEpoch)
	}
}

func TestOwnEchoWithoutSyncInFlightStillSyncs(t *testing.T) {
	// An uncertain mutation does not sync by itself; its echo must still verify it.
	a, session, q := failingSyncApp()
	a.notificationSync(ownSyncHint, func(fn func()) { q <- fn }, func(localstore.Request) localstore.Reply { return localstore.Reply{} })
	if a.pending != 1 {
		t.Fatal("own echo did not start a sync")
	}
	(<-q)()
	if session.syncs != 1 || a.pending != 0 {
		t.Fatal("sync did not run")
	}
	// While another operation is busy, the echo is queued rather than lost.
	a.pending = 1
	a.notificationSync(ownSyncHint, nil, nil)
	if !a.notificationSyncPending {
		t.Fatal("own echo during a mutation was dropped")
	}
}

func TestSyncViewLoadedOffUIIsDiscardedAfterLock(t *testing.T) {
	f := newResourceControllerFixture(t)
	f.refresh()
	(<-f.q)() // network and publication done; authority accepted on the UI thread
	if f.a.pending != 1 {
		t.Fatal("sync released pending before its view was adopted")
	}
	f.a.stopNetwork()
	f.drain()
	if f.a.pending != 0 || f.a.session != nil || f.a.vault != nil || len(f.a.items) != 0 {
		t.Fatal("view decrypted for a locked session was adopted")
	}
}

func TestSyncViewLoadedOffUIIsAdopted(t *testing.T) {
	f := newResourceControllerFixture(t)
	before := f.a.sessionRevision
	f.refresh()
	f.drain()
	if f.a.vault == nil || len(f.a.items) == 0 || f.a.sessionRevision == before || f.a.itemsRevision != f.a.sessionRevision {
		t.Fatal("sync result was not adopted")
	}
}
