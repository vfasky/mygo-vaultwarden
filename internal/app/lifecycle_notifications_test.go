// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestUnlockNotificationsWithoutWindow(t *testing.T) {
	for _, operation := range []string{"list", "listPassword"} {
		t.Run(operation, func(t *testing.T) {
			a := passwordLockedApp()
			a.notificationsEnabled = true
			queue := make(chan func(), 8)
			a.uiDispatcher = func(f func()) { queue <- f }
			a.storageBackend = func(localstore.Request) localstore.Reply { return localstore.Reply{} }
			a.pending, a.epoch = 1, 2
			a.completeStorage(localstore.Request{Operation: operation, ExpectedRevision: a.snapshot.Revision, Scope: a.snapshot.Scope}, a.epoch,
				localstore.Reply{OK: true, State: a.snapshot, Session: savedUIFixture(t, a)})
			if a.window != nil || a.notifications == nil {
				t.Fatal("unlock did not assemble headless subscription")
			}
			// The legacy fixture has no access token: startup reports its error
			// through the injected dispatcher, without native UI/network access.
			select {
			case f := <-queue:
				f()
			case <-time.After(time.Second):
				t.Fatal("injected dispatcher not used")
			}
			a.stopNetwork()
		})
	}
}

type notificationCapability struct {
	started chan struct{}
	release chan struct{}
}

func (s *notificationCapability) StartNotifications(ctx context.Context, scope vaultwarden.Scope, persist func(vaultwarden.SessionCheckpoint) error, event vaultwarden.NotificationCallback) (*vaultwarden.NotificationStream, error) {
	_ = persist(vaultwarden.SessionCheckpoint{Scope: scope})
	_ = event(ctx, vaultwarden.NotificationEvent{})
	close(s.started)
	<-s.release
	return nil, vaultwarden.ErrCancelled
}

func TestNotificationControllerUsesInjectedStorageAndDropsClosedEvents(t *testing.T) {
	scope := vaultwarden.Scope{Server: "https://vault.example.com", Account: "account-a"}
	n := newControllerNotifications(scope, "r1", "snapshot")
	s := &notificationCapability{started: make(chan struct{}), release: make(chan struct{})}
	queue := make(chan func(), 4)
	requests := make(chan localstore.Request, 1)
	events := 0
	n.start(s, func(f func()) { queue <- f }, func(r localstore.Request) localstore.Reply {
		requests <- r
		return localstore.Reply{Code: "cancelled"}
	}, func(vaultwarden.NotificationEvent, *localstore.SnapshotStatus) { events++ })
	select {
	case <-s.started:
	case <-time.After(time.Second):
		t.Fatal("subscription did not start")
	}
	r := <-requests
	if r.Operation != "saveSession" || r.ExpectedRevision != "r1" || r.Scope == nil || *r.Scope != scope {
		t.Fatal("checkpoint bypassed injected backend or scope binding")
	}
	n.close()
	(<-queue)() // queued event must be discarded after close
	if events != 0 {
		t.Fatal("closed subscription delivered event")
	}
	if _, active := n.lease.state(); active {
		t.Fatal("closed subscription kept storage lease")
	}
	close(s.release)
	select {
	case f := <-queue:
		f()
	case <-time.After(time.Second):
		t.Fatal("worker did not settle")
	}
	if n.refresh("r2", "snapshot") {
		t.Fatal("closed subscription was revived")
	}
}
