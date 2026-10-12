// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"sync/atomic"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// notificationSession exposes only the capability needed to subscribe. The
// controller owns stream installation, cancellation and checkpoint persistence;
// it has no access to the app or its editors/navigation/authentication state.
type notificationSession interface {
	StartNotifications(context.Context, vaultwarden.Scope, func(vaultwarden.SessionCheckpoint) error, vaultwarden.NotificationCallback) (*vaultwarden.NotificationStream, error)
}

// Notification lifetime is tied to a Session, not a navigation page. A separate
// immutable clock keeps read hints alive across same-session snapshot revisions.
type controllerNotifications struct {
	clock  atomic.Uint64
	lease  *controllerLease
	cancel context.CancelFunc
	stream *vaultwarden.NotificationStream
	closed bool // UI thread only
}

func (n *controllerNotifications) close() {
	if n == nil || n.closed {
		return
	}
	n.closed = true
	n.lease.revoke()
	n.cancel()
	stopNotificationStream(n.stream)
}

func stopNotificationStream(stream *vaultwarden.NotificationStream) {
	if stream != nil {
		stream.Stop()
		go stream.Wait()
	}
}

func (n *controllerNotifications) refresh(revision, snapshotID string) bool {
	if n.closed || n.stream == nil || n.stream.Err() != nil {
		return false
	}
	n.lease.mu.Lock()
	n.lease.revision, n.lease.snapshotID = revision, snapshotID
	n.lease.mu.Unlock()
	return true
}

func newControllerNotifications(scope vaultwarden.Scope, revision, snapshotID string) *controllerNotifications {
	n := &controllerNotifications{}
	n.lease = &controllerLease{clock: &n.clock, scope: scope, revision: revision, snapshotID: snapshotID, active: true}
	return n
}

func (n *controllerNotifications) start(session notificationSession, dispatch func(func()), storage func(localstore.Request) localstore.Reply, event func(vaultwarden.NotificationEvent, *localstore.SnapshotStatus)) {
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	scope := n.lease.scope
	// Session may be busy: subscription and persistence stay on the worker.
	go func() {
		stream, err := session.StartNotifications(ctx, scope,
			func(cp vaultwarden.SessionCheckpoint) error { return n.lease.persist(cp, storage) },
			func(ctx context.Context, hint vaultwarden.NotificationEvent) error {
				if ctx.Err() != nil {
					return vaultwarden.ErrCancelled
				}
				dispatch(func() {
					if !n.closed {
						event(hint, n.lease.takeCheckpoint())
					}
				})
				return nil
			})
		dispatch(func() {
			if n.closed || ctx.Err() != nil {
				stopNotificationStream(stream)
				return
			}
			if err != nil {
				n.close()
				stopNotificationStream(stream)
				return
			}
			n.stream = stream
		})
	}()
}

// The app only assembles the capability and applies events to its current view.
func (a *app) startNotifications(dispatch func(func()), storage func(localstore.Request) localstore.Reply) {
	if !a.notificationsEnabled || !a.sessionOwnsSnapshot() {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	if n := a.notifications; n != nil {
		if n.refresh(a.sessionRevision, a.snapshot.SnapshotID) {
			return
		}
		n.close()
	}
	scope := *a.liveScope
	n := newControllerNotifications(scope, a.sessionRevision, a.snapshot.SnapshotID)
	a.notifications = n
	n.start(session, dispatch, storage, func(event vaultwarden.NotificationEvent, checkpoint *localstore.SnapshotStatus) {
		if a.notifications != n || a.session != session || a.liveScope == nil || *a.liveScope != scope {
			return
		}
		if checkpoint != nil {
			if !a.adoptSessionCheckpoint(checkpoint) {
				a.stopNetwork()
				a.status = vaultwarden.ErrorMessage(vaultwarden.ErrIdentity)
				return
			}
			a.advanceEpoch()
		}
		if event.Kind == vaultwarden.NotificationLogout {
			a.runStorage(localstore.OperationLogout)
			return
		}
		a.notificationSync(event, dispatch, storage)
	})
}

// notificationSync turns a change hint into at most one follow-up sync.
func (a *app) notificationSync(event vaultwarden.NotificationEvent, dispatch func(func()), storage func(localstore.Request) localstore.Reply) {
	// Server mutations and syncs are serialized by pending, so this device's
	// own change was answered before the current sync started and that sync's
	// download already contains it. A checkpoint that advanced the epoch has
	// detached the in-flight sync, so its result cannot be relied on.
	if event.FromThisDevice && a.syncEpoch != 0 && a.syncEpoch == a.epoch {
		return
	}
	if a.pending != 0 {
		a.notificationSyncPending = true
		return
	}
	a.syncVaultWith(false, dispatch, storage)
}
