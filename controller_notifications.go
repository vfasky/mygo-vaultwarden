// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"sync/atomic"
)

// Notification lifetime is tied to a Session, not a navigation page. A separate
// immutable clock keeps read hints alive across same-session snapshot revisions.
// The lease revision still advances only after authenticated receipts.
type controllerNotifications struct {
	clock  atomic.Uint64
	lease  *controllerLease
	cancel context.CancelFunc
	stream *vaultwarden.NotificationStream
}

func (n *controllerNotifications) close() {
	if n == nil {
		return
	}
	n.lease.revoke()
	n.cancel()
	if n.stream != nil {
		n.stream.Stop()
		go n.stream.Wait()
	}
}
func (a *app) startNotifications(dispatch func(func()), storage func(storageRequest) storageReply) {
	if !a.notificationsEnabled || !a.sessionOwnsSnapshot() {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	if n := a.notifications; n != nil {
		if n.stream != nil && n.stream.Err() == nil {
			n.lease.mu.Lock()
			n.lease.revision = a.sessionRevision
			n.lease.snapshotID = a.snapshot.SnapshotID
			n.lease.mu.Unlock()
			return
		}
		n.close()
		a.notifications = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &controllerNotifications{cancel: cancel}
	scope := *a.liveScope
	n.lease = &controllerLease{clock: &n.clock, scope: scope, revision: a.sessionRevision, snapshotID: a.snapshot.SnapshotID, active: true}
	a.notifications = n
	// StartNotifications briefly takes Session.mu; perform it on a worker so UI
	// never waits for an in-flight request. Installation is also scope checked.
	go func() {
		stream, err := session.StartNotifications(ctx, scope, func(cp vaultwarden.SessionCheckpoint) error { return n.lease.persist(cp, storage) }, func(ctx context.Context, event vaultwarden.NotificationEvent) error {
			if ctx.Err() != nil {
				return vaultwarden.ErrCancelled
			}
			dispatch(func() {
				if a.notifications != n || a.session != session || a.liveScope == nil || *a.liveScope != scope {
					return
				}
				if checkpoint := n.lease.takeCheckpoint(); checkpoint != nil {
					if !a.adoptSessionCheckpoint(checkpoint) {
						a.stopNetwork()
						a.status = vaultwarden.ErrIdentity.Error()
						return
					}
					a.advanceEpoch()
				}
				if event.Kind == vaultwarden.NotificationLogout {
					a.runStorage("logout")
					return
				}
				// Events contain hints only. Coalesce while a normal request is running.
				if a.pending != 0 {
					a.notificationSyncPending = true
					return
				}
				a.syncVaultWith(false, dispatch, storage)
			})
			return nil
		})
		dispatch(func() {
			if a.notifications != n || ctx.Err() != nil {
				if stream != nil {
					stream.Stop()
					go stream.Wait()
				}
				return
			}
			if err != nil {
				n.close()
				a.notifications = nil
				return
			}
			n.stream = stream
		})
	}()
}
