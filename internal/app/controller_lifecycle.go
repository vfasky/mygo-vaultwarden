// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"sync"
	"sync/atomic"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) componentBusy(started bool) {
	if started {
		a.pending++
	} else {
		a.pending--
		if a.notificationSyncPending {
			session := a.session
			a.dispatchUI(func() {
				if a.pending == 0 && a.session == session && a.session != nil && a.notificationSyncPending {
					a.notificationSyncPending = false
					a.syncVault(false)
				}
			})
		}
	}
}

func (a *app) dispatchUI(f func()) {
	if a.uiDispatcher != nil {
		a.uiDispatcher(f)
		return
	}
	a.window.Update(f)
}

// controllerLease is the only mutable controller state visible to workers.
// Its mutex never spans storage, Session methods, dispatch, or native UI calls.
// UI state (including app.epoch) remains confined to the UI thread.
type controllerLease struct {
	mu                   sync.Mutex
	epoch                uint64
	clock                *atomic.Uint64
	scope                vaultwarden.Scope
	revision, snapshotID string
	active               bool
	checkpoint           *snapshotStatus
}

func (a *app) advanceEpoch() uint64 {
	a.epoch++
	a.workerEpoch.Store(a.epoch)
	if a.runtimeVault != nil {
		a.prepareRuntimeSecret()
	}
	if a.componentLease != nil {
		a.componentLease.revoke()
		a.componentLease = nil
	}
	a.closeConnectedPanels()
	return a.epoch
}

func (a *app) newControllerLease() *controllerLease {
	if !a.sessionOwnsSnapshot() || a.snapshot.SnapshotID == "" {
		return nil
	}
	// Also initialize the clock for restored sessions and headless fixtures.
	a.workerEpoch.Store(a.epoch)
	l := &controllerLease{epoch: a.epoch, clock: &a.workerEpoch, scope: *a.liveScope,
		revision: a.sessionRevision, snapshotID: a.snapshot.SnapshotID, active: true}
	a.componentLease = l
	return l
}

func (l *controllerLease) revoke() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.active = false
	l.checkpoint = nil
	l.mu.Unlock()
}
func (l *controllerLease) state() (snapshotStatus, bool) {
	if l == nil {
		return snapshotStatus{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	scope := l.scope
	return snapshotStatus{Available: true, Scope: &scope, Revision: l.revision, SnapshotID: l.snapshotID}, l.active && l.clock.Load() == l.epoch
}
func (l *controllerLease) check(storage func(storageRequest) storageReply) error {
	prior, active := l.state()
	if !active {
		return vaultwarden.ErrCancelled
	}
	reply := storage(storageRequest{Operation: "status"})
	next, active := l.state()
	if !active || next.Revision != prior.Revision {
		return vaultwarden.ErrCancelled
	}
	if !reply.OK {
		return reply.failure()
	}
	if reply.State == nil || !reply.State.Available || reply.State.Scope == nil ||
		*reply.State.Scope != *prior.Scope || reply.State.Revision != prior.Revision || reply.State.SnapshotID != prior.SnapshotID {
		return vaultwarden.ErrIdentity
	}
	return nil
}

// Called under Session.mu. Saving and receipt validation must finish before
// returning, but adoption (which reenters Session) belongs to the UI dispatch.
func (l *controllerLease) persist(cp vaultwarden.SessionCheckpoint, storage func(storageRequest) storageReply) error {
	prior, active := l.state()
	if !active {
		return vaultwarden.ErrCancelled
	}
	reply, err := saveSessionCheckpoint(&prior, cp, storage)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.active || l.clock.Load() != l.epoch || l.revision != prior.Revision {
		return vaultwarden.ErrCancelled
	}
	state := *reply.State
	scope := *reply.State.Scope
	state.Scope = &scope
	l.revision = state.Revision
	l.checkpoint = &state
	return nil
}
func (l *controllerLease) takeCheckpoint() *snapshotStatus {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.active || l.clock.Load() != l.epoch {
		return nil
	}
	state := l.checkpoint
	l.checkpoint = nil
	return state
}
