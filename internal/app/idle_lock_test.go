// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type idleHarness struct {
	now        time.Time
	idle       time.Duration
	tick       func()
	queued     []func()
	locks      int
	controller *idleLockController
}

func newIdleHarness() *idleHarness {
	h := &idleHarness{now: time.Unix(1000, 0)}
	h.controller = &idleLockController{
		now: func() time.Time { return h.now }, idle: func() time.Duration { return h.idle },
		after:    func(_ time.Duration, f func()) func() { h.tick = f; return func() {} },
		dispatch: func(f func()) { h.queued = append(h.queued, f) },
		lock:     func() { h.locks++ },
	}
	return h
}

func (h *idleHarness) fire() {
	h.tick()
	f := h.queued[0]
	h.queued = h.queued[1:]
	f()
}

func TestIdleLockDeadlineIgnoresBackgroundRefresh(t *testing.T) {
	h := newIdleHarness()
	h.controller.start()
	h.now = h.now.Add(vaultIdleTimeout - time.Second)
	h.idle = vaultIdleTimeout - time.Second
	h.fire()
	if h.locks != 0 {
		t.Fatal("locked before deadline")
	}
	// Sync/adoption and repeated render-related starts cannot renew the timer.
	h.controller.start()
	h.now = h.now.Add(time.Second)
	h.idle += time.Second
	h.fire()
	if h.locks != 1 || h.controller.active {
		t.Fatal("background activity extended deadline")
	}
	h.fire()
	if h.locks != 1 {
		t.Fatal("timer locked twice")
	}
}

func TestIdleLockRealInputAndAuthenticatedUnlock(t *testing.T) {
	h := newIdleHarness()
	h.idle = time.Hour // no recent input when biometric authentication completes
	h.controller.start()
	h.fire()
	if h.locks != 0 {
		t.Fatal("fresh unlock inherited old idle interval")
	}
	h.now = h.now.Add(vaultIdleTimeout)
	h.idle = time.Minute // real user activity, even outside this app
	h.fire()
	if h.locks != 0 {
		t.Fatal("keyboard/mouse activity ignored")
	}
	h.now = h.now.Add(14 * time.Minute)
	h.idle = vaultIdleTimeout
	h.fire()
	if h.locks != 1 {
		t.Fatal("did not lock after renewed activity expired")
	}
}

func TestIdleLockRejectsQueuedOldGeneration(t *testing.T) {
	h := newIdleHarness()
	h.controller.start()
	h.tick() // worker has already dispatched the old completion
	h.controller.stop()
	h.controller.start()
	h.now = h.now.Add(vaultIdleTimeout)
	h.idle = vaultIdleTimeout
	old := h.queued[0]
	h.queued = nil
	old()
	if h.locks != 0 {
		t.Fatal("old generation locked a new session")
	}
	h.fire()
	if h.locks != 1 {
		t.Fatal("current generation lost its deadline")
	}
}

type idleNativeSecret struct{ revoked bool }

func (*idleNativeSecret) Use(vaultwarden.Scope, uint64, time.Time, string, bool) error { return nil }
func (n *idleNativeSecret) Revoke()                                                    { n.revoked = true }

func TestIdleLockCancelsWorkAndRevokesRuntime(t *testing.T) {
	a, session := onlineTestApp()
	h := newIdleHarness()
	a.idleLock = h.controller
	h.controller.lock = func() { a.runStorage("lock") }
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	native := &idleNativeSecret{}
	runtime := &runtimeVault{active: true, native: native}
	a.runtimeVault = runtime
	a.diskSnapshot = a.snapshot
	uiQueue := make(chan func(), 2)
	a.uiDispatcher = func(f func()) { uiQueue <- f }
	operations := make(chan localstore.Operation, 2)
	a.storageBackend = func(r localstore.Request) localstore.Reply {
		operations <- r.Operation
		return localstore.Reply{OK: true}
	}
	h.controller.start()
	oldEpoch := a.epoch
	h.now = h.now.Add(vaultIdleTimeout)
	h.idle = vaultIdleTimeout
	h.fire()
	if ctx.Err() != context.Canceled || !native.revoked || runtime.active || a.runtimeVault != nil || a.epoch <= oldEpoch {
		t.Fatal("idle lock retained work or temporary authority")
	}
	select {
	case op := <-operations:
		if op != "lock" {
			t.Fatalf("operation = %s", op)
		}
	case <-time.After(time.Second):
		t.Fatal("storage lock was not dispatched")
	}
	select {
	case f := <-uiQueue:
		f()
	case <-time.After(time.Second):
		t.Fatal("missing storage completion")
	}
	assertSessionRevoked(t, a, session)
	// A pre-lock successful unlock must not resurrect the revoked session.
	a.pending++
	a.completeStorage(localstore.Request{Operation: "list"}, oldEpoch, localstore.Reply{OK: true, State: a.snapshot})
	if a.unlocked() || a.session != nil || h.controller.active {
		t.Fatal("late completion resurrected session")
	}
}
