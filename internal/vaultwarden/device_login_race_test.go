// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeviceLoginApprovalThenAccountSwitch(t *testing.T) {
	f, c, scope := newDeviceLoginFixture(t)
	f.tokenHook = func() { f.epoch.Store(2) }
	flow, e := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
	if e != nil {
		t.Fatal(e)
	}
	defer flow.Close()
	result, e := flow.Run(nil)
	if !errors.Is(e, ErrExpired) || result.Session != nil {
		t.Fatal("late approved grant adopted", e)
	}
}
func TestDeviceLoginPollingCompensatesUnavailableSocket(t *testing.T) {
	f, c, scope := newDeviceLoginFixture(t)
	f.approve = false
	flow, e := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
	if e != nil {
		t.Fatal(e)
	}
	defer flow.Close()
	done := make(chan error, 1)
	go func() { _, e := flow.Run(nil); done <- e }()
	// The fixture returns 404 for the websocket hub. Polling still finds approval.
	f.mu.Lock()
	f.approve = true
	f.mu.Unlock()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("polling compensation missing")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.grants != 1 {
		t.Fatal("duplicate exchange", f.grants)
	}
}
func TestDeviceLoginRejectedAndExpired(t *testing.T) {
	for _, expired := range []bool{false, true} {
		f, c, scope := newDeviceLoginFixture(t)
		f.responseStatus = 404
		flow, e := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
		if e != nil {
			t.Fatal(e)
		}
		if expired {
			flow.pending.mu.Lock()
			flow.pending.expires = time.Now().Add(-time.Second)
			flow.pending.mu.Unlock()
		}
		_, e = flow.Run(nil)
		flow.Close()
		if expired && !errors.Is(e, ErrExpired) || !expired && !errors.Is(e, ErrDeviceRejected) {
			t.Fatal("terminal source", e)
		}
	}
}
func TestDeviceLoginPasswordBindingRejectsChangedState(t *testing.T) {
	for _, mode := range []string{"wrapper", "epoch", "revision", "cancel", "lock"} {
		t.Run(mode, func(t *testing.T) {
			f, c, scope := newDeviceLoginFixture(t)
			flow, e := c.BeginDeviceLogin(context.Background(), "fixture@example.invalid", scope, 1, f.check)
			if e != nil {
				t.Fatal(e)
			}
			defer flow.Close()
			result, e := flow.Run(nil)
			if e != nil {
				t.Fatal(e)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			f.mu.Lock()
			f.preloginHook = func() { close(entered); <-release }
			f.mu.Unlock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- flow.BindPassword(ctx, []byte("fixture-password")) }()
			<-entered
			s := result.Session
			switch mode {
			case "cancel":
				cancel()
			case "lock":
				s.Close()
			default:
				s.mu.Lock()
				switch mode {
				case "wrapper":
					s.wrapped = "changed"
				case "epoch":
					s.authorizationEpoch++
				case "revision":
					s.authorizationRevision = "replacement"
				}
				s.mu.Unlock()
			}
			close(release)
			if e = <-done; e == nil {
				t.Fatal("stale binding installed")
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.passwordUnlock != nil {
				t.Fatal("password wrapper retained")
			}
		})
	}
}
