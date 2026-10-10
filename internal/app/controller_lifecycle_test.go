// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestControllerLeaseRevokeDuringStorage(t *testing.T) {
	a := writableUIFixture(t)
	a.snapshot.SnapshotID = "fixture-snapshot"
	defer a.stopNetwork()
	a.advanceEpoch()
	l := a.newControllerLease()
	if l == nil {
		t.Fatal("lease")
	}
	prior, _ := l.state()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- l.check(func(localstore.Request) localstore.Reply {
			close(entered)
			<-release
			return localstore.Reply{OK: true, State: &prior}
		})
	}()
	<-entered
	a.advanceEpoch()
	close(release)
	if err := <-done; !errors.Is(err, vaultwarden.ErrCancelled) {
		t.Fatal("stale storage adopted", err)
	}
}
func TestControllerLeaseConcurrentChecksAndLock(t *testing.T) {
	a := writableUIFixture(t)
	a.snapshot.SnapshotID = "fixture-snapshot"
	a.advanceEpoch()
	l := a.newControllerLease()
	prior, _ := l.state()
	storage := func(localstore.Request) localstore.Reply { return localstore.Reply{OK: true, State: &prior} }
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = l.check(storage)
			}
		}()
	}
	a.stopNetwork()
	wg.Wait()
	if err := l.check(storage); !errors.Is(err, vaultwarden.ErrCancelled) {
		t.Fatal(err)
	}
}
func TestControllerSendNavigationAndClose(t *testing.T) {
	a := writableUIFixture(t)
	a.snapshot.SnapshotID = "fixture-snapshot"
	defer a.stopNetwork()
	a.deviceID = "fixture-device-identifier"
	var wire map[string]any
	if err := json.Unmarshal(a.vault.Sync, &wire); err != nil {
		t.Fatal(err)
	}
	wire["sends"] = []any{}
	a.vault.Sync, _ = json.Marshal(wire)
	if err := a.session.(*vaultwarden.Session).AcceptAuthenticatedSnapshot(a.vault, a.sessionRevision); err != nil {
		t.Fatal(err)
	}
	state := *a.snapshot
	storage := func(localstore.Request) localstore.Reply { return localstore.Reply{OK: true, State: &state} }
	queue := make(chan func(), 8)
	a.openSendWith(func(f func()) { queue <- f }, storage, false)
	if a.sendPanel == nil || a.category != "send" {
		t.Fatal("navigation")
	}
	p := a.sendPanel
	tt := ui.NewTester(a.view, 1280, 1800)
	if !tt.HasText("新建文本") {
		t.Fatal("main Send body missing")
	}
	p.New(0)
	p.Fields.Text = "private send"
	// A queued worker result after leaving the page must still be cleaned.
	draft := p.Draft
	p.Draft = nil
	p.Run(func(context.Context) send.Result { return send.Result{Draft: draft} })
	a.category = "personal"
	tt.Frame()
	select {
	case f := <-queue:
		f()
	case <-time.After(time.Second):
		t.Fatal("dispatch")
	}
	if a.sendPanel != nil || !p.Closed || p.Fields.Text != "" || draft.CanEdit() {
		t.Fatal("late Send result revived")
	}
}
func TestControllerMFACancelAndRecoveryAccountBinding(t *testing.T) {
	a := &app{showLogin: true}
	a.advanceEpoch()
	queue := make(chan func(), 8)
	done := make(chan vaultwarden.MFAResponse, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		r, _ := a.requestMFA(ctx, "https://one.example", "a@example.invalid", a.workerEpoch.Load(), vaultwarden.MFAChallenge{Providers: map[string]json.RawMessage{"0": json.RawMessage(`{}`)}}, func(f func()) { queue <- f }, nil)
		done <- r
	}()
	select {
	case f := <-queue:
		f()
	case <-time.After(time.Second):
		t.Fatal("prompt")
	}
	f := a.mfaLogin.form
	f.Provider = 8
	f.Token = "recovery"
	f.Dispatch()
	if !f.Confirming {
		t.Fatal("missing explicit confirmation")
	}
	f.Dispatch()
	r := <-done
	defer clear(r.Token)
	if r.Provider != 8 || !r.ConfirmRemoveAllMFA || r.Remember {
		t.Fatal("delivery")
	}
	a.resetLoginForm()
	if a.mfaWarnings.warning("https://one.example", "a@example.invalid") == "" {
		t.Fatal("warning discarded")
	}
	if a.mfaWarnings.warning("https://two.example", "a@example.invalid") != "" || a.mfaWarnings.warning("https://one.example", "b@example.invalid") != "" {
		t.Fatal("warning moved account")
	}
}
func TestControllerMFALatePromptDoesNotRevive(t *testing.T) {
	a := &app{showLogin: true}
	a.advanceEpoch()
	epoch := a.epoch
	queue := make(chan func(), 1)
	done := make(chan error, 1)
	go func() {
		_, err := a.requestMFA(context.Background(), "https://one.example", "a@example.invalid", epoch, vaultwarden.MFAChallenge{}, func(f func()) { queue <- f }, nil)
		done <- err
	}()
	f := <-queue
	a.stopNetwork()
	f()
	select {
	case err := <-done:
		if !errors.Is(err, vaultwarden.ErrCancelled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
	if a.mfaLogin != nil || a.showVerification {
		t.Fatal("late prompt resurrected")
	}
}
