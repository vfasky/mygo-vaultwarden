// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"sync/atomic"
	"testing"
	"time"
)

type importLifecycleFake struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	err     error
}

func (f *importLifecycleFake) ImportPersonalBackup(ctx context.Context, _ vaultwarden.Scope, _ *vaultwarden.ImportPlan, _ func(vaultwarden.SessionCheckpoint) error) (vaultwarden.ImportResult, error) {
	f.calls.Add(1)
	close(f.entered)
	select {
	case <-f.release:
	case <-ctx.Done():
	}
	return vaultwarden.ImportResult{Entries: []vaultwarden.ImportEntry{{SourceID: "source", ID: "created"}}}, f.err
}

type importHostFake struct {
	current          bool
	settled, applied int
	outcome          backupImportOutcome
}

func (h *importHostFake) Current() bool                 { return h.current }
func (h *importHostFake) Settled()                      { h.settled++ }
func (h *importHostFake) Apply(out backupImportOutcome) { h.applied++; h.outcome = out }

func TestBackupImportControllerIndependentLifecycle(t *testing.T) {
	for _, mode := range []string{"normal", "cancel", "late", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			scope := vaultwarden.Scope{Server: "https://import.example.invalid", Account: "account"}
			state := &localstore.SnapshotStatus{Scope: &scope, Revision: "revision", SnapshotID: "snapshot", Available: true}
			importer := &importLifecycleFake{entered: make(chan struct{}), release: make(chan struct{})}
			if mode == "unknown" {
				importer.err = &vaultwarden.MutationUncertainError{Cause: vaultwarden.ErrNetwork}
			}
			host := &importHostFake{current: true}
			callbacks := make(chan func(), 1)
			storage := func(req localstore.Request) localstore.Reply {
				if req.Operation != localstore.OperationStatus {
					t.Errorf("unexpected storage operation: %v", req.Operation)
				}
				return localstore.Reply{OK: true, State: state}
			}
			controller := newBackupImportController(importer, host, storage, func(f func()) { callbacks <- f }, scope, state, &vaultwarden.ImportPlan{})
			defer controller.Close()
			if !controller.Start() || controller.Start() {
				t.Fatal("import may start only once")
			}
			select {
			case <-importer.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("import did not start")
			}
			if mode == "cancel" {
				controller.Close()
			}
			close(importer.release)
			if mode == "late" {
				host.current = false
			}
			select {
			case f := <-callbacks:
				f()
			case <-time.After(5 * time.Second):
				t.Fatal("missing completion")
			}
			if host.settled != 1 || importer.calls.Load() != 1 {
				t.Fatal("busy accounting or replay", host.settled, importer.calls.Load())
			}
			if mode == "cancel" || mode == "late" {
				if host.applied != 0 {
					t.Fatal("obsolete result reached UI")
				}
			} else {
				if host.applied != 1 || len(host.outcome.result.Entries) != 1 {
					t.Fatal("lost partial/result metadata")
				}
				if mode == "unknown" && !errors.Is(host.outcome.err, vaultwarden.ErrNetwork) {
					t.Fatal("lost unknown-write error")
				}
			}
			if controller.Start() {
				t.Fatal("terminal import replayed")
			}
		})
	}
}
