// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"sync/atomic"
	"testing"
)

type organizationHostFake struct {
	current               bool
	isolated, checkpoints int
}

func (h *organizationHostFake) Current(orgServiceSnapshot) bool         { return h.current }
func (h *organizationHostFake) Busy() bool                              { return false }
func (h *organizationHostFake) Window() *mygo.Window                    { panic("unexpected window") }
func (h *organizationHostFake) Warning(vaultwarden.Scope) string        { return "" }
func (h *organizationHostFake) RequestSync()                            { panic("unexpected sync") }
func (h *organizationHostFake) AdoptIsolation(localstore.Reply, string) { h.isolated++ }
func (h *organizationHostFake) AdoptNotificationCheckpoint(*localstore.SnapshotStatus) {
	h.checkpoints++
}
func (h *organizationHostFake) ResourceSourceCurrent(orgServiceSnapshot, localstore.SnapshotStatus) bool {
	panic("unexpected resource work")
}
func (h *organizationHostFake) AdoptResourceCheckpoint(*localstore.SnapshotStatus) error {
	panic("unexpected checkpoint")
}
func (h *organizationHostFake) ResourceFailure(localstore.Reply, error) { panic("unexpected failure") }
func (h *organizationHostFake) AdoptResourceSnapshot(orgServiceSnapshot, localstore.Reply) (orgResourceAdoption, error) {
	panic("unexpected snapshot")
}
func (h *organizationHostFake) ResourceNotifications() { panic("unexpected notifications") }
func (h *organizationHostFake) RecoveryOutcome(orgServiceSnapshot, vaultwarden.Scope, *localstore.SnapshotStatus, string, bool) {
	panic("unexpected recovery")
}

func TestOrganizationControllerHostReceiptLifecycle(t *testing.T) {
	for _, mode := range []string{"isolation", "checkpoint", "late", "closed"} {
		t.Run(mode, func(t *testing.T) {
			host := &organizationHostFake{current: true}
			ctx, cancel := context.WithCancel(context.Background())
			lease := &controllerLease{active: true, clock: &atomic.Uint64{}, checkpoint: &localstore.SnapshotStatus{Revision: "checkpoint"}}
			queue := make(chan func(), 1)
			controller := &orgServicesController{host: host, ctx: ctx, cancel: cancel, snapshot: orgServiceSnapshot{lease: lease}, dispatch: func(f func()) { queue <- f }}
			defer controller.Close()
			if mode != "checkpoint" {
				controller.isolation = &localstore.Reply{OK: true}
				controller.isolationOrg = "organization"
			}
			cleaned := 0
			controller.deliver(func() { cleaned++ })
			if mode == "late" {
				host.current = false
			}
			if mode == "closed" {
				controller.Close()
			}
			(<-queue)()
			if cleaned != 1 {
				t.Fatal("component cleanup must run for every outcome")
			}
			switch mode {
			case "isolation":
				if host.isolated != 1 || host.checkpoints != 0 {
					t.Fatal("isolation must precede checkpoint adoption")
				}
			case "checkpoint":
				if host.checkpoints != 1 || host.isolated != 0 {
					t.Fatal("checkpoint was not delivered")
				}
			default:
				if host.isolated != 0 || host.checkpoints != 0 {
					t.Fatal("late/closed receipt mutated host")
				}
			}
		})
	}
}
