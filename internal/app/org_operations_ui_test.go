// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestOrgOperationsPanelConfirmationAndPartialResult(t *testing.T) {
	queue := make(chan func(), 1)
	called := make(chan []string, 1)
	p := newOrgOperationsPanel("org-1", []vaultwarden.VaultEntry{{ID: "one", OrganizationID: "org-1", Editable: true, Readable: true}, {ID: "hidden", OrganizationID: "org-1", Editable: true}, {ID: "other", OrganizationID: "org-2", Editable: true, Readable: true}}, func(ctx context.Context, org string, ids []string, a vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error) {
		called <- ids
		return vaultwarden.OrganizationOperationResult{IDs: ids, ReconcileRequired: true}, vaultwarden.ErrConflict
	}, func(f func()) { queue <- f })
	p.selectItem("hidden")
	p.selectItem("other")
	if len(p.ids()) != 0 {
		t.Fatal("permission leak")
	}
	p.selectItem("one")
	p.start()
	if p.running {
		t.Fatal("missing confirmation accepted")
	}
	p.confirmation = true
	p.start()
	select {
	case ids := <-called:
		if len(ids) != 1 || ids[0] != "one" {
			t.Fatal(ids)
		}
	case <-time.After(time.Second):
		t.Fatal("not dispatched")
	}
	select {
	case f := <-queue:
		f()
	case <-time.After(time.Second):
		t.Fatal("no completion")
	}
	if !p.terminal || p.running || p.status == "" {
		t.Fatal("partial failure did not freeze")
	}
	p.confirmation = true
	p.start()
	select {
	case <-called:
		t.Fatal("automatic retry")
	default:
	}
}
func TestOrgOperationsPanelCloseDiscardsLateResult(t *testing.T) {
	queue := make(chan func(), 1)
	started := make(chan struct{})
	p := newOrgOperationsPanel("org-1", []vaultwarden.VaultEntry{{ID: "one", OrganizationID: "org-1", Editable: true, Readable: true}}, func(ctx context.Context, _ string, ids []string, _ vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error) {
		close(started)
		<-ctx.Done()
		return vaultwarden.OrganizationOperationResult{IDs: ids, ReconcileRequired: true}, vaultwarden.ErrCancelled
	}, func(f func()) { queue <- f })
	p.selectItem("one")
	p.confirmation = true
	p.start()
	<-started
	p.Close()
	select {
	case f := <-queue:
		f()
	case <-time.After(time.Second):
		t.Fatal("cancel did not complete")
	}
	if !p.closed || p.entries != nil || p.status != "" {
		t.Fatal("late result restored closed panel")
	}
}
