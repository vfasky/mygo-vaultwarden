// SPDX-License-Identifier: GPL-3.0-only
package organization

import (
	"context"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestOrgOperationsPanelConfirmationAndPartialResult(t *testing.T) {
	queue := make(chan func(), 1)
	called := make(chan []string, 1)
	p := NewOperationsPanel("org-1", []vaultwarden.VaultEntry{{ID: "one", OrganizationID: "org-1", Editable: true, Readable: true}, {ID: "hidden", OrganizationID: "org-1", Editable: true}, {ID: "other", OrganizationID: "org-2", Editable: true, Readable: true}}, func(ctx context.Context, org string, ids []string, a vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error) {
		called <- ids
		return vaultwarden.OrganizationOperationResult{IDs: ids, ReconcileRequired: true}, vaultwarden.ErrConflict
	}, func(f func()) { queue <- f })
	p.selectItem("hidden")
	p.selectItem("other")
	if len(p.ids()) != 0 {
		t.Fatal("permission leak")
	}
	p.selectItem("one")
	p.Start()
	if p.running {
		t.Fatal("missing confirmation accepted")
	}
	p.Confirmation = true
	p.Start()
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
	p.Confirmation = true
	p.Start()
	select {
	case <-called:
		t.Fatal("automatic retry")
	default:
	}
}
func TestOrgOperationsPanelCloseDiscardsLateResult(t *testing.T) {
	queue := make(chan func(), 1)
	started := make(chan struct{})
	p := NewOperationsPanel("org-1", []vaultwarden.VaultEntry{{ID: "one", OrganizationID: "org-1", Editable: true, Readable: true}}, func(ctx context.Context, _ string, ids []string, _ vaultwarden.CipherAction) (vaultwarden.OrganizationOperationResult, error) {
		close(started)
		<-ctx.Done()
		return vaultwarden.OrganizationOperationResult{IDs: ids, ReconcileRequired: true}, vaultwarden.ErrCancelled
	}, func(f func()) { queue <- f })
	p.selectItem("one")
	p.Confirmation = true
	p.Start()
	<-started
	p.Close()
	select {
	case f := <-queue:
		f()
	case <-time.After(time.Second):
		t.Fatal("cancel did not complete")
	}
	if !p.Closed || p.entries != nil || p.status != "" {
		t.Fatal("late result restored closed panel")
	}
}
