// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func orgUIComplete(t *testing.T, q chan func()) {
	t.Helper()
	select {
	case f := <-q:
		f()
	case <-time.After(time.Second):
		t.Fatal("completion missing")
	}
}
func TestOrgBusinessCopyPermissionConfirmationAndFreeze(t *testing.T) {
	q := make(chan func(), 1)
	calls := 0
	p := newOrgCopyPanel(vaultwarden.VaultEntry{ID: "item", Title: "Item", Readable: true, Editable: true, RequiresPassword: true}, []orgCollectionChoice{{ID: "c", OrganizationID: "org", Name: "Collection", Writable: true}}, func(_ context.Context, id, org, col string) (vaultwarden.CipherDocument, error) {
		calls++
		if id != "item" || org != "org" || col != "c" {
			t.Error("identity changed")
		}
		return vaultwarden.CipherDocument{}, vaultwarden.ErrPermission
	}, func(f func()) { q <- f })
	p.target = 0
	p.start()
	if p.flow.running {
		t.Fatal("unconfirmed")
	}
	p.flow.confirm = true
	p.start()
	orgUIComplete(t, q)
	if calls != 1 || !p.flow.terminal || p.flow.status == "" {
		t.Fatal("missing error")
	}
	p.flow.confirm = true
	p.start()
	if calls != 1 {
		t.Fatal("retry")
	}
	p.Close()
}
func TestOrgBusinessCollectionScopeAndIsolationOutcome(t *testing.T) {
	q := make(chan func(), 1)
	p := newOrgCollectionPanel(vaultwarden.VaultEntry{ID: "i", OrganizationID: "org", Readable: true, Editable: true}, []orgCollectionChoice{{ID: "one", OrganizationID: "org", Writable: true}, {ID: "other", OrganizationID: "other", Writable: true}}, []string{"one"}, func(_ context.Context, id string, ids []string) error {
		if id != "i" || len(ids) != 1 || ids[0] != "one" {
			t.Error("cross-org")
		}
		return vaultwarden.ErrCheckpoint
	}, func(f func()) { q <- f })
	if len(p.choices) != 1 {
		t.Fatal("cross org displayed")
	}
	p.flow.confirm = true
	p.start()
	orgUIComplete(t, q)
	if !strings.Contains(p.flow.rows[0], "隔离") {
		t.Fatal("isolation outcome lost")
	}
}
func TestOrgBusinessAPIKeyCloseErasesLateSecret(t *testing.T) {
	q := make(chan func(), 1)
	started := make(chan struct{})
	var password []byte
	p := newOrgAPIKeyPanel(true, func(ctx context.Context, pw []byte, _ bool, borrow func(string, []byte, time.Time) error) error {
		password = pw
		close(started)
		<-ctx.Done()
		return borrow("organization.org", []byte("secret"), time.Time{})
	}, func(f func()) { q <- f })
	p.password = "password"
	p.flow.confirm = true
	p.start()
	<-started
	p.Close()
	orgUIComplete(t, q)
	if p.key != "" || p.password != "" || p.clientID != "" {
		t.Fatal("late secret leak")
	}
	for _, b := range password {
		if b != 0 {
			t.Fatal("borrowed password retained")
		}
	}
}
func TestOrgBusinessDirectoryPartialAndPreview(t *testing.T) {
	q := make(chan func(), 1)
	var borrowed []byte
	p := newOrgDirectoryPanel(true, true, func(_ context.Context, secret []byte, input vaultwarden.OrganizationDirectoryImport) (vaultwarden.OrganizationDirectoryResult, error) {
		borrowed = secret
		if len(input.Members) != 1 || len(input.Groups) != 1 || !input.OverwriteExisting {
			t.Error("preview lost")
		}
		return vaultwarden.OrganizationDirectoryResult{ReconcileRequired: true, Reconciliation: &vaultwarden.OrganizationDirectoryReconciliation{Rows: []vaultwarden.OrganizationDirectoryRowResult{{ExternalID: "member", Kind: "member", Verified: true}, {ExternalID: "team", Kind: "group"}}}}, vaultwarden.ErrProtocol
	}, func(f func()) { q <- f })
	p.email = "ONE@example.invalid"
	p.external = "member"
	p.addMember()
	p.email = "one@example.invalid"
	p.external = "duplicate"
	p.addMember()
	if len(p.members) != 1 {
		t.Fatal("duplicate accepted")
	}
	p.name = "Team"
	p.groupExternal = "team"
	p.groupMembers["member"] = true
	p.addGroup()
	p.overwrite = true
	p.secret = "secret"
	p.flow.confirm = true
	p.start()
	orgUIComplete(t, q)
	if len(p.flow.rows) != 3 || !strings.Contains(p.flow.rows[1], "已确认") || !strings.Contains(p.flow.rows[2], "未知") {
		t.Fatal(p.flow.rows)
	}
	for _, b := range borrowed {
		if b != 0 {
			t.Fatal("secret retained")
		}
	}
}
func TestOrgBusinessImportMappingAndCloseDuringFlight(t *testing.T) {
	raw := []byte(`{"encrypted":false,"collections":[{"id":"11111111-1111-4111-8111-111111111111","name":"Source"}],"items":[{"id":"22222222-2222-4222-8222-222222222222","type":2,"name":"Note","favorite":false,"reprompt":0,"collectionIds":["11111111-1111-4111-8111-111111111111"],"secureNote":{"type":0}}]}`)
	plan, err := vaultwarden.ParseBitwardenOrganizationJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := make(chan func(), 1)
	started := make(chan struct{})
	p := newOrgImportPanel(plan, "Bitwarden 官方明文 JSON", []orgCollectionChoice{{ID: "target", Writable: true}}, false, func(ctx context.Context, plan *vaultwarden.OrganizationImportPlan, m map[string]string) (vaultwarden.OrganizationOperationResult, error) {
		close(started)
		<-ctx.Done()
		if len(plan.PreviewItems()) != 1 || m["11111111-1111-4111-8111-111111111111"] != "target" {
			t.Error("plan cleared during worker")
		}
		return vaultwarden.OrganizationOperationResult{}, vaultwarden.ErrCancelled
	}, func(f func()) { q <- f })
	if p.ready() {
		t.Fatal("missing mapping accepted")
	}
	p.mappings["11111111-1111-4111-8111-111111111111"] = "target"
	p.flow.confirm = true
	p.start()
	<-started
	p.Close()
	orgUIComplete(t, q)
	if len(plan.PreviewItems()) != 0 || p.flow.status != "" {
		t.Fatal("plan retained or late result")
	}
}
