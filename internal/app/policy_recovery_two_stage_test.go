// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestPolicyRecoveryControllerTwoStage(t *testing.T) {
	for _, mode := range []string{"success", "changed-policy", "late-preview", "wrong-preview-receipt", "stale-preview", "ordinary-sync", "cancel", "wrong-final-receipt", "late-final"} {
		t.Run(mode, func(t *testing.T) {
			a := organizationUIFixture(t, true, true, 0)
			defer a.stopNetwork()
			var mu sync.Mutex
			serverSync := append([]byte(nil), a.vault.Sync...)
			syncCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.URL.Path {
				case "/identity/connect/token":
					_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture-access", "refresh_token": "fixture-next-refresh", "expires_in": 3600, "token_type": "Bearer"})
				case "/api/sync":
					syncCount++
					_, _ = w.Write(serverSync)
				default:
					t.Error("unexpected request", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			a.session.(*vaultwarden.Session).Close()
			scope := *a.liveScope
			scope.Server = server.URL
			a.liveScope = &scope
			a.snapshot.Scope = &scope
			v := *a.vault
			v.Scope = scope
			session, err := vaultwarden.RestoreSessionFromAuthenticatedSnapshot(savedUIFixture(t, a), scope, a.snapshot.PasswordUnlock, &v, a.sessionRevision)
			if err != nil {
				t.Fatal(err)
			}
			a.session = session
			a.vault = &v
			target := vaultwarden.PendingPolicyMutation{OrganizationID: "organization-1", PolicyType: 15, MutationID: "target"}
			other := vaultwarden.PendingPolicyMutation{OrganizationID: "other-org", PolicyType: 5, MutationID: "other"}
			pending := v
			pending.Version = 2
			pending.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{target, other}
			pending.QuarantinedOrganizations = []string{"organization-1", "other-org"}
			state := *a.snapshot
			state.Revision = "pending"
			state.SnapshotID = "pending-id"
			if !a.adoptOrganizationIsolation(&state, &pending, target.OrganizationID) {
				t.Fatal("pending adoption")
			}
			a.openOrganizationEditor(target.OrganizationID)
			e, epoch := a.organizationEditor, a.epoch
			var durableSession []byte
			persist := func(c vaultwarden.SessionCheckpoint) error {
				durableSession = append([]byte(nil), c.Session...)
				previous := a.sessionRevision
				if err := c.AcceptAuthenticatedReceipt(a.vault, previous, "token-checkpoint"); err != nil {
					return err
				}
				a.sessionRevision = "token-checkpoint"
				a.snapshot.Revision = "token-checkpoint"
				a.itemsRevision = "token-checkpoint"
				return nil
			}
			initial, err := session.SyncWithCheckpoint(context.Background(), persist)
			if err != nil || len(durableSession) == 0 {
				t.Fatal("preview sync/checkpoint", err)
			}
			defer clear(durableSession)
			review, err := session.ReviewPendingPolicy(initial, target)
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			preview := *initial.Vault
			preview.Version = 2
			preview.PendingPolicyMutations = pending.PendingPolicyMutations
			preview.QuarantinedOrganizations = pending.QuarantinedOrganizations
			previewState := *a.snapshot
			previewState.Revision = "preview"
			previewState.SnapshotID = "preview-id"
			if mode == "late-preview" {
				a.lockInterface()
			}
			if mode == "wrong-preview-receipt" {
				previewState.SnapshotID = a.snapshot.SnapshotID
			}
			ok := a.adoptPolicyRecoveryPreview(epoch, e, &previewState, &preview, review)
			if mode == "late-preview" || mode == "wrong-preview-receipt" {
				if ok {
					t.Fatal("bad preview bound")
				}
				if mode == "late-preview" && (a.session != nil || a.vault != nil) {
					t.Fatal("late preview revived lock")
				}
				return
			}
			if !ok || e.policyRecovery != review || e.confirmation != "policy-restore" || a.organizationEditor != e {
				t.Fatal("controller failed to bind preview")
			}
			if mode == "stale-preview" {
				if err := session.AcceptAuthenticatedSnapshot(a.vault, "later"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "changed-policy" {
				mu.Lock()
				var obj map[string]any
				_ = json.Unmarshal(serverSync, &obj)
				policies := []any{map[string]any{"id": "p", "organizationId": target.OrganizationID, "type": 15, "enabled": true, "data": []int{1}}}
				obj["policies"], obj["policiesNew"] = policies, policies
				serverSync, _ = json.Marshal(obj)
				mu.Unlock()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			var fresh vaultwarden.SyncResult
			if mode == "ordinary-sync" {
				fresh, err = session.SyncWithCheckpoint(ctx, persist)
			} else {
				fresh, err = session.SyncForPolicyRecovery(ctx, a.vault, review, persist)
			}
			if mode == "stale-preview" || mode == "cancel" {
				if err == nil {
					t.Fatal("stale/cancelled confirmation accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			err = session.ValidatePolicyRecovery(fresh, review)
			if mode == "ordinary-sync" || mode == "changed-policy" {
				if err == nil || !a.vault.HasPendingPolicy(target) {
					t.Fatal("unrelated/changed sync cleared barrier")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			requests := syncCount
			mu.Unlock()
			if requests != 2 {
				t.Fatal("recovery did not issue exactly two fresh syncs", requests)
			}
			restored := *fresh.Vault
			restored.Version = 2
			restored.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{other}
			restored.QuarantinedOrganizations = []string{"other-org"}
			final := previewState
			final.Revision = "restored"
			final.SnapshotID = "restored-id"
			if mode == "wrong-final-receipt" {
				restored.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{target}
			}
			if mode == "late-final" {
				a.lockInterface()
			}
			ok = a.adoptOrganizationSnapshot(&final, &restored, target.OrganizationID, false, target)
			if mode == "wrong-final-receipt" || mode == "late-final" {
				if ok {
					t.Fatal("bad final adopted")
				}
				return
			}
			if !ok || a.session != session || a.vault.HasPendingPolicy(target) || !a.vault.HasPendingPolicy(other) || len(a.vault.QuarantinedOrganizations) != 1 {
				t.Fatal("dedicated final receipt did not preserve unrelated state")
			}
		})
	}
}
