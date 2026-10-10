// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func TestControllerAuthenticatedUnlockRequiresCompletePolicyReceipt(t *testing.T) {
	source := writableUIFixture(t)
	defer source.stopNetwork()
	for _, scenario := range []string{"authenticated", "legacy", "modified-identity", "wrong-revision", "late-epoch", "status"} {
		t.Run(scenario, func(t *testing.T) {
			a := passwordLockedApp()
			defer a.stopNetwork()
			a.pending, a.epoch = 1, 2
			v := *source.vault
			v.Sync = append([]byte(nil), v.Sync...)
			state := *a.snapshot
			req := storageRequest{Operation: "listPassword", ExpectedRevision: state.Revision, Scope: state.Scope}
			epoch := a.epoch
			switch scenario {
			case "legacy", "modified-identity":
				var body map[string]any
				_ = json.Unmarshal(v.Sync, &body)
				if scenario == "legacy" {
					delete(body, "policies")
				} else {
					body["profile"].(map[string]any)["id"] = "other"
				}
				v.Sync, _ = json.Marshal(body)
			case "wrong-revision":
				req.ExpectedRevision = "stale"
			case "late-epoch":
				epoch--
			case "status":
				req.Operation = "status"
			}
			a.completeStorage(req, epoch, storageReply{OK: true, State: &state, Session: savedUIFixture(t, a), Vault: &v, Items: []displayCredential{{ID: "unfiltered", Title: "must not appear"}}})
			if scenario == "authenticated" {
				if a.vault == nil || len(a.items) != 1 || a.items[0].ID != "card-1" {
					t.Fatal("authenticated vault not adopted", a.status)
				}
				if err := a.session.(*vaultwarden.Session).ValidateAuthenticatedSnapshot(a.vault, a.sessionRevision); err != nil {
					t.Fatal(err)
				}
			} else if a.vault != nil || len(a.items) != 0 {
				t.Fatal("unverified metadata adopted", scenario)
			}
			if scenario == "legacy" && (!a.sessionOwnsSnapshot() || a.status != "本机快照需要更新策略，请先同步后使用密码库。") {
				t.Fatal("legacy lost network migration capability or actionable status", a.status)
			}
		})
	}
}

func TestAdoptVaultCannotAuthorizePublicMutationOrRevision(t *testing.T) {
	for _, scenario := range []string{"content", "revision", "revoke"} {
		t.Run(scenario, func(t *testing.T) {
			a := writableUIFixture(t)
			defer a.stopNetwork()
			v := *a.vault
			session := a.session.(*vaultwarden.Session)
			switch scenario {
			case "content":
				v.QuarantinedOrganizations = []string{"unverified"}
			case "revision":
				a.sessionRevision = "borrowed"
				_ = session.BindSnapshotRevision(*a.liveScope, a.sessionRevision)
			case "revoke":
				session.RevokeItemAuthorizations()
			}
			if err := a.adoptVault(&v); err == nil {
				t.Fatal("adoption minted offline permission")
			}
			if a.vault != nil || len(a.items) != 0 {
				t.Fatal("failed adoption retained display data")
			}
		})
	}
}
