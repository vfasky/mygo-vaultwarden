// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

// Exercise the production controller's authenticated receipt adoption boundary.
// This deliberately does not claim Swift persistence or platform authentication.
func TestPolicyRecoveryControllerReceiptIsolation(t *testing.T) {
	for _, mode := range []string{"success", "revoked", "wrong-organization", "wrong-mutation", "wrong-policy-type", "retained-target", "lost-sibling", "lost-marker", "old-revision", "old-snapshot", "locked"} {
		t.Run(mode, func(t *testing.T) {
			a := organizationUIFixture(t, true, true, 0)
			defer a.stopNetwork()
			target := vaultwarden.PendingPolicyMutation{OrganizationID: "organization-1", PolicyType: 15, MutationID: "mutation-target"}
			sibling := vaultwarden.PendingPolicyMutation{OrganizationID: "sibling-organization", PolicyType: 5, MutationID: "mutation-sibling"}
			other := vaultwarden.PendingPolicyMutation{OrganizationID: "other-organization", PolicyType: 16, MutationID: "mutation-other"}
			pending := *a.vault
			pending.Version = 2
			pending.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{target, sibling, other}
			pending.QuarantinedOrganizations = []string{"organization-1", "sibling-organization", "other-organization"}
			state := *a.snapshot
			state.Revision, state.SnapshotID = "pending-revision", "pending-snapshot"
			if !a.adoptOrganizationIsolation(&state, &pending, target.OrganizationID) {
				t.Fatal("isolation receipt")
			}
			session := a.session
			before := a.vault
			restored := pending
			restored.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{sibling, other}
			restored.QuarantinedOrganizations = []string{"sibling-organization", "other-organization"}
			next := state
			next.Revision, next.SnapshotID = "restored-revision", "restored-snapshot"
			cleared := target
			isolated := false
			switch mode {
			case "revoked":
				isolated = true
				restored.QuarantinedOrganizations = pending.QuarantinedOrganizations
			case "wrong-organization":
				cleared = other
				restored.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{target, sibling}
			case "wrong-mutation":
				cleared.MutationID = "foreign"
			case "wrong-policy-type":
				cleared.PolicyType = 16
			case "retained-target":
				restored.PendingPolicyMutations = pending.PendingPolicyMutations
			case "lost-sibling":
				restored.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{other}
			case "lost-marker":
				restored.QuarantinedOrganizations = nil
			case "old-revision":
				next.Revision = state.Revision
			case "old-snapshot":
				next.SnapshotID = state.SnapshotID
			case "locked":
				a.lockInterface()
			}
			ok := a.adoptOrganizationSnapshot(&next, &restored, target.OrganizationID, isolated, cleared)
			if mode == "success" || mode == "revoked" {
				if !ok || a.session != session || a.vault.HasPendingPolicy(target) || !a.vault.HasPendingPolicy(sibling) || !a.vault.HasPendingPolicy(other) || a.sessionRevision != next.Revision {
					t.Fatal("target-only receipt did not preserve session and other barriers")
				}
				if a.adoptOrganizationSnapshot(&next, &restored, target.OrganizationID, isolated, cleared) {
					t.Fatal("replayed receipt")
				}
			} else if ok {
				t.Fatal("invalid receipt accepted")
			} else if mode == "locked" {
				if a.vault != nil || a.session != nil || a.organizationEditor != nil {
					t.Fatal("late receipt revived lock")
				}
			} else if a.vault != before || a.session != session || a.sessionRevision != state.Revision {
				t.Fatal("rejected receipt mutated active state")
			}
		})
	}
}
