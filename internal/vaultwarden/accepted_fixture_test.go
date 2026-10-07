// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "testing"

func acceptedOwnerVault(t *testing.T, s *Session, v *VaultData) *VaultData {
	t.Helper()
	v = ownerVault(t, v)
	installFixtureSnapshot(t, s, v, s.authorizationRevision)
	return v
}
func acceptedCollectionManagerVault(t *testing.T, s *Session, v *VaultData) *VaultData {
	t.Helper()
	v = collectionManagerVault(t, v)
	installFixtureSnapshot(t, s, v, s.authorizationRevision)
	return v
}
func acceptedGroupsVault(t *testing.T, s *Session, v *VaultData) *VaultData {
	t.Helper()
	v = groupsEnabledVault(t, v)
	installFixtureSnapshot(t, s, v, s.authorizationRevision)
	return v
}
func acceptedBulkFixture(t *testing.T, s *Session, scope Scope, deleted bool) *VaultData {
	t.Helper()
	v := bulkFixture(scope, deleted)
	installFixtureSnapshot(t, s, v, "bulk-revision")
	return v
}
