// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

// The callback borrows this record while Session.mu is held. It must return
// before the record is consumed; it must not retain it or start asynchronous work.
type checkpointPolicyReceipt struct {
	prior    *snapshotPolicies
	revision string
}

// AcceptAuthenticatedReceipt is a privileged controller callback, called only
// after verifying saveSession operation, current scope, expected/new revision
// and unchanged SnapshotID. It never locks Session.mu: persistence runs with it
// held. Generic isolation checkpoints have no continuation record. This method
// verifies content equality; it cannot install policy from caller-owned data.
func (c SessionCheckpoint) AcceptAuthenticatedReceipt(vault *VaultData, previous, revision string) error {
	if c.receipt != nil {
		c.receipt.revision = ""
	}
	if previous == "" || revision == "" || revision == previous || len(revision) > 1024 {
		return ErrIdentity
	}
	if vault == nil && (c.receipt == nil || c.receipt.prior == nil) {
		return nil // Legacy migration persists tokens without installing authority.
	}
	if vault == nil || vault.Scope != c.Scope {
		return ErrIdentity
	}
	digest, err := snapshotDigest(vault)
	if err != nil {
		return err
	}
	if c.receipt == nil || c.receipt.prior == nil {
		return nil // Network-only migration checkpoint; no offline authority.
	}
	p := c.receipt.prior
	if p.revision != previous || p.policies.scope != c.Scope || p.digest != digest {
		return ErrIdentity
	}
	c.receipt.revision = revision
	return nil
}
