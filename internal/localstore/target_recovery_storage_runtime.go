// SPDX-License-Identifier: GPL-3.0-only
package localstore

import "github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"

// A purpose=recovery native runtime lease, created by #14 only after validating
// the actual Session proof and this immutable dispatch. A secret-copy lease is
// never accepted here. These are capabilities, never loggable identifiers.
type TargetRecoveryRuntimeAuthority struct {
	Scope          vaultwarden.Scope `json:"scope"`
	Generation     uint64            `json:"generation"`
	DeadlineUnixMS int64             `json:"deadlineUnixMS"`
	LeaseID        string            `json:"leaseID"`
	OperationID    string            `json:"operationID"`
	SummaryHash    string            `json:"summaryHash"`
}
type TargetRecoveryProtection struct {
	Scope                    vaultwarden.Scope                   `json:"scope"`
	PendingPolicyMutations   []vaultwarden.PendingPolicyMutation `json:"pendingPolicyMutations"`
	QuarantinedOrganizations []string                            `json:"quarantinedOrganizations"`
}

func NewTargetRecoveryRuntimeStorage(state *SnapshotStatus, epoch uint64, currentEpoch func() uint64,
	authority TargetRecoveryRuntimeAuthority, call func(Request) Reply) (*TargetRecoveryStorage, error) {
	if state == nil || state.Revision == "" || epoch == 0 || currentEpoch == nil || currentEpoch() != epoch || call == nil || authority.Generation == 0 || len(authority.LeaseID) != 64 || authority.OperationID == "" || !targetValidHash(authority.SummaryHash) {
		return nil, ErrTargetRecovery
	}
	return &TargetRecoveryStorage{scope: authority.Scope, localScope: state.Scope, snapshotID: state.SnapshotID, revision: state.Revision, epoch: epoch, currentEpoch: currentEpoch, call: call, runtime: &authority}, nil
}

// Explicit user-presence operation. Never invoke from BeforeDispatch/Session lock.
// Returns only local restriction projection and, if present, the existing #17
// recovery journal needed by its dedicated algorithm; no ordinary vault lease.
func (s *TargetRecoveryStorage) InspectLocalTarget() (Reply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding == nil {
		return Reply{}, ErrTargetRecovery
	}
	req := s.request(OperationTargetRecoveryInspectLocal)
	target := s.binding.Target
	req.Scope = &target
	reply, err := s.receive(req)
	if err == nil && (reply.TargetProtection == nil || reply.TargetProtection.Scope != target) {
		s.receipt = nil
		return Reply{}, ErrTargetRecovery
	}
	return reply, err
}
