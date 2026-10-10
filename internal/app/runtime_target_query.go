// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

var errRuntimeTargetBlocked = errors.New("此账号存在未解除的跨账号恢复记录；请先通过当前主密码登录并完成专用恢复核验")

func sameStorageSource(a, b *snapshotStatus) bool {
	if a == nil || b == nil || a.Revision != b.Revision || a.SnapshotID != b.SnapshotID || a.Available != b.Available || a.RecoveryPending != b.RecoveryPending || a.AccountSwitchPending != b.AccountSwitchPending || a.TargetRecoveryPresent != b.TargetRecoveryPresent {
		return false
	}
	if a.Scope == nil || b.Scope == nil {
		return a.Scope == nil && b.Scope == nil
	}
	return *a.Scope == *b.Scope
}

// This facade never exposes targetRecoveryStorage or a writable recovery
// capability. Its domain-separated query description is not RecoveryDispatch
// and therefore cannot authorize Begin even if its opaque lease is replayed.
func checkRuntimeTargetProtection(cap *vaultwarden.RuntimeAuthority, vault *vaultwarden.VaultData, source *snapshotStatus, epoch uint64, clock *atomic.Uint64, storage func(storageRequest) storageReply, native *nativeRuntimeSecrets, projections ...**vaultwarden.VaultData) error {
	if cap == nil || vault == nil || source == nil || source.Revision == "" || clock.Load() != epoch {
		return vaultwarden.ErrIdentity
	}
	if err := cap.Check(vault); err != nil {
		return err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	queryID := hex.EncodeToString(id[:])
	digest := targetRecoveryHash(vault.Sync)
	var binding runtimeSecretRequest
	var protectedDeadline time.Time
	err := cap.WithProtection(vault, func(deadline time.Time) error { protectedDeadline = deadline; return nil })
	if err == nil {
		binding, err = native.activateBound(cap.Scope(), "recovery", protectedDeadline, func(generation uint64, deadlineMS int64) (string, string) {
			description, _ := json.Marshal(struct {
				Purpose             string            `json:"purpose"`
				QueryID             string            `json:"queryId"`
				Scope               vaultwarden.Scope `json:"scope"`
				SyncHash, Authority string
				Epoch, Generation   uint64
				Deadline            int64
			}{"mygo-runtime-target-block-query-v1", queryID, cap.Scope(), digest, cap.Revision(), epoch, generation, deadlineMS})
			return queryID, targetRecoveryHash(description)
		})
	}
	if err != nil {
		return err
	}
	defer native.Revoke()
	if clock.Load() != epoch || cap.CheckLease() != nil {
		return vaultwarden.ErrCancelled
	}
	authority := targetRecoveryRuntimeAuthority{Scope: binding.Scope, Generation: binding.Generation, DeadlineUnixMS: binding.DeadlineUnixMS, LeaseID: binding.LeaseID, OperationID: binding.OperationID, SummaryHash: binding.SummaryHash}
	scope := cap.Scope()
	reply := storage(storageRequest{Operation: "targetRecoveryRuntimePending", Scope: &scope, ExpectedRevision: source.Revision, TargetRuntime: &authority})
	defer func() {
		for i := range reply.TargetRecords {
			reply.TargetRecords[i].Close()
		}
	}()
	if !reply.OK {
		return reply.failure()
	}
	if !sameStorageSource(source, reply.State) || len(reply.TargetRecords) > 1024 || clock.Load() != epoch || cap.CheckLease() != nil {
		return vaultwarden.ErrIdentity
	}
	projection := &vaultwarden.VaultData{Version: 1, Scope: scope}
	seen := map[string]bool{}
	for _, record := range reply.TargetRecords {
		if !validTargetRecord(record) || seen[record.Binding.OperationID] || (record.Binding.Actor != scope && record.Binding.Target != scope) {
			return errTargetRecovery
		}
		seen[record.Binding.OperationID] = true
		if record.Binding.Target == scope && record.Protection != nil {
			if record.Protection.Scope != scope {
				return errTargetRecovery
			}
			for _, pending := range record.Protection.PendingPolicyMutations {
				if !projection.HasPendingPolicy(pending) {
					projection.PendingPolicyMutations = append(projection.PendingPolicyMutations, pending)
				}
			}
			for _, id := range record.Protection.QuarantinedOrganizations {
				found := false
				for _, old := range projection.QuarantinedOrganizations {
					if old == id {
						found = true
					}
				}
				if !found {
					projection.QuarantinedOrganizations = append(projection.QuarantinedOrganizations, id)
				}
			}
		}
		if record.RequireTargetLogin && record.Binding.Target == scope && record.Phase != "resolved" {
			return errRuntimeTargetBlocked
		}
	}
	// A write during native query/cleanup cannot be accepted as the old source.
	current := storage(storageRequest{Operation: "status"})
	if !current.OK {
		return current.failure()
	}
	if !sameStorageSource(source, current.State) || clock.Load() != epoch {
		return vaultwarden.ErrIdentity
	}
	if len(projection.PendingPolicyMutations) > 0 {
		projection.Version = 2
	}
	if len(projections) > 0 && projections[0] != nil {
		*projections[0] = projection
	}
	return nil
}
