// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTargetRecoveryAdapterRejectsInvalidReceiptsAndEpoch(t *testing.T) {
	scope := vaultwarden.Scope{Server: "https://adapter.example.invalid", Account: "actor"}
	state := &snapshotStatus{Available: true, Scope: &scope, Revision: "old"}
	d := vaultwarden.RecoveryDispatch{OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Actor: scope, Target: scope, Kind: "reset", PreviousRevision: "session-revision", AuthorizationEpoch: 7, RequireTargetLogin: true}
	for _, bad := range []string{"missing", "scope", "revision", "hash", "target", "epoch", "local-target", "phase", "late"} {
		t.Run(bad, func(t *testing.T) {
			var epoch atomic.Uint64
			epoch.Store(1)
			calls := 0
			adapter, err := newTargetRecoveryStorage(state, 1, epoch.Load, bytes.Repeat([]byte{1}, 32), func(req storageRequest) storageReply {
				calls++
				record := targetRecoveryRecord{Binding: *req.TargetBinding, Summary: bytes.Clone(req.TargetSummary), Phase: "prepared", RequireTargetLogin: true}
				next := *state
				next.Revision = "new"
				next.SnapshotID = "new-id"
				next.TargetRecoveryPresent = true
				switch bad {
				case "missing":
					return storageReply{OK: true, State: &next}
				case "scope":
					other := scope
					other.Account = "foreign"
					next.Scope = &other
				case "revision":
					next.Revision = "old"
				case "hash":
					record.Binding.SummaryHash = "wrong"
				case "target":
					record.Binding.Target.Account = "wrong"
				case "epoch":
					record.Binding.AuthorizationEpoch++
				case "local-target":
					record.NoLocalTarget = true
				case "phase":
					record.Phase = "confirmed"
				case "late":
					epoch.Add(1)
				}
				return storageReply{OK: true, State: &next, TargetRecords: []targetRecoveryRecord{record}}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			if adapter.Begin(d) == nil {
				t.Fatal("invalid receipt accepted")
			}
			epoch.Add(1)
			if _, err := adapter.Query(); err == nil || calls != 1 {
				t.Fatal("stale epoch called native")
			}
		})
	}
}
func TestTargetRecoveryAdapterCloseRace(t *testing.T) {
	scope := vaultwarden.Scope{Server: "https://adapter.example.invalid", Account: "actor"}
	var epoch atomic.Uint64
	epoch.Store(1)
	adapter, err := newTargetRecoveryStorage(&snapshotStatus{Available: true, Scope: &scope, Revision: "revision"}, 1, epoch.Load, bytes.Repeat([]byte{1}, 32), func(storageRequest) storageReply { return storageReply{Code: "test-failure"} })
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = adapter.Pending(); adapter.Close() }()
	}
	wg.Wait()
}
