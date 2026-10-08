// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func runtimeQueryRecord(scope vaultwarden.Scope, kind string) targetRecoveryRecord {
	actor := scope
	actor.Account = "foreign-actor"
	target := scope
	required := true
	phase := "prepared"
	switch kind {
	case "resolved":
		phase = "resolved"
	case "verified":
		phase = "verified"
	case "unrelated":
		actor = scope
		target.Account = "other-target"
	case "invitation":
		required = false
	}
	d := vaultwarden.RecoveryDispatch{OperationID: strings.Repeat("b", 32), Actor: actor, Target: target, Kind: "reset", PreviousRevision: "trusted-session", AuthorizationEpoch: 7, RequireTargetLogin: required}
	summary, _ := json.Marshal(d)
	return targetRecoveryRecord{Binding: targetRecoveryBinding{OperationID: d.OperationID, Actor: actor, Target: target, StorageRevision: "before", HostEpoch: 3, AuthorizationEpoch: 7, SummaryHash: targetRecoveryHash(summary)}, Summary: summary, Phase: phase, RequireTargetLogin: required}
}
func TestRuntimeTargetQueryForeignBlocksAndReadOnlyFacade(t *testing.T) {
	for _, kind := range []string{"prepared", "verified", "resolved", "unrelated", "invitation", "source-changed", "bad-summary", "wrong-scope"} {
		t.Run(kind, func(t *testing.T) {
			f := newRuntimeResourceControllerFixture(t)
			runtime := f.a.runtimeVault
			source := runtime.source
			source.TargetRecoveryPresent = true
			cap := runtime.authority
			native := &nativeRuntimeSecrets{call: runtime.native.(*nativeRuntimeSecrets).call}
			calls := 0
			storage := func(r storageRequest) storageReply {
				calls++
				if r.Operation == "targetRecoveryRuntimePending" {
					if r.TargetBinding != nil || r.TargetSummary != nil || r.TargetResolution != nil || r.TargetRuntime == nil || r.TargetRuntime.OperationID == strings.Repeat("b", 32) {
						t.Fatal("query acquired write dispatch")
					}
					record := runtimeQueryRecord(cap.Scope(), kind)
					if kind == "source-changed" {
						record = runtimeQueryRecord(cap.Scope(), "resolved")
					}
					if kind == "bad-summary" {
						record.Summary = append(record.Summary, 'x')
					}
					if kind == "wrong-scope" {
						record.Binding.Actor.Account = "other"
						record.Binding.Target.Account = "other"
					}
					return storageReply{OK: true, State: &source, TargetRecords: []targetRecoveryRecord{record}}
				}
				if r.Operation != "status" {
					t.Fatal("query attempted persistent mutation", r.Operation)
				}
				current := source
				if kind == "source-changed" {
					current.Revision += "-new-blocker"
				}
				return storageReply{OK: true, State: &current}
			}
			err := checkRuntimeTargetProtection(cap, runtime.vault, &source, f.a.epoch, &f.a.workerEpoch, storage, native)
			shouldPass := kind == "resolved" || kind == "unrelated" || kind == "invitation"
			if (err == nil) != shouldPass {
				t.Fatal("wrong query outcome", kind, err)
			}
			if kind == "prepared" || kind == "verified" {
				if !errors.Is(err, errRuntimeTargetBlocked) {
					t.Fatal(err)
				}
			}
			if calls == 0 || f.serial != 0 {
				t.Fatal("missing query or wrote cache")
			}
		})
	}
}
func TestRuntimeResolvedHistoryAddsProtectionInsteadOfGrantingAccess(t *testing.T) {
	f := newRuntimeResourceControllerFixture(t)
	r := f.a.runtimeVault
	cap := r.authority
	source := r.source
	source.TargetRecoveryPresent = true
	record := runtimeQueryRecord(cap.Scope(), "resolved")
	record.Protection = &targetRecoveryProtection{Scope: cap.Scope(), PendingPolicyMutations: []vaultwarden.PendingPolicyMutation{{OrganizationID: "11111111-1111-4111-8111-111111111111", MutationID: "22222222-2222-4222-8222-222222222222", PolicyType: 15}}}
	storage := func(req storageRequest) storageReply {
		if req.Operation == "targetRecoveryRuntimePending" {
			return storageReply{OK: true, State: &source, TargetRecords: []targetRecoveryRecord{record}}
		}
		return storageReply{OK: true, State: &source}
	}
	var protection *vaultwarden.VaultData
	if err := checkRuntimeTargetProtection(cap, r.vault, &source, f.a.epoch, &f.a.workerEpoch, storage, &nativeRuntimeSecrets{call: r.native.(*nativeRuntimeSecrets).call}, &protection); err != nil {
		t.Fatal(err)
	}
	_, accepted, err := cap.Restrict(r.vault, protection)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.session.ReadPersonalCipher(accepted, "card-1"); err == nil {
		t.Fatal("resolved history dropped its pending policy")
	}
	if !accepted.PreservesPendingPolicies(protection) || f.serial != 0 {
		t.Fatal("protection lost or cache overwritten")
	}
}

func TestRuntimeControllerBootstrapWithoutOldActorSnapshot(t *testing.T) {
	f := newRuntimeResourceControllerFixture(t)
	originalScope := *f.a.liveScope
	nativeCall := f.a.runtimeVault.native.(*nativeRuntimeSecrets).call
	f.a.stopNetwork()
	f.mu.Lock()
	state := *f.state
	state.Scope = nil
	state.Available = false
	state.PasswordUnlock = nil
	state.SnapshotID = ""
	state.Revision = "empty-with-history"
	f.state = &state
	f.mu.Unlock()
	f.a.snapshot = &state
	f.a.deviceAccountID = originalScope.Account
	f.a.openDeviceLoginWith(f.dispatch, f.a.storageBackend, func() *nativeRuntimeSecrets { return &nativeRuntimeSecrets{call: nativeCall} })
	timeout := time.After(10 * time.Second)
	for f.a.runtimeVault == nil {
		select {
		case fn := <-f.q:
			fn()
		case <-timeout:
			t.Fatal("empty-cache bootstrap", f.a.status)
		}
	}
	if f.state.Available || f.state.Scope != nil || f.serial != 0 || *f.a.liveScope != originalScope {
		t.Fatal("bootstrap fabricated old cache or adopted wrong identity")
	}
}
