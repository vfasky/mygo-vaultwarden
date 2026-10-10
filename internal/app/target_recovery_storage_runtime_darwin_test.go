// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package app

import (
	"encoding/json"
	"github.com/ebitengine/purego"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func targetRuntimeNativeCall(t *testing.T) func(map[string]any) map[string]any {
	t.Helper()
	library := os.Getenv("SNAPSHOT_TEST_HARNESS")
	if library == "" {
		t.Skip("requires isolated runtime clipboard harness")
	}
	handle, err := purego.Dlopen(library, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := purego.Dlsym(handle, "mygo_runtime_secret_execute")
	if err != nil {
		t.Fatal(err)
	}
	var native func([]byte, int, []byte, int) int32
	purego.RegisterFunc(&native, symbol)
	return func(request map[string]any) map[string]any {
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		output := make([]byte, 4096)
		defer clear(output)
		n := native(raw, len(raw), output, len(output))
		runtime.KeepAlive(raw)
		runtime.KeepAlive(output)
		if n <= 0 || int(n) > len(output) {
			t.Fatalf("runtime ABI length %d", n)
		}
		var reply map[string]any
		if json.Unmarshal(output[:n], &reply) != nil {
			t.Fatal("invalid runtime JSON")
		}
		return reply
	}
}
func TestNativeRuntimeSecretLeaseABI(t *testing.T) {
	call := targetRuntimeNativeCall(t)
	scope := vaultwarden.Scope{Server: "https://runtime.example.invalid", Account: "actor"}
	request := map[string]any{"operation": "activate", "purpose": "secret", "scope": scope, "generation": uint64(time.Now().UnixNano()), "deadlineUnixMS": time.Now().Add(20 * time.Second).UnixMilli()}
	active := call(request)
	if active["ok"] != true {
		t.Fatal(active["code"])
	}
	if call(request)["leaseID"] != active["leaseID"] {
		t.Fatal("activate renewed identity")
	}
	request["leaseID"] = active["leaseID"]
	request["operation"] = "authorizeDisplay"
	if call(request)["ok"] != true {
		t.Fatal("display denied")
	}
	request["operation"] = "copy"
	request["requestID"] = "11111111-1111-4111-8111-111111111111"
	request["secret"] = "isolated-fixture-secret"
	if call(request)["ok"] != true || call(request)["ok"] != true {
		t.Fatal("copy/idempotence failed")
	}
	request["secret"] = "different"
	if call(request)["ok"] == true {
		t.Fatal("same request changed secret")
	}
	delete(request, "secret")
	request["operation"] = "revoke"
	if call(request)["ok"] != true {
		t.Fatal("revoke failed")
	}
	request["operation"] = "authorizeDisplay"
	if call(request)["ok"] == true {
		t.Fatal("revoked display allowed")
	}
}
func TestNativeRuntimeActorForeignTargetLocalAuthentication(t *testing.T) {
	call := recoveryNativeCall(t)
	runtimeCall := targetRuntimeNativeCall(t)
	actor := vaultwarden.Scope{Server: "https://runtime.example.invalid", Account: "actor"}
	target := vaultwarden.Scope{Server: actor.Server, Account: "target"}
	old := targetFixture(target)
	old.Vault.Version = 2
	old.Vault.PendingPolicyMutations = []vaultwarden.PendingPolicyMutation{{OrganizationID: "org-1", PolicyType: 15, MutationID: "mutation-1"}}
	old.Vault.QuarantinedOrganizations = []string{"org-2"}
	initial := call(storageRequest{Operation: "publishVault", Scope: &target, ExpectedRevision: "empty-v1", PasswordUnlock: old.PasswordUnlock, Session: old.Session, Vault: old.Vault})
	if !initial.OK {
		t.Fatal(initial.Code)
	}
	d := vaultwarden.RecoveryDispatch{OperationID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Actor: actor, Target: target, Kind: "administrator-recovery", Verification: targetFixtureExpectation(), AuthorizationEpoch: 11, PreviousRevision: "runtime-session", RequireTargetLogin: true}
	raw, _ := json.Marshal(d)
	hash := targetRecoveryHash(raw)
	deadline := time.Now().Add(25 * time.Second).UnixMilli()
	generation := uint64(time.Now().UnixNano())
	active := runtimeCall(map[string]any{"operation": "activate", "purpose": "recovery", "scope": actor, "generation": generation, "deadlineUnixMS": deadline, "operationID": d.OperationID, "summaryHash": hash})
	if active["ok"] != true {
		t.Fatal(active["code"])
	}
	authority := targetRecoveryRuntimeAuthority{actor, generation, deadline, active["leaseID"].(string), d.OperationID, hash}
	var epoch atomic.Uint64
	epoch.Store(2)
	adapter, err := newTargetRecoveryRuntimeStorage(initial.State, 2, epoch.Load, authority, call)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if err := adapter.Begin(d); err != nil {
		t.Fatal(err)
	}
	state := adapter.Receipt()
	if state == nil || *state.Scope != target {
		t.Fatal("receipt confused actor with local target")
	}
	blocked := call(storageRequest{Operation: "listPassword", Scope: &target, ExpectedRevision: state.Revision, UnlockKey: old.PasswordUnlock.Key})
	if blocked.OK {
		t.Fatal("old target accessible")
	}
	protection, err := adapter.InspectLocalTarget()
	if err != nil {
		t.Fatal(err)
	}
	if len(protection.TargetProtection.PendingPolicyMutations) != 1 {
		t.Fatal("policy projection lost")
	}
	fresh := targetFixture(target)
	fresh.PasswordUnlock.Key = make([]byte, 32)
	fresh.Session = []byte("new-target-authentication")
	complete, err := adapter.ResolveVerifiedWithLocalAuthentication(fresh, targetEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.Vault.PendingPolicyMutations) != 1 || len(complete.Vault.QuarantinedOrganizations) != 1 {
		t.Fatal("local restrictions lost")
	}
	if *complete.State.Scope != target || complete.TargetRecords[0].Phase != "resolved" {
		t.Fatal("wrong target resolved")
	}
	request := map[string]any{"operation": "revoke", "purpose": "recovery", "scope": actor, "generation": generation, "deadlineUnixMS": deadline, "operationID": d.OperationID, "summaryHash": hash, "leaseID": authority.LeaseID}
	if runtimeCall(request)["ok"] != true {
		t.Fatal("revoke failed")
	}
	if _, err := adapter.Query(); err == nil {
		t.Fatal("revoked runtime authority read accepted")
	}
}
