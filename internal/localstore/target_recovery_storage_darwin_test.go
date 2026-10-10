// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package localstore

import (
	"bytes"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"os"
	"sync/atomic"
	"testing"
)

func targetFixture(scope vaultwarden.Scope) vaultwarden.SyncResult {
	return vaultwarden.SyncResult{Scope: scope, Vault: &vaultwarden.VaultData{Version: 1, Scope: scope, Sync: []byte(`{"profile":{"id":"` + scope.Account + `","organizations":[]},"policies":[],"policiesNew":[],"ciphers":[]}`)}, Session: []byte("isolated-fresh-session"), PasswordUnlock: &vaultwarden.PasswordUnlock{Config: vaultwarden.PasswordUnlockConfig{Email: "fixture@example.invalid", KDF: vaultwarden.KDF{Iterations: 5000}}, Key: bytes.Repeat([]byte{41}, 32)}}
}
func targetFixtureExpectation() vaultwarden.RecoveryVerificationExpectation {
	// Structural native-storage fixture; this is not a remote verification proof.
	return vaultwarden.RecoveryVerificationExpectation{Version: 1, ResetPassword: true, ResetMFA: true, ExpectedUserKeySHA256: TargetRecoveryHash([]byte("fixture-user-key")), ExpectedMasterWrapperSHA256: TargetRecoveryHash([]byte("fixture-wrapper"))}
}
func targetEvidence() TargetRecoveryVerification {
	h := TargetRecoveryHash([]byte("test-only verified evidence"))
	return TargetRecoveryVerification{Kind: vaultwarden.TargetEvidenceEffects, AuthorityHash: h, KeyHash: h, MembershipHash: h, MFAHash: h, ConfirmationHash: h, AuthenticationEpoch: 19}
}
func TestNativeTargetRecoveryLifecycle(t *testing.T) {
	for _, self := range []bool{true, false} {
		t.Run(map[bool]string{true: "self", false: "foreign"}[self], func(t *testing.T) {
			call := recoveryNativeCall(t)
			actor := vaultwarden.Scope{Server: "https://target.example.invalid", Account: "actor"}
			target := actor
			if !self {
				target.Account = "target"
			}
			initial := targetFixture(actor)
			first := call(Request{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &actor, PasswordUnlock: initial.PasswordUnlock, Session: initial.Session, Vault: initial.Vault})
			if !first.OK {
				t.Fatal(first.Code)
			}
			var epoch atomic.Uint64
			epoch.Store(3)
			adapter, err := NewTargetRecoveryStorage(first.State, 3, epoch.Load, initial.PasswordUnlock.Key, call)
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			d := vaultwarden.RecoveryDispatch{OperationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Actor: actor, Target: target, Kind: "administrator-recovery", Verification: targetFixtureExpectation(), PreviousRevision: "session-revision", AuthorizationEpoch: 7, RequireTargetLogin: true, TargetEmail: "private@example.invalid", ConfirmedImpact: "private-impact"}
			var before vaultwarden.RecoveryBeforeDispatch = adapter.Begin
			if err := before(d); err != nil {
				t.Fatal(err)
			}
			pending, err := adapter.Query()
			if err != nil {
				t.Fatal(err)
			}
			if pending.TargetRecords[0].NoLocalTarget == self {
				t.Fatal("wrong target fact")
			}
			read := call(Request{Operation: "listPassword", Scope: &actor, ExpectedRevision: pending.State.Revision, UnlockKey: initial.PasswordUnlock.Key})
			if read.OK == self {
				t.Fatal("incorrect actor access")
			}
			if err := adapter.Result(vaultwarden.RecoveryOperationResult{RecoveryDispatch: d, IsolationAttempted: true, Dispatched: true, Unknown: true}); err != nil {
				t.Fatal(err)
			}
			saved, err := adapter.Query()
			if err != nil {
				t.Fatal(err)
			}
			disk, err := os.ReadFile(os.Getenv("SNAPSHOT_TEST_DIRECTORY") + "/snapshot-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(disk, []byte(d.TargetEmail)) || bytes.Contains(disk, []byte(d.OperationID)) {
				t.Fatal("plaintext operation leaked")
			}
			fresh := targetFixture(target)
			fresh.Session = []byte("newly-authenticated-target")
			fresh.PasswordUnlock.Key = bytes.Repeat([]byte{71}, 32)
			if _, err := adapter.ResolveVerified(fresh, TargetRecoveryVerification{}); err == nil {
				t.Fatal("missing evidence accepted")
			}
			if !self {
				verified, err := adapter.ResolveVerified(fresh, targetEvidence())
				if err != nil {
					t.Fatal(err)
				}
				if *verified.State.Scope != actor || verified.State.SnapshotID != first.State.SnapshotID || verified.TargetRecords[0].Phase != "verified" {
					t.Fatal("actor replaced by target verification")
				}
				saved = verified
			}
			logout := call(Request{Operation: "logout", ExpectedRevision: saved.State.Revision})
			if !logout.OK {
				t.Fatal(logout.Code)
			}
			epoch.Add(1)
			if _, err := adapter.Query(); err == nil {
				t.Fatal("late epoch accepted")
			}
			old := call(Request{Operation: "publishVault", Scope: &target, ExpectedRevision: logout.State.Revision, PasswordUnlock: initial.PasswordUnlock, Session: initial.Session, Vault: fresh.Vault})
			if old.OK {
				t.Fatal("old target published")
			}
			login, err := NewTargetRecoveryLoginStorage(logout.State, epoch.Load(), epoch.Load, fresh, targetEvidence(), call)
			if err != nil {
				t.Fatal(err)
			}
			defer login.Close()
			operations, err := login.Pending()
			if err != nil || len(operations.TargetRecords) != 1 {
				t.Fatalf("pending: %v", err)
			}
			if err := login.Select(operations.TargetRecords[0]); err != nil {
				t.Fatal(err)
			}
			complete, err := login.ResolveVerified(fresh, targetEvidence())
			if err != nil {
				t.Fatal(err)
			}
			if complete.TargetRecords[0].Phase != "resolved" || *complete.State.Scope != target {
				t.Fatal("resolve receipt")
			}
			unlocked := call(Request{Operation: "listPassword", Scope: &target, ExpectedRevision: complete.State.Revision, UnlockKey: fresh.PasswordUnlock.Key})
			if !unlocked.OK || !bytes.Equal(unlocked.Session, fresh.Session) {
				t.Fatal("fresh target unavailable")
			}
		})
	}
}
func TestNativeTargetRecoveryUnknownInviteAndFailure(t *testing.T) {
	call := recoveryNativeCall(t)
	scope := vaultwarden.Scope{Server: "https://target.example.invalid", Account: "actor"}
	fresh := targetFixture(scope)
	state := call(Request{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &scope, PasswordUnlock: fresh.PasswordUnlock, Session: fresh.Session, Vault: fresh.Vault}).State
	var epoch atomic.Uint64
	epoch.Store(1)
	adapter, err := NewTargetRecoveryStorage(state, 1, epoch.Load, fresh.PasswordUnlock.Key, call)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	dispatch := vaultwarden.RecoveryDispatch{OperationID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Actor: scope, Target: vaultwarden.Scope{Server: scope.Server}, Kind: "invite", PreviousRevision: "session-revision", AuthorizationEpoch: 4}
	dir := os.Getenv("SNAPSHOT_TEST_DIRECTORY")
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	err = adapter.Begin(dispatch)
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if err == nil {
		t.Fatal("failed persistence allowed mutation callback")
	}
	status := call(Request{Operation: "status"})
	if status.State.Revision != state.Revision {
		t.Fatal("failed begin mutated vault")
	}
	adapter.Close()
	next, err := NewTargetRecoveryStorage(state, 1, epoch.Load, fresh.PasswordUnlock.Key, call)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := next.Begin(dispatch); err != nil {
		t.Fatal(err)
	}
	if err := next.Result(vaultwarden.RecoveryOperationResult{RecoveryDispatch: dispatch, IsolationAttempted: true, Dispatched: true, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	pending, err := next.Query()
	if err != nil || pending.TargetRecords[0].Phase != "confirmed" {
		t.Fatal(err)
	}
}
