// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package app

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Actual production controller + actual Go password login/Sync/verification +
// isolated Swift C ABI. The prepared record is a structural storage fixture;
// this test does not claim that a remote administrator mutation was performed.
func targetControllerFixture(t *testing.T, mode string) (*resourceControllerFixture, func(storageRequest) storageReply, vaultwarden.Scope) {
	t.Helper()
	native := recoveryNativeCall(t)
	f := newRuntimeResourceControllerFixture(t)
	scope := *f.a.liveScope
	device := f.device
	der, err := vaultwarden.DecryptString(device.private, device.key)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	clear(der)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.(*rsa.PrivateKey).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	profile := f.body["profile"].(map[string]any)
	profile["publicKey"] = base64.StdEncoding.EncodeToString(public)
	f.additional = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/version":
			json.NewEncoder(w).Encode("1.37.4")
		case "/api/config":
			json.NewEncoder(w).Encode(map[string]any{"gitHash": "7c188967e7a467b19b2757bc3326f9cf3ccae327", "server": map[string]string{"name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden"}})
		case "/identity/connect/token":
			r.ParseForm()
			if r.Form.Get("authrequest") != "" {
				return false
			}
			master, e := vaultwarden.DeriveMaster([]byte("fixture-master"), device.email, device.config.KDF)
			if e != nil {
				t.Error(e)
				w.WriteHeader(500)
				return true
			}
			defer clear(master)
			if r.Form.Get("grant_type") != "password" || r.Form.Get("password") != vaultwarden.AuthorizationHash(master, []byte("fixture-master")) {
				t.Error("not a fresh password grant")
				w.WriteHeader(400)
				return true
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh-controller-target", "refresh_token": "fresh-controller-target-refresh", "expires_in": 3600, "token_type": "Bearer", "key": device.wrapped})
		case "/api/accounts/keys":
			json.NewEncoder(w).Encode(profile)
		case "/api/two-factor":
			providers := []any{}
			if mode == "nondispatch" {
				providers = append(providers, map[string]any{"type": 0, "enabled": true})
			}
			json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": providers})
		default:
			return false
		}
		return true
	}
	f.mu.Unlock()
	f.a.stopNetwork()
	actor := scope
	if mode == "foreign" || mode == "multiple" {
		actor.Account = "original-local-account"
	}
	old := targetFixture(actor)
	state := native(storageRequest{Operation: "status"}).State
	saved := native(storageRequest{Operation: "publishVault", ExpectedRevision: state.Revision, Scope: &actor, PasswordUnlock: old.PasswordUnlock, Session: old.Session, Vault: old.Vault})
	if !saved.OK {
		t.Fatal(saved.Code)
	}
	expectation := vaultwarden.RecoveryVerificationExpectation{Version: 1, ResetPassword: true, ResetMFA: true, ExpectedUserKeySHA256: targetRecoveryHash(device.key), ExpectedMasterWrapperSHA256: targetRecoveryHash([]byte(device.wrapped))}
	if mode == "nondispatch" || mode == "partial" {
		expectation.ExpectedMasterWrapperSHA256 = targetRecoveryHash([]byte("never observed future wrapper"))
	}
	d := vaultwarden.RecoveryDispatch{OperationID: strings.Repeat("d", 32), Actor: actor, Target: scope, Kind: "administrator-recovery", PreviousRevision: "fixture-original-authority", AuthorizationEpoch: 1, OrganizationID: "recovery-org", MembershipID: "recovery-member", RequireTargetLogin: true, Verification: expectation}
	adapter, e := newTargetRecoveryStorage(saved.State, 1, func() uint64 { return 1 }, bytes.Repeat([]byte{41}, 32), native)
	if e != nil {
		t.Fatal(e)
	}
	if e = adapter.Begin(d); e != nil {
		t.Fatal(e)
	}
	result := vaultwarden.RecoveryOperationResult{RecoveryDispatch: d, IsolationAttempted: true, Dispatched: mode != "nondispatch", Confirmed: mode != "nondispatch" && mode != "partial", Unknown: mode == "partial"}
	if e = adapter.Result(result); e != nil {
		t.Fatal(e)
	}
	adapter.Close()
	if mode == "multiple" {
		d.OperationID = strings.Repeat("e", 32)
		d.OrganizationID = "recovery-org-two"
		second, e := newTargetRecoveryStorage(native(storageRequest{Operation: "status"}).State, 1, func() uint64 { return 1 }, bytes.Repeat([]byte{41}, 32), native)
		if e != nil {
			t.Fatal(e)
		}
		if e = second.Begin(d); e != nil {
			t.Fatal(e)
		}
		if e = second.Result(vaultwarden.RecoveryOperationResult{RecoveryDispatch: d, IsolationAttempted: true, Dispatched: true, Confirmed: true}); e != nil {
			t.Fatal(e)
		}
		second.Close()
	}
	f.a.snapshot = native(storageRequest{Operation: "status"}).State
	f.a.serverURL, f.a.email, f.a.deviceID = scope.Server, device.email, "fresh-target-controller-device"
	f.a.storageBackend = native
	f.a.uiDispatcher = f.dispatch
	f.a.openTargetRecoveryWith(f.dispatch, native)
	return f, native, scope
}
func TestNativeEmergencyControllerPersistsBeforeTransportAndLateOutcome(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "late-cancel"}[late], func(t *testing.T) {
			f, native, scope := targetControllerFixture(t, "self")
			target := f.a.targetRecovery
			target.password = "fixture-master"
			target.inspect()
			f.drain()
			target.verify(0)
			f.drain()
			if f.a.session == nil {
				t.Fatal(target.status)
			}
			unlock, err := vaultwarden.DeriveSnapshotUnlockKey([]byte("fixture-master"), *f.a.snapshot.PasswordUnlock)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(unlock)
			f.a.openEmergencyServices()
			controller := f.a.orgServices
			panel := newEmergencyPanel(nil, true, controller.prepareRecovery, controller.commitRecovery, controller.deliver)
			controller.replacePanel(panel)
			panel.email = "recipient@example.invalid"
			panel.preparePlan()
			f.drain()
			if panel.plan == nil {
				t.Fatal(panel.status)
			}
			operation := panel.plan.Summary().OperationID
			entered, release := make(chan struct{}), make(chan struct{})
			var writes atomic.Int32
			f.mu.Lock()
			previous := f.additional
			f.additional = func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/emergency-access/invite" {
					return previous(w, r)
				}
				writes.Add(1)
				state := native(storageRequest{Operation: "status"}).State
				pending := native(storageRequest{Operation: "targetRecoveryPending", ExpectedRevision: state.Revision, Scope: &scope, UnlockKey: unlock})
				found := false
				for _, record := range pending.TargetRecords {
					if record.Binding.OperationID == operation && record.Phase == "prepared" {
						found = true
					}
				}
				if !pending.OK || !found {
					t.Error("transport crossed without durable exact-operation journal")
				}
				if late {
					close(entered)
					<-release
				}
				w.WriteHeader(http.StatusNoContent)
				return true
			}
			f.mu.Unlock()
			panel.commitPlan()
			if late {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("mutation not entered")
				}
				f.a.stopNetwork()
				close(release)
			}
			f.drain()
			state := native(storageRequest{Operation: "status"}).State
			pending := native(storageRequest{Operation: "targetRecoveryPending", ExpectedRevision: state.Revision, Scope: &scope, UnlockKey: unlock})
			expected := "confirmed"
			if late {
				expected = "unknown"
			}
			found := false
			for _, record := range pending.TargetRecords {
				if record.Binding.OperationID == operation && record.Phase == expected {
					found = true
				}
			}
			if !pending.OK || !found || writes.Load() != 1 {
				t.Fatalf("original actor outcome missing: phase=%s writes=%d", expected, writes.Load())
			}
			panel.commitPlan()
			if writes.Load() != 1 {
				t.Fatal("terminal operation replayed")
			}
			if late && (f.a.session != nil || f.a.liveScope != nil) {
				t.Fatal("late outcome restored session")
			}
		})
	}
}

func TestNativeTargetMainControllerLateResolveCannotReopenUI(t *testing.T) {
	f, native, _ := targetControllerFixture(t, "self")
	panel := f.a.targetRecovery
	panel.password = "fixture-master"
	panel.inspect()
	f.drain()
	if panel.workspace == nil {
		t.Fatal(panel.status)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	panel.storage = func(request storageRequest) storageReply {
		if request.Operation == "targetRecoveryResolveLocal" {
			close(entered)
			<-release
		}
		return native(request)
	}
	panel.verify(0)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("resolve did not reach native boundary")
	}
	f.a.stopNetwork()
	close(release)
	f.drain()
	if f.a.session != nil || f.a.liveScope != nil || f.a.targetRecovery != nil || len(f.a.items) != 0 {
		t.Fatal("late native result reopened locked UI")
	}
}

func TestNativeTargetMainControllerFreshAuthenticationAndPublication(t *testing.T) {
	for _, mode := range []string{"self", "foreign", "multiple", "nondispatch", "partial"} {
		t.Run(mode, func(t *testing.T) {
			f, native, scope := targetControllerFixture(t, mode)
			panel := f.a.targetRecovery
			panel.password = "fixture-master"
			panel.inspect()
			f.drain()
			want := 1
			if mode == "multiple" {
				want = 2
			}
			if panel.workspace == nil || len(panel.records) != want {
				t.Fatalf("inspection failed: %s", panel.status)
			}
			if mode == "foreign" || mode == "multiple" {
				panel.verify(0)
				f.drain()
				if f.a.liveScope != nil || native(storageRequest{Operation: "status"}).State.Scope.Account != "original-local-account" {
					t.Fatal("foreign cache replaced without consent/all records")
				}
				panel.replaceForeign = true
			}
			index := 0
			if mode == "multiple" {
				index = 1
			}
			panel.verify(index)
			f.drain()
			if mode == "partial" {
				state := native(storageRequest{Operation: "status"}).State
				unlock := native(storageRequest{Operation: "listPassword", ExpectedRevision: state.Revision, Scope: &scope, UnlockKey: bytes.Repeat([]byte{41}, 32)})
				if f.a.liveScope != nil || f.a.targetRecovery != panel || unlock.OK {
					t.Fatal("partial outcome cleared target barrier")
				}
				return
			}
			if f.a.targetRecovery != nil || f.a.liveScope == nil || *f.a.liveScope != scope || f.a.vault == nil || f.a.session == nil {
				t.Fatalf("dedicated receipt not adopted: %s / %s", panel.status, f.a.status)
			}
			if f.a.snapshot.AccountSwitchPending || f.a.snapshot.RecoveryPending {
				t.Fatal("pending state adopted")
			}
			if err := f.a.session.(*vaultwarden.Session).ValidateAuthenticatedSnapshot(f.a.vault, f.a.sessionRevision); err != nil {
				t.Fatal(err)
			}
		})
	}
}
