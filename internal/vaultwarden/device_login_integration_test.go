// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Opt in to an exclusively owned volatile 1.37.4 loopback fixture.
func TestDeviceLoginLive1374(t *testing.T) {
	if os.Getenv("MYGO_DEVICE_LOGIN_TEST") != "1" {
		t.Skip("MYGO_DEVICE_LOGIN_TEST=1 required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	name := "mygo-device-login-" + fixtureUUID()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	out, e := exec.CommandContext(ctx, "docker", "create", "--name", name, "--label", "mygo.fixture="+name, "--publish", fmt.Sprintf("127.0.0.1:%d:80", port), "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true", "-e", "DOMAIN="+base, "-e", "SIGNUPS_ALLOWED=true", "-e", "SIGNUPS_VERIFY=false", "vaultwarden/server:1.37.4").CombinedOutput()
	if e != nil {
		t.Fatalf("fixture create: %s %v", out, e)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		out, e := exec.CommandContext(cleanup, "docker", "inspect", "--format", "{{index .Config.Labels \"mygo.fixture\"}}", id).CombinedOutput()
		if e != nil || strings.TrimSpace(string(out)) != name {
			t.Error("fixture ownership check failed", e)
			return
		}
		if out, e = exec.CommandContext(cleanup, "docker", "rm", "-fv", id).CombinedOutput(); e != nil {
			t.Errorf("cleanup: %s %v", out, e)
		}
	})
	if out, e = exec.CommandContext(ctx, "docker", "start", id).CombinedOutput(); e != nil {
		t.Fatalf("fixture start: %s %v", out, e)
	}
	health := http.Client{Timeout: time.Second}
	ready := false
	for until := time.Now().Add(35 * time.Second); time.Now().Before(until); {
		r, e := health.Get(base + "/alive")
		if e == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				ready = true
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(150 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("fixture readiness")
	}
	password := []byte("Public-member-fixture-password!")
	for account := 0; account < 2; account++ {
		requester, _ := liveOrganizationMember(t, ctx, base)
		defer requester.Close()
		initial, e := requester.Sync(ctx)
		if e != nil {
			t.Fatal(e)
		}
		otherClient, _ := NewClient(base, fixtureUUID())
		approver, e := otherClient.Login(ctx, requester.email, password, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer approver.Close()
		synced, e := approver.Sync(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = approver.AcceptAuthenticatedSnapshot(synced.Vault, fixtureUUID()); e != nil {
			t.Fatal(e)
		}
		item, e := approver.CreatePersonalCipher(ctx, initial.Scope, CipherFields{Type: 1, Name: "device login fixture", Login: map[string]any{"username": "fictional", "password": "synthetic secret"}}, nil)
		if e != nil {
			t.Fatal(e)
		}
		synced, e = approver.Sync(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = approver.AcceptAuthenticatedSnapshot(synced.Vault, fixtureUUID()); e != nil {
			t.Fatal(e)
		}
		unknown, _ := NewClient(base, fixtureUUID())
		if _, e = unknown.BeginDeviceLogin(ctx, requester.email, initial.Scope, 1, func(Scope, uint64) error { return nil }); e != ErrDeviceUnknown {
			t.Fatal("unknown device", e)
		}
		var totp string
		if account == 1 {
			raw, e := approver.MFAManage(ctx, "get-authenticator", AccountSensitiveInput{Password: password}, nil, false, nil)
			if e != nil {
				t.Fatal(e)
			}
			var config struct{ Key string }
			if json.Unmarshal(raw, &config) != nil || config.Key == "" {
				t.Fatal("TOTP setup")
			}
			totp = config.Key
			clear(raw)
			if _, e = approver.MFAManage(ctx, "authenticator", AccountSensitiveInput{Password: password}, map[string]json.RawMessage{"key": mfaJSON(totp), "token": mfaJSON(mfaTOTP(totp))}, true, nil); e != nil {
				t.Fatal(e)
			}
			timer := time.NewTimer(time.Duration(31-time.Now().Unix()%30) * time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-timer.C:
			}
		}
		rejected, e := requester.client.BeginDeviceLogin(ctx, requester.email, initial.Scope, 1, func(Scope, uint64) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		if e = approver.RespondAuthRequest(ctx, synced.Vault, rejected.Metadata().ID, "", false, true, nil); e != nil {
			t.Fatal("reject", e)
		}
		if _, e = rejected.Run(nil); e != ErrDeviceRejected {
			t.Fatal("real rejection source", e)
		}
		rejected.Close()
		flow, e := requester.client.BeginDeviceLogin(ctx, requester.email, initial.Scope, 1, func(Scope, uint64) error { return nil })
		if e != nil {
			t.Fatal("begin", e)
		}
		defer flow.Close()
		// Trust the public key obtained directly from the initiating handle, not GET.
		if e = approver.RespondAuthRequest(ctx, synced.Vault, flow.Metadata().ID, flow.Metadata().PublicKey, true, true, nil); e != nil {
			t.Fatal("approve", e)
		}
		flow.pending.mu.Lock()
		accessCode := flow.pending.code
		flow.pending.mu.Unlock()
		calls := 0
		result, e := flow.Run(func(_ context.Context, ch MFAChallenge) (MFAResponse, error) {
			calls++
			if ch.SendEmail != nil {
				t.Error("unsupported email proof")
			}
			return MFAResponse{Provider: 0, Token: []byte(mfaTOTP(totp))}, nil
		})
		if e != nil {
			t.Fatal("grant sync", e)
		}
		if account == 1 && calls != 1 {
			t.Fatal("MFA not enforced")
		}
		if result.Sync.Scope != initial.Scope || result.Sync.PasswordUnlock != nil || len(result.Sync.Session) != 0 {
			t.Fatal("identity or persistence")
		}
		if e = result.Session.AcceptAuthenticatedSnapshot(result.Sync.Vault, fixtureUUID()); e != nil {
			t.Fatal(e)
		}
		itemFields, e := DecryptCipherDocument(item, approver.key)
		if e != nil {
			t.Fatal(e)
		}
		_, fields, e := result.Session.ReadPersonalCipherAuthorized(result.Sync.Vault, itemFields.ID, nil)
		if e != nil || fields.Login["password"] != "synthetic secret" {
			t.Fatal("decryption", e)
		}
		if _, e = flow.Run(nil); e != ErrConflict {
			t.Fatal("replay")
		}
		replay := url.Values{"grant_type": {"password"}, "username": {requester.email}, "password": {accessCode}, "authrequest": {flow.Metadata().ID}, "scope": {"api offline_access"}, "client_id": {"desktop"}, "deviceType": {"7"}, "deviceIdentifier": {requester.client.deviceID}, "deviceName": {"fixture"}}
		status, raw, e := requester.client.request(ctx, "POST", "/identity/connect/token", "application/x-www-form-urlencoded", replay.Encode(), "")
		clear(replay)
		clear(raw)
		accessCode = ""
		if e != nil || status != 400 {
			t.Fatal("server allowed consumed request", status, e)
		}
		if e = flow.BindPassword(ctx, password); e != nil {
			t.Fatal("bind", e)
		}
		saved, e := result.Session.Sync(ctx)
		if e != nil || saved.PasswordUnlock == nil || len(saved.Session) == 0 {
			t.Fatal("persistent sync", e)
		}
		restored, e := RestoreSession(saved.Session, saved.Scope, &saved.PasswordUnlock.Config)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = restored.SyncWithCheckpoint(ctx, func(SessionCheckpoint) error { return nil }); e != nil {
			t.Fatal("restored refresh and sync", e)
		}
		restored.Close()
		clear(saved.Session)
		clear(saved.PasswordUnlock.Key)
		flow.Close()
	}
}
