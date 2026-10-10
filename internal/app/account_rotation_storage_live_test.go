// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// Restricted adapter for this test's new account: one independent item key and
// explicitly enumerated empty Send/folder/organization/emergency collections.
// This does not stand in for production nonempty cross-resource converters.
type storageLiveRotationAdapter struct{}

func (storageLiveRotationAdapter) Convert(ctx context.Context, in vaultwarden.AccountRotationInput) (vaultwarden.AccountRotationConversion, error) {
	out := vaultwarden.AccountRotationConversion{Coverage: vaultwarden.AccountRotationCoverage{Scope: in.Scope, Revision: in.Revision, Epoch: in.Epoch, SnapshotHash: in.SnapshotHash, EmergencyComplete: true, RecoveryComplete: true}, Data: vaultwarden.AccountRotationData{Ciphers: []json.RawMessage{}, Folders: []vaultwarden.AccountRotationFolder{}, Sends: []json.RawMessage{}}, Emergency: []vaultwarden.AccountRotationEmergency{}, Recovery: []vaultwarden.AccountRotationRecovery{}}
	var raw struct {
		Profile                 struct{ Organizations, OrganizationsNew []json.RawMessage }
		Ciphers, Sends, Folders []json.RawMessage
	}
	if json.Unmarshal(in.Sync, &raw) != nil || raw.Profile.Organizations == nil || raw.Profile.OrganizationsNew == nil || len(raw.Profile.Organizations) != 0 || len(raw.Profile.OrganizationsNew) != 0 || len(raw.Sends) != 0 || len(raw.Folders) != 0 || len(raw.Ciphers) != 1 {
		return out, vaultwarden.ErrIdentity
	}
	check := func(ctx context.Context, read func(context.Context, string) (json.RawMessage, error)) error {
		data, err := read(ctx, "/api/emergency-access/trusted")
		if err != nil {
			return err
		}
		var contacts struct {
			Data              []json.RawMessage
			ContinuationToken *string
		}
		if json.Unmarshal(data, &contacts) != nil || contacts.Data == nil || len(contacts.Data) != 0 || contacts.ContinuationToken != nil {
			return vaultwarden.ErrIdentity
		}
		return nil
	}
	if err := check(ctx, in.Read); err != nil {
		return out, err
	}
	out.Revalidate = check
	for _, cipher := range raw.Ciphers {
		converted, err := vaultwarden.AccountRewrapRotationCipher(cipher, in.OldUserKey, in.NewUserKey, in.Scope.Account)
		if err != nil {
			return out, err
		}
		out.Data.Ciphers = append(out.Data.Ciphers, converted)
	}
	return out, nil
}

func TestLiveAccountRecoveryStorage(t *testing.T) {
	target := os.Getenv("MYGO_RECOVERY_TEST_URL")
	if target == "" {
		t.Skip("requires self-owned ephemeral Vaultwarden 1.37.4 fixture")
	}
	if !strings.HasPrefix(target, "http://127.0.0.1:") {
		t.Fatal("refusing nonloopback fixture")
	}
	parsed, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(parsed)
	var drop atomic.Bool
	var posts atomic.Int32
	proxy.ModifyResponse = func(response *http.Response) error {
		if strings.Contains(response.Request.URL.Path, "rotate-user-account-keys") {
			posts.Add(1)
			if drop.Load() {
				response.Body.Close()
				return errors.New("test dropped response after server commit")
			}
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) { w.WriteHeader(http.StatusBadGateway) }
	server := httptest.NewServer(proxy)
	defer server.Close()
	call := recoveryNativeCall(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client, err := vaultwarden.NewClient(server.URL, "5f3d5969-fb1c-430b-9522-a2e3ea69eaa7")
	if err != nil {
		t.Fatal(err)
	}
	email := fmt.Sprintf("recovery-%d@example.invalid", time.Now().UnixNano())
	password := []byte("Recovery-Fixture-Primary-Passphrase-581!")
	defer clear(password)
	registration, err := client.AccountSendRegistrationEmail(ctx, email, "Recovery storage fixture")
	if err != nil || registration.EmailSent {
		t.Fatal("registration email", err)
	}
	if err := client.AccountRegister(ctx, email, password, vaultwarden.KDF{Iterations: 100000}, "", registration.Token); err != nil {
		t.Fatal("register", err)
	}
	session, err := client.Login(ctx, email, password, nil)
	if err != nil {
		t.Fatal("login", err)
	}
	defer session.Close()
	syncResult, err := session.Sync(ctx)
	if err != nil {
		t.Fatal("initial sync", err)
	}
	state := call(storageRequest{Operation: "publishVault", ExpectedRevision: "empty-v1", Scope: &syncResult.Scope, PasswordUnlock: syncResult.PasswordUnlock, Session: syncResult.Session, Vault: syncResult.Vault, Credentials: syncResult.Credentials})
	if !state.OK {
		t.Fatal(state.Code)
	}
	if err := session.AcceptAuthenticatedSnapshot(state.Vault, state.State.Revision); err != nil {
		t.Fatal(err)
	}
	// Seed an independently keyed login so the actual server rotates a real item.
	_, err = session.CreatePersonalCipher(ctx, syncResult.Scope, vaultwarden.CipherFields{Type: 1, Name: "Recovery fixture item", Login: map[string]any{"username": "fixture-user", "password": "fixture-item-password", "uris": []map[string]any{{"uri": "https://example.invalid", "match": nil}}}}, nil)
	if err != nil {
		t.Fatal("seed cipher", err)
	}
	syncResult, err = session.Sync(ctx)
	if err != nil {
		t.Fatal("seed sync", err)
	}
	state = call(storageRequest{Operation: "publishVault", ExpectedRevision: state.State.Revision, Scope: &syncResult.Scope, PasswordUnlock: syncResult.PasswordUnlock, Session: syncResult.Session, Vault: syncResult.Vault, Credentials: syncResult.Credentials})
	if !state.OK {
		t.Fatal(state.Code)
	}
	if err := session.AcceptAuthenticatedSnapshot(state.Vault, state.State.Revision); err != nil {
		t.Fatal(err)
	}
	var epoch atomic.Uint64
	epoch.Store(1)
	for cycle := 0; cycle < 2; cycle++ {
		storage, err := newAccountRecoveryStorage(state.State, epoch.Load(), epoch.Load, syncResult.PasswordUnlock.Key, call)
		if err != nil {
			t.Fatal(err)
		}
		checkpoint := func(cp vaultwarden.SessionCheckpoint) error {
			reply, err := saveSessionCheckpoint(state.State, cp, call)
			if err == nil {
				state = reply
			}
			return err
		}
		plan, err := session.PrepareAccountRotation(ctx, state.Vault, password, storageLiveRotationAdapter{}, checkpoint)
		if err != nil {
			t.Fatal("prepare rotation", err)
		}
		if cycle == 0 {
			dir := os.Getenv("SNAPSHOT_TEST_DIRECTORY")
			if err := os.Chmod(dir, 0500); err != nil {
				t.Fatal(err)
			}
			failed, commitErr := session.CommitAccountChange(ctx, plan, string(vaultwarden.AccountRotateKey), checkpoint, storage.Begin)
			restoreErr := os.Chmod(dir, 0700)
			if restoreErr != nil {
				t.Fatal(restoreErr)
			}
			if commitErr == nil || failed.Dispatched || posts.Load() != 0 {
				t.Fatal("disk failure did not block rotation POST")
			}
			plan.Close()
			plan, err = session.PrepareAccountRotation(ctx, state.Vault, password, storageLiveRotationAdapter{}, checkpoint)
			if err != nil {
				t.Fatal(err)
			}
		}
		drop.Store(cycle == 1)
		result, commitErr := session.CommitAccountChange(ctx, plan, string(vaultwarden.AccountRotateKey), checkpoint, storage.Begin)
		plan.Close()
		if !result.Dispatched || (cycle == 0 && (commitErr != nil || !result.Confirmed)) || (cycle == 1 && (commitErr == nil || !result.Unknown)) {
			t.Fatalf("unexpected rotation result cycle=%d err=%v", cycle, commitErr)
		}
		if err := storage.Result(result); err != nil {
			t.Fatal("persist result", err)
		}
		pending, err := storage.Query()
		if err != nil {
			t.Fatal(err)
		}
		var recovery vaultwarden.AccountRecovery
		if json.Unmarshal(pending.Recovery.Record, &recovery) != nil || len(recovery.NewUserKey) != 64 {
			t.Fatal("missing recovery keys")
		}
		pending.Recovery.Close()
		// Simulate exit/reopen by dropping the controller adapter. No old session is
		// restored. The same persisted operation is discovered after lock/re-auth.
		storage.Close()
		epoch.Add(1)
		locked := call(storageRequest{Operation: "lock"})
		if !locked.OK {
			t.Fatal(locked.Code)
		}
		storage, err = newAccountRecoveryStorage(locked.State, epoch.Load(), epoch.Load, recovery.OldUnlock.Key, call)
		if err != nil {
			t.Fatal(err)
		}
		defer storage.Close()
		reopened, err := storage.Query()
		if err != nil {
			t.Fatal(err)
		}
		reopened.Recovery.Close()
		freshSession, err := client.Login(ctx, email, password, nil)
		if err != nil {
			t.Fatal("new-key login", err)
		}
		fresh, err := freshSession.SyncWithCheckpoint(ctx, storage.Checkpoint)
		if err != nil {
			t.Fatal("new-key full sync", err)
		}
		if len(fresh.Credentials) != 1 || fresh.Credentials[0].Title != "Recovery fixture item" || fresh.Credentials[0].Password != "fixture-item-password" {
			t.Fatal("rotated item did not decrypt")
		}
		// Verify the authoritative session uses the journal's new key; empty other
		// resources were actually enumerated before POST by the fixture adapter.
		var saved struct{ UserKey []byte }
		if json.Unmarshal(fresh.Session, &saved) != nil || recoveryHash(saved.UserKey) != recoveryHash(recovery.NewUserKey) {
			t.Fatal("authoritative wrapper selected unexpected key")
		}
		clear(saved.UserKey)
		complete, err := storage.ResolveVerified(fresh, true, true, true)
		if err != nil {
			t.Fatal("durable completion", err)
		}
		if err := freshSession.AcceptAuthenticatedSnapshot(complete.Vault, complete.State.Revision); err != nil {
			t.Fatal("install receipt", err)
		}
		recovery.Close()
		session.Close()
		session = freshSession
		state = complete
		syncResult = fresh
	}
	session.Close()
	if posts.Load() != 2 {
		t.Fatal("rotation was retried unexpectedly")
	}
}
