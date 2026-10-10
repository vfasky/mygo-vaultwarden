// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/organization"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type runtimeDeviceFixture struct {
	key                                   []byte
	wrapped, private, public, code, email string
	config                                vaultwarden.PasswordUnlockConfig
	grants, refreshes                     int
}

func (d *runtimeDeviceFixture) serve(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case strings.HasPrefix(r.URL.Path, "/notifications/"):
		w.WriteHeader(http.StatusNotFound)
	case r.URL.Path == "/api/devices/knowndevice":
		json.NewEncoder(w).Encode(true)
	case r.URL.Path == "/api/auth-requests":
		var request struct{ PublicKey, AccessCode string }
		json.NewDecoder(r.Body).Decode(&request)
		d.public, d.code = request.PublicKey, request.AccessCode
		json.NewEncoder(w).Encode(map[string]any{"id": "11111111-1111-4111-8111-111111111111", "publicKey": d.public})
	case strings.HasPrefix(r.URL.Path, "/api/auth-requests/") && strings.HasSuffix(r.URL.Path, "/response"):
		raw, e := base64.StdEncoding.DecodeString(d.public)
		if e != nil {
			w.WriteHeader(400)
			return true
		}
		public, e := x509.ParsePKIXPublicKey(raw)
		if e != nil {
			w.WriteHeader(400)
			return true
		}
		wrapped, e := rsa.EncryptOAEP(sha256.New(), rand.Reader, public.(*rsa.PublicKey), d.key, nil)
		if e != nil {
			w.WriteHeader(400)
			return true
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "11111111-1111-4111-8111-111111111111", "publicKey": d.public, "key": "3." + base64.StdEncoding.EncodeToString(wrapped), "requestApproved": true, "responseDate": "2026-01-01T00:00:00Z"})
	case r.URL.Path == "/identity/connect/token":
		r.ParseForm()
		if r.Form.Get("grant_type") == "refresh_token" {
			d.refreshes++
			return false
		}
		if r.Form.Get("password") != d.code || r.Form.Get("authrequest") != "11111111-1111-4111-8111-111111111111" {
			w.WriteHeader(400)
			return true
		}
		d.grants++
		json.NewEncoder(w).Encode(map[string]any{"access_token": "test-access", "refresh_token": "runtime-refresh-must-not-persist", "expires_in": 3600, "token_type": "Bearer", "key": d.wrapped})
	case r.URL.Path == "/identity/accounts/prelogin":
		json.NewEncoder(w).Encode(d.config.KDF)
	default:
		return false
	}
	return true
}
func newRuntimeResourceControllerFixture(t *testing.T) *resourceControllerFixture {
	t.Helper()
	f := newResourceControllerFixture(t, true)
	a := f.a
	d := &runtimeDeviceFixture{key: bytes.Repeat([]byte{4}, 64), email: a.snapshot.PasswordUnlock.Email, config: *a.snapshot.PasswordUnlock}
	master, e := vaultcrypto.DeriveMaster([]byte("fixture-master"), d.email, d.config.KDF)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(master)
	stretched, e := vaultcrypto.StretchMaster(master)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(stretched)
	d.wrapped, e = vaultcrypto.EncryptString(d.key, stretched)
	if e != nil {
		t.Fatal(e)
	}
	private, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	d.private, e = vaultcrypto.EncryptString(der, d.key)
	clear(der)
	if e != nil {
		t.Fatal(e)
	}
	f.body["profile"].(map[string]any)["key"] = d.wrapped
	f.body["profile"].(map[string]any)["privateKey"] = d.private
	f.body["sends"] = []any{}
	login, e := vaultwarden.NewPersonalCipher(vaultwarden.CipherFields{Type: 1, Name: "Runtime login", Login: map[string]any{"username": "runtime-user", "password": "runtime-secret"}}, d.key, a.liveScope.Account)
	if e != nil {
		t.Fatal(e)
	}
	var loginObject map[string]any
	json.Unmarshal(login.JSON, &loginObject)
	itemKey, e := vaultcrypto.DecryptString(loginObject["key"].(string), d.key)
	if e != nil {
		t.Fatal(e)
	}
	history, e := vaultcrypto.EncryptString([]byte("prior-runtime-secret"), itemKey)
	clear(itemKey)
	if e != nil {
		t.Fatal(e)
	}
	loginObject["passwordHistory"] = []any{map[string]any{"password": history, "lastUsedDate": "2026-01-01T00:00:00Z"}}
	loginObject["id"], loginObject["revisionDate"], loginObject["edit"], loginObject["viewPassword"] = "runtime-login", "2026-01-01T00:00:00Z", true, true
	f.body["ciphers"] = append(f.body["ciphers"].([]any), loginObject)
	f.body["folders"] = []any{}
	f.device = d
	a.serverURL, a.email, a.deviceID = a.liveScope.Server, d.email, "runtime-controller-device"
	a.uiDispatcher = f.dispatch
	sourceStorage := func(r localstore.Request) localstore.Reply {
		if r.Operation == "list" || r.Operation == "targetRecoveryRuntimePending" {
			f.mu.Lock()
			defer f.mu.Unlock()
			if r.ExpectedRevision != f.state.Revision {
				return localstore.Reply{Code: "stale_revision"}
			}
			v := *f.vault
			v.Sync = append([]byte(nil), v.Sync...)
			return localstore.Reply{OK: true, State: f.state, Vault: &v, TargetRecords: []localstore.TargetRecoveryRecord{}}
		}
		if r.Operation == "lock" {
			f.mu.Lock()
			defer f.mu.Unlock()
			state := *f.state
			state.Revision += "-locked"
			f.state = &state
			return localstore.Reply{OK: true, State: &state}
		}
		return f.storage(r)
	}
	a.storageBackend = sourceStorage
	var nativeMu sync.Mutex
	active := map[string]localstore.RuntimeSecretRequest{}
	nativeCall := func(raw []byte) ([]byte, error) {
		nativeMu.Lock()
		defer nativeMu.Unlock()
		var request localstore.RuntimeSecretRequest
		if json.Unmarshal(raw, &request) != nil {
			t.Fatal("native request")
		}
		if request.Operation == "activate" {
			request.LeaseID = strings.Repeat("a", 64)
			active[request.Purpose] = request
		} else if request.Operation == "revoke" {
			delete(active, request.Purpose)
		} else if active[request.Purpose].Generation != request.Generation {
			return json.Marshal(localstore.RuntimeSecretReply{OK: false})
		}
		return json.Marshal(localstore.RuntimeSecretReply{OK: true, LeaseID: request.LeaseID, Generation: request.Generation, DeadlineUnixMS: request.DeadlineUnixMS})
	}
	a.openDeviceLoginWith(f.dispatch, sourceStorage, func() *localstore.NativeRuntimeSecrets { return &localstore.NativeRuntimeSecrets{Call: nativeCall} })
	deadline := time.After(10 * time.Second)
	for a.runtimeVault == nil {
		select {
		case fn := <-f.q:
			fn()
		case <-deadline:
			t.Fatal("runtime login did not install", a.status)
		}
	}
	if a.pending != 0 || f.serial != 0 || d.grants != 1 || d.refreshes != 0 {
		t.Fatal("runtime login changed disk or refreshed")
	}
	return f
}
func TestRuntimeControllerDeviceToResourceImportAndEveryFile(t *testing.T) {
	f := newRuntimeResourceControllerFixture(t)
	before, _ := json.Marshal(f.state)
	f.open(true)
	f.a.importBackupWith(f.dispatch, f.storage, f.refresh)
	f.drain()
	if f.creates != 1 {
		t.Fatal("runtime metadata mutation unavailable", f.a.status)
	}
	e := f.a.backupEditor
	for i := range 2 {
		f.file(i, false)
		f.file(i, true)
		if e.resources.rows[i].State != organization.ResourceVerified {
			t.Fatal("runtime resource did not verify", i, f.a.status)
		}
	}
	after, _ := json.Marshal(f.state)
	if !bytes.Equal(before, after) || f.serial != 0 || f.uploads != 2 || f.device.refreshes != 0 {
		t.Fatal("runtime touched disk/refresh or missed files")
	}
	cap := f.a.runtimeVault.authority
	f.a.runStorage("logout")
	f.drain()
	if cap.CheckLease() == nil || f.a.runtimeVault != nil || f.a.deviceFlow != nil || !f.state.Available || f.serial != 0 {
		t.Fatal("runtime logout retained authority or deleted old disk")
	}
}
func TestRuntimeControllerSecretRepromptSourceAndNewAuthorization(t *testing.T) {
	f := newRuntimeResourceControllerFixture(t)
	f.a.openCipherEditor("runtime-login", 1)
	if f.a.editor == nil {
		t.Fatal("runtime ordinary item entry")
	}
	f.a.showCipherHistory(f.a.vaultStorage())
	if len(f.a.editor.shownHistory) != 1 {
		t.Fatal("runtime history", f.a.status)
	}
	f.a.showPersonalSecret("password", f.a.vaultStorage())
	if f.a.editor.shownSecret != "runtime-secret" || len(f.a.editor.shownHistory) != 0 {
		t.Fatal("new native authorization retained old display", f.a.status)
	}
	f.a.copyPersonalSecret("password", f.a.vaultStorage())
	if !f.a.secretClipboardOwned || f.a.editor.shownSecret != "" {
		t.Fatal("runtime copy/new authorization")
	}
	f.mu.Lock()
	f.cipher("runtime-login")["reprompt"] = 1
	f.mu.Unlock()
	f.refresh()
	f.drain()
	f.a.openCipherEditor("runtime-login", 1)
	if f.a.editor == nil || f.a.editor.repromptID != "runtime-login" {
		t.Fatal("reprompt missing")
	}
	f.a.editor.repromptPassword = "fixture-master"
	f.a.authorizePersonalItem()
	f.drain()
	if f.a.editor == nil || f.a.editor.authorization == nil {
		t.Fatal("runtime reprompt failed", f.a.status)
	}
	f.a.showPersonalSecret("password", f.a.vaultStorage())
	if f.a.editor.shownSecret != "runtime-secret" {
		t.Fatal("authorized runtime secret", f.a.status)
	}
	f.mu.Lock()
	f.failLease = true
	f.mu.Unlock()
	f.a.showPersonalSecret("password", f.a.vaultStorage())
	if f.a.editor.shownSecret != "" {
		t.Fatal("changed source exposed secret")
	}
	if f.serial != 0 || f.device.refreshes != 0 {
		t.Fatal("runtime secret persisted credentials")
	}
}
func TestRuntimeControllerBindPasswordPublishesOnlyAfterFreshSync(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "write-failed"}[fail], func(t *testing.T) {
			f := newRuntimeResourceControllerFixture(t)
			before, _ := json.Marshal(f.state)
			f.failPublish = fail
			f.a.masterPassword = "fixture-master"
			f.a.bindRuntimePasswordWith(f.dispatch, f.storage)
			f.drain()
			if fail {
				after, _ := json.Marshal(f.state)
				if !bytes.Equal(before, after) || f.serial != 0 || f.a.runtimeVault != nil {
					t.Fatal("failed binding overwrote disk or reused revoked runtime")
				}
			} else {
				if f.a.runtimeVault != nil || f.serial != 1 || f.a.sessionRevision != f.state.Revision || !f.a.sessionOwnsSnapshot() || f.a.deviceFlow == nil {
					t.Fatal("binding did not install receipt and retain flow", f.a.status)
				}
			}
		})
	}
}
