// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func writePendingInvitationProfile(w http.ResponseWriter) {
	_, _ = w.Write([]byte(`{"id":"account-a","email":"fixture@example.invalid","organizations":[],"organizationsNew":[]}`))
}

func TestInvitationRecoveryConsentAndChangedAuthority(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer clearAccountPrivateKey(private)
	der, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	public := base64.StdEncoding.EncodeToString(der)
	policyOrg, policyData := "new-org", `{"autoEnrollEnabled":true}`
	profileAccepted := false
	var writes, reads atomic.Int32
	var recovered []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			reads.Add(1)
		}
		switch r.URL.Path {
		case "/api/accounts/profile":
			rows := []Organization{}
			if profileAccepted {
				rows = append(rows, Organization{ID: "new-org", OrganizationUserID: "new-member", UserID: "account-a", Status: 1})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "account-a", "email": "fixture@example.invalid", "organizations": []any{}, "organizationsNew": rows})
		case "/api/organizations/new-org/policies/token":
			if r.URL.Query().Get("token") != "a+b&c=d" {
				t.Error("query token corrupted")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"type": 8, "organizationId": policyOrg, "enabled": true, "data": json.RawMessage(policyData)}}})
		case "/api/organizations/new-org/public-key":
			_ = json.NewEncoder(w).Encode(map[string]any{"publicKey": public})
		case "/api/organizations/new-org/users/new-member/accept":
			writes.Add(1)
			var payload map[string]string
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload["token"] != "a+b&c=d" || !strings.HasPrefix(payload["resetPasswordKey"], "3.") {
				t.Error("accept payload")
				return
			}
			wrapped, _ := base64.StdEncoding.DecodeString(payload["resetPasswordKey"][2:])
			var err error
			recovered, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, private, wrapped, nil)
			if err != nil {
				t.Error(err)
			}
		default:
			t.Error("unexpected request", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	link := server.URL + "/#/accept-organization/?" + url.Values{"email": {s.email}, "organizationId": {"new-org"}, "organizationUserId": {"new-member"}, "token": {"a+b&c=d"}}.Encode()
	draft, err := s.PrepareInvitationAcceptance(context.Background(), v, link, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer draft.Close()
	if !draft.RecoveryRequired() || draft.RecoveryPublicKey() != public {
		t.Fatal("consent details")
	}
	before := reads.Load()
	for _, approval := range []struct {
		consent bool
		key     string
	}{{false, public}, {true, ""}, {true, "wrong"}} {
		if err = s.AcceptPreparedInvitation(context.Background(), v, draft, approval.consent, approval.key, nil); err != ErrPermission {
			t.Fatal(err)
		}
	}
	if reads.Load() != before || writes.Load() != 0 {
		t.Fatal("unapproved enrollment made requests")
	}
	policyData = `{"autoEnrollEnabled":true,"futureSetting":"changed"}`
	if err = s.AcceptPreparedInvitation(context.Background(), v, draft, true, public, nil); err != ErrConflict {
		t.Fatal("policy change", err)
	}
	policyData = `{"autoEnrollEnabled":true}`
	oldPublic := public
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	defer clearAccountPrivateKey(other)
	der, _ = x509.MarshalPKIXPublicKey(&other.PublicKey)
	public = base64.StdEncoding.EncodeToString(der)
	if err = s.AcceptPreparedInvitation(context.Background(), v, draft, true, oldPublic, nil); err != ErrConflict {
		t.Fatal("key change", err)
	}
	public = oldPublic
	if writes.Load() != 0 {
		t.Fatal("changed authority wrote")
	}
	unconsumed := draft.Clone()
	defer unconsumed.Close()
	if err = s.AcceptPreparedInvitation(context.Background(), v, draft, true, public, nil); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 || !bytes.Equal(recovered, s.key) {
		t.Fatal("wrong recovery secret")
	}
	clear(recovered)
	profileAccepted = true
	if _, err = s.PrepareInvitationAcceptance(context.Background(), v, link, nil); err != ErrInvitationAlreadyAccepted {
		t.Fatal("repeat accepted invitation", err)
	}
	if writes.Load() != 1 {
		t.Fatal("repeated accept wrote")
	}
	profileAccepted = false
	if err = s.AcceptPreparedInvitation(context.Background(), v, draft, true, public, nil); err != ErrExpired {
		t.Fatal("consumed consent replay", err)
	}
	draft = unconsumed
	s.authorizationEpoch++
	if err = s.AcceptPreparedInvitation(context.Background(), v, draft, true, public, nil); err != ErrExpired {
		t.Fatal("checkpoint epoch changed consent", err)
	}
	s.authorizationEpoch--
	_ = s.BindSnapshotRevision(v.Scope, "next-revision")
	if err = s.AcceptPreparedInvitation(context.Background(), v, draft, true, public, nil); err != ErrExpired {
		t.Fatal("stale consent", err)
	}
	if writes.Load() != 1 {
		t.Fatal("stale grant wrote")
	}
	installFixtureSnapshot(t, s, v, s.authorizationRevision)
	policyOrg = "different-org"
	if _, err = s.PrepareInvitationAcceptance(context.Background(), v, link, nil); err != ErrIdentity {
		t.Fatal("foreign policy", err)
	}
}

func TestInvitationRecoveryCheckpointAndMalformedKey(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/api/accounts/profile" {
			writePendingInvitationProfile(w)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/policies/token") {
			_, _ = w.Write([]byte(`{"data":[{"organizationId":"new-org","type":8,"enabled":true,"data":{"autoEnrollEnabled":true}}]}`))
		} else {
			_, _ = w.Write([]byte(`{"publicKey":"invalid"}`))
		}
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	link := server.URL + "/#/accept-organization/?" + url.Values{"email": {s.email}, "organizationId": {"new-org"}, "organizationUserId": {"new-member"}, "token": {"token"}}.Encode()
	if _, err := s.PrepareInvitationAcceptance(context.Background(), v, link, nil); err != ErrProtocol {
		t.Fatal("malformed org key", err)
	}
	if calls.Load() != 3 {
		t.Fatal("unexpected requests")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.PrepareInvitationAcceptance(cancelled, v, link, nil); err != ErrCancelled {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("cancelled read dispatched")
	}
	s.checkpointPending = true
	diskError := errors.New("disk unavailable")
	if _, err := s.PrepareInvitationAcceptance(context.Background(), v, link, func(SessionCheckpoint) error { return diskError }); !errors.Is(err, diskError) {
		t.Fatal("checkpoint failure", err)
	}
	if calls.Load() != 3 {
		t.Fatal("invitation read escaped failed checkpoint")
	}
	s.Close()
	if _, err := s.PrepareInvitationAcceptance(context.Background(), v, link, nil); err == nil {
		t.Fatal("closed session accepted")
	}
}

func TestOrganizationRecoveryInitializationAndKeySeparation(t *testing.T) {
	var orgKey []byte
	var public string
	var writes int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": public})
			return
		}
		writes++
		var pair organizationKeyPair
		if json.NewDecoder(r.Body).Decode(&pair) != nil {
			t.Error("pair")
		}
		plain, err := vaultcrypto.DecryptString(pair.EncryptedPrivateKey, orgKey)
		if err != nil {
			t.Error(err)
			return
		}
		defer clear(plain)
		parsed, err := x509.ParsePKCS8PrivateKey(plain)
		if err != nil {
			t.Error(err)
			return
		}
		key := parsed.(*rsa.PrivateKey)
		defer clearAccountPrivateKey(key)
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if base64.StdEncoding.EncodeToString(der) != pair.PublicKey {
			t.Error("pair mismatch")
		}
		public = pair.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": public, "privateKey": pair.EncryptedPrivateKey})
	}))
	defer server.Close()
	s, v, key, _ := organizationFixture(t, server.URL)
	defer s.Close()
	orgKey = key
	if _, err := s.OrganizationRecoveryPublicKey(context.Background(), v, "org-1", true, nil); err != ErrPermission {
		t.Fatal("ordinary member initialization", err)
	}
	v = acceptedOwnerVault(t, s, v)
	if got, err := s.OrganizationRecoveryPublicKey(context.Background(), v, "org-1", false, nil); err != nil || got != "" || writes != 0 {
		t.Fatal("read created keys", err)
	}
	got, err := s.OrganizationRecoveryPublicKey(context.Background(), v, "org-1", true, nil)
	if err != nil || got == "" || writes != 1 {
		t.Fatal("initialize", err)
	}
	if again, err := s.OrganizationRecoveryPublicKey(context.Background(), v, "org-1", true, nil); err != nil || again != got || writes != 1 {
		t.Fatal("existing key was rotated", err)
	}
}

func TestClientQueryPreservesBasePathAndRejectsURLOverrides(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/vault/api/test" || r.URL.Query().Get("token") != "a+b&c=d" || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("transport binding")
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL+"/vault", fixtureUUID())
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/test?" + url.Values{"token": {"a+b&c=d"}}.Encode()
	if _, _, err = client.request(context.Background(), "GET", path, "", "", "fixture"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"https://attacker.invalid/path", "//attacker.invalid/path", "/../api", "/api/./test", "/api/%2f/test", "/api/test#fragment", "/api?bad=%Q1", `/api\test`} {
		if _, _, err = client.request(context.Background(), "GET", path, "", "", "fixture"); !errors.Is(err, ErrProtocol) {
			t.Fatal(path, err)
		}
	}
	if calls != 1 {
		t.Fatal("unsafe URL dispatched")
	}
}
