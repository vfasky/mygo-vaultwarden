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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func memberRows() []OrganizationMember {
	return []OrganizationMember{{ID: "member-1", UserID: "account-a", Email: "owner@example.invalid", Type: 0, Status: 2}, {ID: "member-2", UserID: "account-b", Email: "member@example.invalid", Type: 2, Status: 1}}
}
func writeMembers(w http.ResponseWriter, rows []OrganizationMember) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": rows, "continuationToken": nil})
}
func TestMemberConfirmationVerifiesIdentityAndWrapsOnlyOrganizationKey(t *testing.T) {
	recipient, _ := rsa.GenerateKey(rand.Reader, 2048)
	public, _ := x509.MarshalPKIXPublicKey(&recipient.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(public)
	var orgKey []byte
	var confirms int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/organizations/org-1/users":
			writeMembers(w, memberRows())
		case "/api/users/account-b/public-key":
			_ = json.NewEncoder(w).Encode(map[string]string{"userId": "account-b", "publicKey": encoded})
		case "/api/organizations/org-1/users/member-2/confirm":
			confirms++
			if r.Method != "POST" {
				t.Error("method")
			}
			var body struct{ Key string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !strings.HasPrefix(body.Key, "3.") {
				t.Error("algorithm")
				return
			}
			wrapped, err := base64.StdEncoding.DecodeString(body.Key[2:])
			if err != nil {
				t.Error(err)
				return
			}
			plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, recipient, wrapped, nil)
			if err != nil || !bytes.Equal(plain, orgKey) {
				t.Error("wrong key released", err)
			}
		default:
			t.Error("unexpected route", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	s, v, key, _ := organizationFixture(t, server.URL)
	defer s.Close()
	orgKey = key
	v = ownerVault(t, v)
	d, err := s.OrganizationMembers(context.Background(), v, "org-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	copy := d.Members()
	copy[1].UserID = "attacker" // public rows cannot alter dispatch identity
	proof, err := s.PrepareMemberConfirmation(context.Background(), v, d, "member-2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Close()
	if err = s.ConfirmOrganizationMember(context.Background(), v, proof, "not verified", nil); err != ErrIdentity {
		t.Fatal(err)
	}
	if confirms != 0 {
		t.Fatal("unverified key released")
	}
	if err = s.ConfirmOrganizationMember(context.Background(), v, proof, encoded, nil); err != nil {
		t.Fatal(err)
	}
	if confirms != 1 {
		t.Fatal(confirms)
	}
	replacement, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&replacement.PublicKey)
	encoded = base64.StdEncoding.EncodeToString(der)
	if err = s.ConfirmOrganizationMember(context.Background(), v, proof, proof.PublicKey(), nil); err != ErrConflict {
		t.Fatal("key change", err)
	}
	if confirms != 1 {
		t.Fatal("changed key released")
	}
}

func TestMemberDirectoryRejectsIdentityConfusionAndStaleAuthority(t *testing.T) {
	rows := memberRows()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; writeMembers(w, rows) }))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	if _, err := s.OrganizationMembers(context.Background(), v, "org-1", nil); err != ErrPermission {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("member dispatched admin GET")
	}
	v = ownerVault(t, v)
	rows[1].UserID = "account-a"
	if _, err := s.OrganizationMembers(context.Background(), v, "org-1", nil); err != ErrIdentity {
		t.Fatal(err)
	}
	rows = memberRows()
	d, err := s.OrganizationMembers(context.Background(), v, "org-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BindSnapshotRevision(v.Scope, "new-revision"); err != nil {
		t.Fatal(err)
	}
	before := calls
	if err = s.ChangeOrganizationMember(context.Background(), v, d, "member-2", "remove", nil, nil); err != ErrExpired {
		t.Fatal(err)
	}
	if before != calls {
		t.Fatal("stale request")
	}
}

func TestMemberSelfRemovalIsolationPrecedesEveryRequest(t *testing.T) {
	var calls atomic.Int32
	isolated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !isolated {
			t.Error("request before isolation")
		}
		if r.Method == "GET" {
			writeMembers(w, memberRows())
			return
		}
		if r.Method != "DELETE" || r.URL.Path != "/api/organizations/org-1/users/member-1" {
			t.Error("route")
		}
		w.WriteHeader(400) // live last-owner rejection is treated as possibly partial
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	v = ownerVault(t, v)
	d := &MemberDirectory{organizationID: "org-1", revision: s.authorizationRevision, scope: v.Scope, rows: memberRows()}
	for _, checkpoint := range []func(SessionCheckpoint) error{nil, func(SessionCheckpoint) error { return errors.New("disk") }} {
		if err := s.ChangeOrganizationMember(context.Background(), v, d, "member-1", "remove", checkpoint, nil); err != ErrCheckpoint {
			t.Fatal(err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("HTTP escaped")
	}
	err := s.ChangeOrganizationMember(context.Background(), v, d, "member-1", "remove", func(SessionCheckpoint) error { isolated = true; return nil }, nil)
	var unknown *MutationUncertainError
	if !errors.As(err, &unknown) || calls.Load() != 2 {
		t.Fatal(err, calls.Load())
	}
}

func TestMemberLifecycleRolesCancellationAndConflict(t *testing.T) {
	rows := memberRows()
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			writeMembers(w, rows)
			return
		}
		writes++
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	v = ownerVault(t, v)
	d, err := s.OrganizationMembers(context.Background(), v, "org-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.ChangeOrganizationMember(cancelled, v, d, "member-2", "revoke", nil, nil); err != ErrCancelled {
		t.Fatal(err)
	}
	if err = s.ChangeOrganizationMember(context.Background(), v, d, "member-1", "revoke", nil, nil); err != ErrPermission {
		t.Fatal(err)
	}
	if err = s.ChangeOrganizationMember(context.Background(), v, d, "member-2", "restore", nil, nil); err != ErrValidation {
		t.Fatal(err)
	}
	rows[1].UserID = "changed-account"
	if err = s.ChangeOrganizationMember(context.Background(), v, d, "member-2", "remove", nil, nil); err != ErrConflict {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatal("invalid operation dispatched")
	}
}

func TestMemberInvitationSingleEmailAndLinkBinding(t *testing.T) {
	var accepted, invited int
	var s *Session
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/accounts/profile" {
			writePendingInvitationProfile(w)
			return
		}
		if r.URL.Path == "/api/organizations/new-org/policies/token" {
			_, _ = w.Write([]byte(`{"data":[],"continuationToken":null}`))
			return
		}
		if r.Method == "GET" {
			writeMembers(w, memberRows())
			return
		}
		switch r.URL.Path {
		case "/api/organizations/org-1/users/invite":
			invited++
			var data struct {
				Emails []string
				Type   int
			}
			_ = json.NewDecoder(r.Body).Decode(&data)
			if len(data.Emails) != 1 || data.Emails[0] != "invite@example.invalid" || data.Type != 2 {
				t.Error("invitation body")
			}
		case "/api/organizations/new-org/users/new-member/accept":
			accepted++
			var data map[string]string
			_ = json.NewDecoder(r.Body).Decode(&data)
			if data["token"] != "test-token" || len(data) != 1 {
				t.Error("token")
			}
		default:
			t.Error(r.URL.Path)
		}
	}))
	defer server.Close()
	s, v, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	v = ownerVault(t, v)
	d, err := s.OrganizationMembers(context.Background(), v, "org-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.InviteOrganizationMember(context.Background(), v, d, "invite@example.invalid", 2, nil); err != nil {
		t.Fatal(err)
	}
	query := url.Values{"email": {s.email}, "organizationId": {"new-org"}, "organizationUserId": {"new-member"}, "token": {"test-token"}}
	link := server.URL + "/#/accept-organization/?" + query.Encode()
	if err = s.AcceptOrganizationInvitation(context.Background(), v, link, nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(link, server.URL, "https://wrong.example.invalid", 1), link + "&token=another", strings.Replace(link, "new-member", "bad%2Fid", 1), strings.Replace(link, "email=", "email=other", 1)} {
		if err = s.AcceptOrganizationInvitation(context.Background(), v, bad, nil); err == nil {
			t.Fatal("invalid link accepted")
		}
	}
	if accepted != 1 || invited != 1 {
		t.Fatal(accepted, invited)
	}
	public, err := s.AccountSharingPublicKey(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseMemberPublicKey(public); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err = s.AccountSharingPublicKey(v); err == nil {
		t.Fatal("closed account key")
	}
}
