// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func ownerVault(t *testing.T, vault *VaultData) *VaultData {
	return changeOrganizationFixture(t, vault, func(d map[string]any) {
		p := d["profile"].(map[string]any)
		for _, name := range []string{"organizations", "organizationsNew"} {
			p[name].([]any)[0].(map[string]any)["Type"] = float64(0)
		}
	})
}

func TestOrganizationManagementCreatesIndependentKeyAndPlainMetadata(t *testing.T) {
	var session *Session
	var vault *VaultData
	var createdKeys [][]byte
	server := newOrganizationPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/organizations" {
			t.Error("route")
		}
		var body struct {
			Name, BillingEmail, CollectionName, Key string
			PlanType                                int
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name != "团队" || body.BillingEmail != "owner@example.invalid" || body.PlanType != 0 {
			t.Error("metadata")
		}
		var data struct{ Profile json.RawMessage }
		_ = json.Unmarshal(vault.Sync, &data)
		private, err := accountPrivateKey(data.Profile, session.key)
		if err != nil {
			t.Error(err)
			return
		}
		defer clearAccountPrivateKey(private)
		key, err := unwrapOrganizationKey(body.Key, private)
		if err != nil || bytes.Equal(key, session.key) {
			t.Error("org key", err)
		}
		createdKeys = append(createdKeys, key)
		collection, err := vaultcrypto.DecryptString(body.CollectionName, key)
		if err != nil || string(collection) != "默认私密集合" {
			t.Error("collection encryption", err)
		}
		_, _ = w.Write([]byte(`{"id":"created-org","name":"团队","billingEmail":"owner@example.invalid"}`))
	}))
	defer server.Close()
	session, vault, _, _ = organizationFixture(t, server.URL)
	defer session.Close()
	for i := 0; i < 2; i++ {
		got, err := session.SaveOrganization(context.Background(), vault, "", OrganizationSettings{Name: "团队", BillingEmail: "owner@example.invalid", CollectionName: "默认私密集合"}, nil)
		if err != nil || got.ID != "created-org" {
			t.Fatal(got, err)
		}
	}
	if len(createdKeys) != 2 || bytes.Equal(createdKeys[0], createdKeys[1]) {
		t.Fatal("key reused")
	}
}

func TestOrganizationManagementPermissionsCheckpointAndIsolationOrder(t *testing.T) {
	var calls atomic.Int32
	isolated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !isolated {
			t.Error("request preceded durable isolation")
		}
		if r.URL.Path != "/api/organizations/org-1/leave" || r.Method != "POST" {
			t.Error("leave route")
		}
		w.WriteHeader(http.StatusBadRequest) // last owner: live server check, not local count
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	settings := OrganizationSettings{Name: "new", BillingEmail: "owner@example.invalid"}
	if _, err := s.SaveOrganization(context.Background(), vault, "org-1", settings, nil); err != ErrPermission {
		t.Fatal(err)
	}
	if _, err := s.OrganizationProfile(context.Background(), vault, "org-1", nil); err != ErrPermission {
		t.Fatal(err)
	}
	if err := s.DeleteOrganization(context.Background(), vault, "org-1", []byte("password"), nil, nil); err != ErrPermission {
		t.Fatal(err)
	}
	if err := s.LeaveOrganization(context.Background(), vault, "org-1", nil, nil); err != ErrCheckpoint {
		t.Fatal(err)
	}
	if err := s.LeaveOrganization(context.Background(), vault, "org-1", func(SessionCheckpoint) error { return errors.New("disk failed") }, nil); err != ErrCheckpoint {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request sent")
	}
	installFixtureSnapshot(t, s, vault, "revision-1")
	err := s.LeaveOrganization(context.Background(), vault, "org-1", func(cp SessionCheckpoint) error {
		if cp.Scope != vault.Scope || len(cp.UnlockKey) != 32 || len(cp.Session) == 0 {
			t.Fatal("isolation authority")
		}
		isolated = true
		return nil
	}, nil)
	var uncertain *MutationUncertainError
	if !errors.As(err, &uncertain) || calls.Load() != 1 {
		t.Fatal("nontransactional error retried", err)
	}
}

func TestOrganizationManagementOwnerUpdateIdentityAndPasswordDelete(t *testing.T) {
	var methods []string
	var isolated bool
	var expectedHash string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.URL.Path != "/api/organizations/org-1" {
			t.Error("org path")
		}
		if r.Method == "DELETE" {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !isolated || len(body) != 1 || body["masterPasswordHash"] != expectedHash {
				t.Error("delete verification")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == "PUT" {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body) != 2 || body["name"] != "new name" || body["billingEmail"] != "owner@example.invalid" {
				t.Error("update DTO")
			}
		}
		_, _ = w.Write([]byte(`{"id":"org-1","name":"new name","billingEmail":"owner@example.invalid"}`))
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	vault = acceptedOwnerVault(t, s, vault)
	if _, err := s.OrganizationProfile(context.Background(), vault, "org-1", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveOrganization(context.Background(), vault, "org-1", OrganizationSettings{Name: "new name", BillingEmail: "owner@example.invalid"}, nil); err != nil {
		t.Fatal(err)
	}
	master, err := vaultcrypto.DeriveMaster([]byte("master"), s.passwordUnlock.Config.Email, s.passwordUnlock.Config.KDF)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	expectedHash = vaultcrypto.AuthorizationHash(master, []byte("master"))
	if err := s.DeleteOrganization(context.Background(), vault, "org-1", []byte("master"), func(SessionCheckpoint) error { isolated = true; return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if len(methods) != 3 {
		t.Fatal(methods)
	}
}

func TestOrganizationManagementCancelAfterIsolationIsUnknown(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "lock-close"}[closeSession], func(t *testing.T) {
			received := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				close(received)
				<-release
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			s, vault, _, _ := organizationFixture(t, server.URL)
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			isolated := false
			done := make(chan error, 1)
			go func() {
				done <- s.LeaveOrganization(ctx, vault, "org-1", func(SessionCheckpoint) error { isolated = true; return nil }, nil)
			}()
			select {
			case <-received:
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("write not sent")
			}
			if closeSession {
				s.Close()
			} else {
				cancel()
			}
			close(release)
			select {
			case err := <-done:
				var unknown *MutationUncertainError
				if !isolated || !errors.As(err, &unknown) || calls.Load() != 1 {
					t.Fatal("isolation/cancellation boundary", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancel not honored")
			}
		})
	}
}

func TestOrganizationManagementRefreshCheckpointBlocksDispatch(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	defer s.Close()
	s.checkpointPending = true
	settings := OrganizationSettings{Name: "org", BillingEmail: "owner@example.invalid", CollectionName: "default"}
	diskFailure := errors.New("disk failure")
	if _, err := s.SaveOrganization(context.Background(), vault, "", settings, func(SessionCheckpoint) error { return diskFailure }); !errors.Is(err, diskFailure) {
		t.Fatal(err)
	}
	installFixtureSnapshot(t, s, vault, "revision-1")
	isolated := false
	if err := s.LeaveOrganization(context.Background(), vault, "org-1", func(SessionCheckpoint) error { isolated = true; return nil }, func(SessionCheckpoint) error { return diskFailure }); !errors.Is(err, diskFailure) {
		t.Fatal(err)
	}
	if !isolated || calls.Load() != 0 {
		t.Fatal("checkpoint failure sent write")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	isolated = false
	if err := s.LeaveOrganization(ctx, vault, "org-1", func(SessionCheckpoint) error { isolated = true; return nil }, nil); err == nil || isolated || calls.Load() != 0 {
		t.Fatal("pre-cancel isolation or dispatch", err)
	}
	installFixtureSnapshot(t, s, vault, "revision-1")
	if _, err := s.SaveOrganization(context.Background(), vault, "", settings, func(SessionCheckpoint) error { return nil }); err == nil || calls.Load() != 1 || s.checkpointPending {
		t.Fatal("durable refreshed checkpoint did not permit request", err)
	}
}

func TestQuarantinedOrganizationNeverProvidesKeysDocumentsOrProjection(t *testing.T) {
	s, vault, _, _ := organizationFixture(t, "http://127.0.0.1:1")
	defer s.Close()
	vault.QuarantinedOrganizations = []string{"org-1"}
	installFixtureSnapshot(t, s, vault, "revision-1")
	orgs, collections, err := s.Organizations(vault)
	if err != nil || len(orgs) != 0 || len(collections) != 0 {
		t.Fatal("isolated metadata", err)
	}
	docs, err := vault.Documents(vault.Scope)
	if err != nil || len(docs) != 0 {
		t.Fatal("isolated docs", err)
	}
	if _, _, err := s.ReadOrganizationCipher(vault, "item-org", nil); err == nil {
		t.Fatal("isolated key access")
	}
	if err := s.LeaveOrganization(context.Background(), vault, "org-1", func(SessionCheckpoint) error { t.Fatal("isolation retried"); return nil }, nil); err != ErrPermission {
		t.Fatal(err)
	}
	vault.QuarantinedOrganizations = []string{"../org-1"}
	if _, err := vault.Documents(vault.Scope); err != ErrProtocol {
		t.Fatal("invalid marker", err)
	}
}
