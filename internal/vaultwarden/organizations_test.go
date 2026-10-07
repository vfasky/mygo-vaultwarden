// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func organizationFixture(t *testing.T, endpoint string) (*Session, *VaultData, []byte, CipherDocument) {
	t.Helper()
	session, _ := resumableFixture(t, endpoint)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(private)
	public, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	wrapped, _ := EncryptString(der, session.key)
	key := bytes.Repeat([]byte{27}, 64)
	rsaCipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &private.PublicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	org := Organization{ID: "org-1", OrganizationUserID: "member-1", UserID: "account-a", Name: "组织一", Key: "3." + base64.StdEncoding.EncodeToString(rsaCipher), Status: 2, Type: 2, Enabled: true}
	name, _ := EncryptString([]byte("共享集合"), key)
	document, err := NewPersonalCipher(CipherFields{Type: 1, Name: "组织项目", Login: map[string]any{"username": "user", "password": "secret"}}, key, session.account)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := documentObject(document)
	object["id"], object["organizationId"], object["collectionIds"] = "item-org", org.ID, []string{"collection-1"}
	object["revisionDate"], object["edit"], object["viewPassword"] = "2026-06-01T00:00:00Z", true, true
	document.JSON, _ = json.Marshal(object)
	raw, _ := json.Marshal(map[string]any{"profile": map[string]any{"id": "account-a", "privateKey": wrapped, "accountKeys": map[string]any{"publicKeyEncryptionKeyPair": map[string]any{"wrappedPrivateKey": wrapped, "publicKey": base64.StdEncoding.EncodeToString(public)}}, "organizations": []Organization{org}, "organizationsNew": []Organization{org}}, "collections": []Collection{{ID: "collection-1", OrganizationID: org.ID, Name: name}}, "ciphers": []json.RawMessage{document.JSON}})
	vault := &VaultData{Version: 1, Scope: Scope{Server: endpoint, Account: "account-a"}, Sync: raw}
	if err := session.BindSnapshotRevision(vault.Scope, "revision-1"); err != nil {
		t.Fatal(err)
	}
	return session, vault, key, document
}
func changeOrganizationFixture(t *testing.T, vault *VaultData, change func(map[string]any)) *VaultData {
	t.Helper()
	var data map[string]any
	if json.Unmarshal(vault.Sync, &data) != nil {
		t.Fatal("fixture JSON")
	}
	change(data)
	raw, _ := json.Marshal(data)
	return &VaultData{Version: 1, Scope: vault.Scope, Sync: raw}
}
func TestOrganizationRSAAndIdentity(t *testing.T) {
	s, vault, key, doc := organizationFixture(t, "http://127.0.0.1:1")
	defer s.Close()
	defer clear(key)
	organizations, collections, err := s.Organizations(vault)
	if err != nil || len(organizations) != 1 || organizations[0].Name != "组织一" || organizations[0].Key != "" || organizations[0].OrganizationUserID == organizations[0].UserID || len(collections) != 1 || collections[0].Name != "共享集合" {
		t.Fatal("organization metadata", err)
	}
	_, fields, err := s.ReadOrganizationCipher(vault, "item-org", nil)
	if err != nil || fields.Login["password"] != "secret" || fields.OrganizationID == nil {
		t.Fatal("item key decryption", err)
	}
	if _, _, err := s.ReadPersonalCipherAuthorized(vault, "item-org", nil); err != ErrPermission {
		t.Fatal("personal bypass", err)
	}
	fields.Name = "new"
	if _, err := s.UpdatePersonalCipher(context.Background(), vault.Scope, doc, fields, nil); err != ErrPermission {
		t.Fatal("personal update bypass", err)
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"member-is-user", func(d map[string]any) {
			p := d["profile"].(map[string]any)
			p["organizations"].([]any)[0].(map[string]any)["OrganizationUserID"] = "account-a"
		}},
		{"wrong-account", func(d map[string]any) {
			p := d["profile"].(map[string]any)
			p["organizations"].([]any)[0].(map[string]any)["UserID"] = "other"
		}},
		{"compatibility-mismatch", func(d map[string]any) { d["profile"].(map[string]any)["privateKey"] = "2.bad" }},
		{"missing-collection-flags", func(d map[string]any) { delete(d["collections"].([]any)[0].(map[string]any), "ReadOnly") }},
		{"cross-organization-collection", func(d map[string]any) { d["collections"].([]any)[0].(map[string]any)["OrganizationID"] = "org-other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered := changeOrganizationFixture(t, vault, tc.change)
			_, _, err := s.ReadOrganizationCipher(altered, "item-org", nil)
			if tc.name == "cross-organization-collection" { // unrelated collections are not granted or used as destinations
				_, cs, e := s.Organizations(altered)
				if e != nil || len(cs) != 0 {
					t.Fatal("foreign collection", e)
				}
				return
			}
			if err == nil {
				t.Fatal("accepted invalid organization state")
			}
		})
	}
}
func TestOrganizationOAEPFormats(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{42}, 64)
	for _, kind := range []string{"3", "4"} {
		digest := sha256.New()
		if kind == "4" {
			digest = sha1.New()
		}
		ciphertext, err := rsa.EncryptOAEP(digest, rand.Reader, &private.PublicKey, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		wrapped := kind + "." + base64.StdEncoding.EncodeToString(ciphertext)
		plain, err := unwrapOrganizationKey(wrapped, private)
		if err != nil || !bytes.Equal(plain, key) {
			t.Fatal("OAEP", kind, err)
		}
		for _, bad := range []string{"5." + wrapped[2:], wrapped + "|extra", wrapped[:len(wrapped)-4], "3.AAAA", "4." + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 256))} {
			if _, err := unwrapOrganizationKey(bad, private); err == nil {
				t.Fatal("bad RSA accepted")
			}
		}
	}
}
func TestOrganizationRestrictionsAndRevocation(t *testing.T) {
	s, vault, _, _ := organizationFixture(t, "http://127.0.0.1:1")
	defer s.Close()
	for _, tc := range []struct {
		name         string
		change       func(map[string]any)
		wantReadable bool
	}{
		{"read-only", func(d map[string]any) { d["ciphers"].([]any)[0].(map[string]any)["edit"] = false }, true},
		{"hide-passwords", func(d map[string]any) { d["ciphers"].([]any)[0].(map[string]any)["viewPassword"] = false }, false},
		{"reprompt", func(d map[string]any) { d["ciphers"].([]any)[0].(map[string]any)["reprompt"] = 1 }, false},
		{"accepted-only", func(d map[string]any) {
			p := d["profile"].(map[string]any)
			for _, field := range []string{"organizations", "organizationsNew"} {
				p[field].([]any)[0].(map[string]any)["Status"] = 1
			}
		}, false},
		{"disabled", func(d map[string]any) {
			p := d["profile"].(map[string]any)
			for _, field := range []string{"organizations", "organizationsNew"} {
				p[field].([]any)[0].(map[string]any)["Enabled"] = false
			}
		}, false},
		{"revoked", func(d map[string]any) {
			p := d["profile"].(map[string]any)
			p["organizations"], p["organizationsNew"] = []any{}, []any{}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := changeOrganizationFixture(t, vault, tc.change)
			doc, fields, err := s.ReadOrganizationCipher(v, "item-org", nil)
			if (err == nil) != tc.wantReadable {
				t.Fatal("permission", err)
			}
			if tc.name == "read-only" {
				fields.Name = "illegal"
				if _, err := s.UpdateOrganizationCipher(context.Background(), v, doc, fields, nil, nil); err != ErrPermission {
					t.Fatal("read-only write", err)
				}
			}
		})
	}
	s.Close()
	if _, _, err := s.Organizations(vault); err != ErrExpired {
		t.Fatal("closed keys", err)
	}
}
func TestOrganizationUpdateCheckpointAndUnknownPreservation(t *testing.T) {
	var requests atomic.Int32
	var ownerKey []byte
	server := newOrganizationPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "PUT" || r.URL.Path != "/api/ciphers/item-org" {
			t.Error("route")
		}
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		obj, _ := documentObject(CipherDocument{JSON: raw})
		if obj["encryptedFor"] != "account-a" || obj["lastKnownRevisionDate"] != "2026-06-01T00:00:00Z" || obj["opaque"] != "preserve" {
			t.Error("lost source")
		}
		fields, err := DecryptCipherDocument(CipherDocument{JSON: raw}, ownerKey)
		if err != nil || fields.Name != "edited" {
			t.Error("encryption", err)
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	s, vault, key, _ := organizationFixture(t, server.URL)
	defer s.Close()
	ownerKey = key
	vault = changeOrganizationFixture(t, vault, func(d map[string]any) { d["ciphers"].([]any)[0].(map[string]any)["opaque"] = "preserve" })
	doc, fields, err := s.ReadOrganizationCipher(vault, "item-org", nil)
	if err != nil {
		t.Fatal(err)
	}
	fields.Name = "edited"
	s.checkpointPending = true
	_, err = s.UpdateOrganizationCipher(context.Background(), vault, doc, fields, nil, func(SessionCheckpoint) error { return errors.New("storage failed") })
	if err == nil || requests.Load() != 0 {
		t.Fatal("checkpoint bypass", err)
	}
	s.checkpointPending = false
	if _, err = s.UpdateOrganizationCipher(context.Background(), vault, doc, fields, nil, nil); err != nil || requests.Load() != 1 {
		t.Fatal("write", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.UpdateOrganizationCipher(ctx, vault, doc, fields, nil, nil); err == nil || requests.Load() != 1 {
		t.Fatal("cancelled dispatched", err)
	}
}
func TestOrganizationCloseCancelsInFlightWrite(t *testing.T) {
	started := make(chan struct{})
	server := newOrganizationPolicyServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	s, vault, _, _ := organizationFixture(t, server.URL)
	doc, fields, err := s.ReadOrganizationCipher(vault, "item-org", nil)
	if err != nil {
		t.Fatal(err)
	}
	fields.Name = "cancelled"
	result := make(chan error, 1)
	go func() {
		updated, err := s.UpdateOrganizationCipher(context.Background(), vault, doc, fields, nil, nil)
		if len(updated.JSON) != 0 {
			result <- errors.New("late document exposed")
			return
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("write not started")
	}
	s.Close()
	select {
	case err := <-result:
		var uncertain *MutationUncertainError
		if !errors.As(err, &uncertain) {
			t.Fatal("cancelled write must be unknown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write not cancelled")
	}
	if _, _, err := s.ReadOrganizationCipher(vault, "item-org", nil); err != ErrExpired {
		t.Fatal("closed session retained organization read", err)
	}
}

func TestOrganizationRepromptGrants(t *testing.T) {
	s, vault, _, _ := organizationFixture(t, "http://127.0.0.1:1")
	defer s.Close()
	source, _, _ := protectedItemFixture(t, "http://127.0.0.1:1")
	defer source.Close()
	s.passwordUnlock = &PasswordUnlock{Config: source.passwordUnlock.Config, Key: append([]byte(nil), source.passwordUnlock.Key...)}
	vault = changeOrganizationFixture(t, vault, func(d map[string]any) { d["ciphers"].([]any)[0].(map[string]any)["reprompt"] = 1 })
	if _, err := s.AuthorizeOrganizationItem(context.Background(), vault, "revision-1", "item-org", []byte("wrong")); err != ErrPermission {
		t.Fatal("wrong organization master password", err)
	}
	grant, err := s.AuthorizeOrganizationItem(context.Background(), vault, "revision-1", "item-org", []byte("test-master"))
	if err != nil {
		t.Fatal("organization password authorization", err)
	}
	used := false
	if err := s.WithOrganizationSecret(vault, "revision-1", "item-org", "password", grant, func(secret string, key []byte, deadline time.Time) error {
		used = true
		if secret != "secret" || len(key) != 32 || deadline.After(grant.ExpiresAt()) {
			t.Fatal("secret grant scope")
		}
		return nil
	}); err != nil || !used {
		t.Fatal("organization authorized secret", err)
	}
	hidden := changeOrganizationFixture(t, vault, func(d map[string]any) { d["ciphers"].([]any)[0].(map[string]any)["viewPassword"] = false })
	for _, kind := range []string{"password", "totp"} {
		if err := s.WithOrganizationSecret(hidden, "revision-1", "item-org", kind, grant, func(string, []byte, time.Time) error { t.Fatal("hidden-password bypass"); return nil }); err != ErrPermission {
			t.Fatal("hidden secret", err)
		}
	}
	if _, _, err := s.ReadOrganizationCipher(vault, "item-org", grant); err != nil {
		t.Fatal("valid grant", err)
	}
	_ = s.BindSnapshotRevision(vault.Scope, "revision-2")
	if _, _, err := s.ReadOrganizationCipher(vault, "item-org", grant); err != ErrPermission {
		t.Fatal("stale grant", err)
	}
	if _, err := s.AuthorizePersonalItem(context.Background(), vault, "revision-2", "item-org", []byte("fixture")); err != ErrPermission {
		t.Fatal("personal grant bypass", err)
	}
}
