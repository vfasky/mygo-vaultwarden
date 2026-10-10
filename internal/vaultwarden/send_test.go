// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Independent official SDK fixtures, pinned 39dbb510f5eae82f5cbfd527b0f70a01d5626ec1,
// crates/bitwarden-send/src/send.rs::test_get_send_key and test_decrypt.
func TestSendOfficialCryptoVectors(t *testing.T) {
	user, _ := base64.StdEncoding.DecodeString("w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==")
	seed, e := vaultcrypto.DecryptString("2.+1KUfOX8A83Xkwk1bumo/w==|Nczvv+DTkeP466cP/wMDnGK6W9zEIg5iHLhcuQG6s+M=|SZGsfuIAIaGZ7/kzygaVUau3LeOvJUlolENBOU+LX7g=", user)
	if e != nil {
		t.Fatal(e)
	}
	key, e := sendKey(seed)
	if e != nil || base64.StdEncoding.EncodeToString(key) != "IR9ImHGm6rRuIjiN7csj94bcZR5WYTJj5GtNfx33zm6tJCHUl+QZlpNPba8g2yn70KnOHsAODLcR0um6E3MAlg==" {
		t.Fatal("official KDF mismatch", e)
	}
	seed, _ = base64.RawURLEncoding.DecodeString("Pgui0FK85cNhBGWHAlBHBw")
	w := sendWire{Name: "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=", Text: &sendText{Text: "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0="}}
	f, e := decryptSendFields(w, seed)
	if e != nil || f.Name != "Test" || f.Text != "This is a test" {
		t.Fatal("official text mismatch", e)
	}
	seed[0] ^= 1
	if _, e = decryptSendFields(w, seed); e == nil {
		t.Fatal("wrong receiver seed accepted")
	}
	if _, e = sendKey(make([]byte, 32)); e == nil {
		t.Fatal("wrong seed length")
	}
}
func sendTestVault(t *testing.T, s *Session) *VaultData {
	t.Helper()
	body := emptyPolicySyncFixture()
	body["sends"] = []any{}
	b, _ := json.Marshal(body)
	v := &VaultData{Version: 1, Scope: Scope{Server: s.client.base.String(), Account: s.account}, Sync: b}
	installFixtureSnapshot(t, s, v, "send-revision")
	return v
}
func sendTestFields() SendFields {
	return SendFields{Name: "secret name", Text: "secret message", Notes: "private notes", DeletionDate: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)}
}
func sendTestReply(w sendWire) sendWire {
	w.ID = "b6d98b09-e6b1-42b0-93f1-d7f77aab9543"
	w.AccessID = sendAccessID(w.ID)
	w.RevisionDate = "2026-01-01T00:00:00Z"
	w.AuthType = 2
	if w.Password != nil {
		p := "server-password-hash"
		w.Password = &p
		w.AuthType = 1
	}
	return w
}
func TestSendOwnerLifecycleAndPolicies(t *testing.T) {
	for _, tc := range []struct {
		name          string
		role, kind    int
		hide, blocked bool
	}{{"normal", 2, 5, false, false}, {"disabled", 2, 6, false, true}, {"admin", 1, 6, false, false}, {"hide", 2, 7, true, true}, {"visible", 2, 7, false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			var current sendWire
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer access-not-persisted" {
					t.Error("owner bearer")
				}
				switch {
				case r.URL.Path == "/api/sync":
					json.NewEncoder(w).Encode(policySyncFixture(tc.role, tc.kind, map[string]any{"disableHideEmail": true}))
				case r.Method == "GET":
					json.NewEncoder(w).Encode(current)
				case r.Method == "DELETE":
					writes++
					w.WriteHeader(204)
				default:
					writes++
					if e := json.NewDecoder(r.Body).Decode(&current); e != nil {
						t.Error(e)
					}
					current = sendTestReply(current)
					json.NewEncoder(w).Encode(current)
				}
			}))
			defer srv.Close()
			s, _ := resumableFixture(t, srv.URL)
			defer s.Close()
			v := sendTestVault(t, s)
			d, e := s.NewSend(v, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			d.Fields = sendTestFields()
			d.Fields.HideEmail = tc.hide
			next, e := s.SaveSend(context.Background(), d, nil, 0, nil)
			if tc.blocked {
				if !errors.Is(e, ErrPermission) || writes != 0 {
					t.Fatal("policy bypass", e, writes)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer next.Close()
			if next.Fields.Text != d.Fields.Text {
				t.Fatal("text")
			}
			link, e := next.ShareLink()
			if e != nil {
				t.Fatal(e)
			}
			id, seed, e := ParseSendLink(srv.URL, link)
			if e != nil || id != next.wire.AccessID || !bytes.Equal(seed, next.seed) {
				t.Fatal("share link", e)
			}
			if _, e = s.SaveSend(context.Background(), d, nil, 0, nil); !errors.Is(e, ErrExpired) {
				t.Fatal("consumed draft retry", e)
			}
			if e = s.DeleteSend(context.Background(), next, nil); e != nil || writes != 2 {
				t.Fatal("delete", e, writes)
			}
		})
	}
}
func TestSendStalePendingUnknownAndSnapshot(t *testing.T) {
	var writes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" {
			json.NewEncoder(w).Encode(emptyPolicySyncFixture())
			return
		}
		writes.Add(1)
		w.WriteHeader(500)
		w.Write([]byte("secret-error-token"))
	}))
	defer srv.Close()
	s, _ := resumableFixture(t, srv.URL)
	defer s.Close()
	v := sendTestVault(t, s)
	newDraft := func() *SendDraft {
		d, e := s.NewSend(v, 0)
		if e != nil {
			t.Fatal(e)
		}
		d.Fields = sendTestFields()
		t.Cleanup(d.Close)
		return d
	}
	d := newDraft()
	s.pendingPolicyMutations = []PendingPolicyMutation{{PolicyType: 6}}
	if _, e := s.SaveSend(context.Background(), d, nil, 0, nil); !errors.Is(e, ErrPermission) || writes.Load() != 0 {
		t.Fatal(e)
	}
	s.pendingPolicyMutations = nil
	d.epoch--
	if _, e := s.SaveSend(context.Background(), d, nil, 0, nil); !errors.Is(e, ErrExpired) || writes.Load() != 0 {
		t.Fatal(e)
	}
	d = newDraft()
	_, e := s.SaveSend(context.Background(), d, nil, 0, nil)
	var uncertain *MutationUncertainError
	if !errors.As(e, &uncertain) || writes.Load() != 1 || strings.Contains(e.Error(), "secret-error") {
		t.Fatal(e)
	}
	if _, e = s.SaveSend(context.Background(), d, nil, 0, nil); !errors.Is(e, ErrExpired) || writes.Load() != 1 {
		t.Fatal("unknown retry")
	}
	tampered := *v
	tampered.Sync = append([]byte(nil), v.Sync...)
	tampered.Sync = append(tampered.Sync, ' ')
	if _, e = s.Sends(&tampered); e == nil {
		t.Fatal("tampered offline")
	}
	d = newDraft()
	s.checkpointPending = true
	if _, e = s.SaveSend(context.Background(), d, nil, 0, func(SessionCheckpoint) error { return ErrCheckpoint }); !errors.Is(e, ErrCheckpoint) || writes.Load() != 1 {
		t.Fatal("checkpoint bypass", e)
	}
}
func TestSendLinksAndValidation(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 16)
	d := &SendDraft{scope: Scope{Server: "https://example.invalid/base"}, seed: seed, wire: sendWire{AccessID: sendAccessID("b6d98b09-e6b1-42b0-93f1-d7f77aab9543")}}
	link := d.scope.Server + "/#/send/" + d.wire.AccessID + "/" + base64.RawURLEncoding.EncodeToString(seed)
	for _, bad := range []string{strings.Replace(link, "example.invalid", "evil.invalid", 1), link + "/x", strings.Replace(link, "/#/", "/?token=bad#/", 1), strings.Replace(link, "https://", "https://u:p@", 1)} {
		if _, _, e := ParseSendLink(d.scope.Server, bad); e == nil {
			t.Fatal("bad link")
		}
	}
	for _, mutate := range []func(*SendFields){func(f *SendFields) { f.DeletionDate = time.Now().Add(32 * 24 * time.Hour) }, func(f *SendFields) { n := 0; f.MaxAccessCount = &n }, func(f *SendFields) { f.Type = 2 }, func(f *SendFields) { p := ""; f.Password = &p }} {
		f := sendTestFields()
		mutate(&f)
		if validateSendFields(f) == nil {
			t.Fatal("bad fields")
		}
	}
}
