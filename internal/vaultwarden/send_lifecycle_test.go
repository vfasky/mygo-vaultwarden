// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendRefreshCheckpointRevokesDraft(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "persisted", true: "failed"}[fail], func(t *testing.T) {
			var writes, syncs, checkpoints atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/identity/connect/token":
					json.NewEncoder(w).Encode(map[string]any{"access_token": "refreshed-access", "refresh_token": "refreshed-refresh", "expires_in": 3600, "token_type": "Bearer"})
				case "/api/sync":
					syncs.Add(1)
					if checkpoints.Load() != 1 {
						t.Error("read before durable checkpoint")
					}
					json.NewEncoder(w).Encode(emptyPolicySyncFixture())
				default:
					writes.Add(1)
					w.WriteHeader(500)
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
			s.expires = time.Now().Add(-time.Second)
			_, e = s.SaveSend(context.Background(), d, nil, 0, func(cp SessionCheckpoint) error {
				checkpoints.Add(1)
				if len(cp.Session) == 0 || cp.Scope != v.Scope {
					t.Error("checkpoint identity")
				}
				if fail {
					return ErrCheckpoint
				}
				return nil
			})
			expected := ErrExpired
			if fail {
				expected = ErrCheckpoint
			}
			if !errors.Is(e, expected) || writes.Load() != 0 || checkpoints.Load() != 1 || (fail && syncs.Load() != 0) {
				t.Fatal("refresh/checkpoint guard", e, writes.Load(), syncs.Load())
			}
		})
	}
}
func TestSendCloseCancelsMutationAndShare(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var writes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/sync" {
			json.NewEncoder(w).Encode(emptyPolicySyncFixture())
			return
		}
		writes.Add(1)
		close(started)
		<-release
		w.WriteHeader(500)
	}))
	defer srv.Close()
	s, _ := resumableFixture(t, srv.URL)
	v := sendTestVault(t, s)
	d, e := s.NewSend(v, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	d.Fields = sendTestFields()
	result := make(chan error, 1)
	go func() { _, e := s.SaveSend(context.Background(), d, nil, 0, nil); result <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	s.Close()
	close(release)
	select {
	case e := <-result:
		var unknown *MutationUncertainError
		if !errors.As(e, &unknown) || writes.Load() != 1 {
			t.Fatal("close result", e)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not cancel")
	}
	if _, e = d.ShareLink(); !errors.Is(e, ErrExpired) {
		t.Fatal("closed session share", e)
	}
}
func TestSendFileStagePolicyAndReceiptGuards(t *testing.T) {
	for _, mode := range []string{"policy", "wrong-url", "azure", "wrong-size"} {
		t.Run(mode, func(t *testing.T) {
			syncs, uploads := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/sync":
					syncs++
					if syncs > 1 && mode == "policy" {
						json.NewEncoder(w).Encode(policySyncFixture(2, 6, nil))
					} else {
						json.NewEncoder(w).Encode(emptyPolicySyncFixture())
					}
				case "/api/sends/file/v2":
					var input sendWire
					json.NewDecoder(r.Body).Decode(&input)
					result := sendTestReply(input)
					result.File.ID = "file-id"
					result.File.Size = sendSize(*input.FileLength)
					if mode == "wrong-size" {
						result.File.Size = "999"
					}
					result.FileLength = nil
					kind := 0
					url := "/sends/" + result.ID + "/file/file-id"
					if mode == "wrong-url" {
						url = "https://evil.invalid/owner-token"
					}
					if mode == "azure" {
						kind = 1
					}
					json.NewEncoder(w).Encode(map[string]any{"fileUploadType": kind, "url": url, "sendResponse": result})
				default:
					uploads++
					w.WriteHeader(200)
				}
			}))
			defer srv.Close()
			s, _ := resumableFixture(t, srv.URL)
			defer s.Close()
			v := sendTestVault(t, s)
			d, e := s.NewSend(v, 1)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			d.Fields = sendTestFields()
			d.Fields.Type = 1
			d.Fields.FileName = "private.txt"
			next, e := s.SaveSend(context.Background(), d, strings.NewReader("abc"), 3, nil)
			if e == nil || next != nil || uploads != 0 {
				t.Fatal("unverified metadata uploaded", e, uploads)
			}
			if mode == "policy" {
				var partial *SendUploadError
				if !errors.As(e, &partial) || !errors.Is(e, ErrPermission) {
					t.Fatal("stage policy", e)
				}
			}
		})
	}
}
func TestSendOfflineDraftCloneAndLock(t *testing.T) {
	s, _ := resumableFixture(t, "https://example.invalid")
	v := sendTestVault(t, s)
	d, e := s.NewSend(v, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	f := sendTestFields()
	n := 5
	f.MaxAccessCount = &n
	w, e := encryptSend(f, d.seed, s.key)
	if e != nil {
		t.Fatal(e)
	}
	w = sendTestReply(w)
	var data map[string]any
	json.Unmarshal(v.Sync, &data)
	data["sends"] = []sendWire{w}
	v.Sync, _ = json.Marshal(data)
	installFixtureSnapshot(t, s, v, "next")
	rows, e := s.Sends(v)
	if e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	defer rows[0].Close()
	*rows[0].Fields.MaxAccessCount = 17
	if *rows[0].wire.MaxAccessCount != 5 {
		t.Fatal("editable pointer aliased authoritative wire")
	}
	if _, e = rows[0].ShareLink(); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if _, e = rows[0].ShareLink(); !errors.Is(e, ErrExpired) {
		t.Fatal("old snapshot shares after lock", e)
	}
}
