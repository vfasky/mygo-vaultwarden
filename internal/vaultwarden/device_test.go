// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeviceScopeConfirmAndCancellation(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer access-not-persisted" {
			t.Error("missing bearer")
		}
		switch {
		case r.URL.Path == "/api/devices":
			fmt.Fprint(w, `{"data":[{"id":"one","identifier":"fixture","name":"device"}],"continuationToken":null}`)
		case strings.HasSuffix(r.URL.Path, "/clear-token"):
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/token"):
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			if v["pushToken"] != "fixture-push" {
				t.Error("push body")
			}
			w.WriteHeader(204)
		default:
			fmt.Fprint(w, `{"id":"one","identifier":"fixture"}`)
		}
	}))
	defer srv.Close()
	s, _ := resumableFixture(t, srv.URL)
	defer s.Close()
	scope := Scope{Server: srv.URL, Account: s.account}
	ctx := context.Background()
	if _, e := s.Devices(ctx, Scope{Server: srv.URL, Account: "foreign"}, nil); e == nil {
		t.Fatal("foreign scope")
	}
	if e := s.ClearDevicePushToken(ctx, scope, false, nil); e != ErrPermission {
		t.Fatal("missing confirmation")
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized HTTP")
	}
	if d, e := s.Devices(ctx, scope, nil); e != nil || len(d) != 1 {
		t.Fatal(d, e)
	}
	if _, e := s.CurrentDevice(ctx, scope, nil); e != nil {
		t.Fatal(e)
	}
	if e := s.RegisterDevicePushToken(ctx, scope, "fixture-push", nil); e != nil {
		t.Fatal(e)
	}
	if e := s.ClearDevicePushToken(ctx, scope, true, nil); e != nil {
		t.Fatal(e)
	}
	if s.closed || s.access == "" {
		t.Fatal("clearing push revoked session")
	}
	s.Close()
	count := calls.Load()
	if _, e := s.Devices(ctx, scope, nil); e == nil || calls.Load() != count {
		t.Fatal("closed request")
	}
}
func TestAuthRequestApprovalTrustAndOneShotKey(t *testing.T) {
	const id = "b6d98b09-e6b1-42b0-93f1-d7f77aab9543"
	var mu sync.Mutex
	var row authRequestWire
	var code string
	var writes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "POST":
			var v struct{ PublicKey, AccessCode string }
			json.NewDecoder(r.Body).Decode(&v)
			row = authRequestWire{AuthRequest: AuthRequest{ID: id, PublicKey: v.PublicKey}}
			code = v.AccessCode
			json.NewEncoder(w).Encode(row)
		case r.Method == "PUT":
			writes.Add(1)
			var v struct {
				Key              string
				RequestApproved  bool
				DeviceIdentifier string
			}
			json.NewDecoder(r.Body).Decode(&v)
			if v.DeviceIdentifier == "" {
				t.Error("missing device")
			}
			date := "2026-01-01T00:00:00Z"
			row.Key = &v.Key
			row.RequestApproved = &v.RequestApproved
			row.ResponseDate = &date
			json.NewEncoder(w).Encode(row)
		default:
			if strings.HasSuffix(r.URL.Path, "/response") && r.URL.Query().Get("code") != code {
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(row)
		}
	}))
	defer srv.Close()
	s, _ := resumableFixture(t, srv.URL)
	defer s.Close()
	vault := sendTestVault(t, s)
	ctx := context.Background()
	pending, metadata, e := s.client.BeginAuthRequest(ctx, "fixture@example.invalid")
	if e != nil {
		t.Fatal(e)
	}
	defer pending.Close()
	if strings.Contains(fmt.Sprintf("%#v", pending), code) {
		t.Fatal("secret diagnostic")
	}
	if _, e = pending.TakeUserKey(ctx); e != ErrPermission {
		t.Fatal("unapproved key", e)
	}
	if e = s.RespondAuthRequest(ctx, vault, id, metadata.PublicKey, true, false, nil); e != ErrPermission {
		t.Fatal("confirmation bypass", e)
	}
	if e = s.RespondAuthRequest(ctx, vault, id, "untrusted", true, true, nil); e != ErrIdentity {
		t.Fatal("trust bypass", e)
	}
	if writes.Load() != 0 {
		t.Fatal("unconfirmed write")
	}
	if e = s.RespondAuthRequest(ctx, vault, id, metadata.PublicKey, true, true, nil); e != nil {
		t.Fatal(e)
	}
	key, e := pending.TakeUserKey(ctx)
	if e != nil || !bytes.Equal(key, s.key) {
		t.Fatal("RSA wrapped key", e)
	}
	clear(key)
	if _, e = pending.TakeUserKey(ctx); e != ErrExpired {
		t.Fatal("key replay", e)
	}
	if e = s.RespondAuthRequest(ctx, vault, id, metadata.PublicKey, true, true, nil); e != ErrConflict {
		t.Fatal("double approval", e)
	}
	if writes.Load() != 1 {
		t.Fatal("mutation repeated")
	}
}
func TestAuthRequestCloseCancelsPoll(t *testing.T) {
	const id = "b6d98b09-e6b1-42b0-93f1-d7f77aab9543"
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var body struct{ PublicKey string }
			json.NewDecoder(r.Body).Decode(&body)
			json.NewEncoder(w).Encode(AuthRequest{ID: id, PublicKey: body.PublicKey})
			return
		}
		close(entered)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "fixture-device-identifier")
	p, _, e := c.BeginAuthRequest(context.Background(), "fixture@example.invalid")
	if e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { _, e := p.Poll(context.Background()); result <- e }()
	<-entered
	p.Close()
	select {
	case e := <-result:
		if !errors.Is(e, ErrCancelled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("poll not cancelled")
	}
	<-cancelled
}
func TestDeviceCloseCancelsRequest(t *testing.T) {
	entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer srv.Close()
	s, _ := resumableFixture(t, srv.URL)
	result := make(chan error, 1)
	go func() {
		_, e := s.Devices(context.Background(), Scope{Server: srv.URL, Account: s.account}, nil)
		result <- e
	}()
	<-entered
	s.Close()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("late success")
		}
	case <-time.After(time.Second):
		t.Fatal("close blocked")
	}
}
