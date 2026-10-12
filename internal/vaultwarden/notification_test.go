// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// Test-only independent writer; production never emits notification payloads.
func notificationPack(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte{0xc0}
	case int:
		if x < 128 {
			return []byte{byte(x)}
		}
		return []byte{0xcd, byte(x >> 8), byte(x)}
	case string:
		b := []byte(x)
		if len(b) < 32 {
			return append([]byte{0xa0 | byte(len(b))}, b...)
		}
		return append([]byte{0xd9, byte(len(b))}, b...)
	case []any:
		b := []byte{0x90 | byte(len(x))}
		for _, e := range x {
			b = append(b, notificationPack(e)...)
		}
		return b
	case map[string]any:
		b := []byte{0x80 | byte(len(x))}
		for k, v := range x {
			b = append(b, notificationPack(k)...)
			b = append(b, notificationPack(v)...)
		}
		return b
	}
	panic("fixture type")
}
func notificationVector(t int, user, id, target string) []byte {
	m := map[string]any{"Type": t, "Payload": map[string]any{"UserId": user, "Id": id}}
	if target != "ReceiveMessage" {
		m["UserId"] = user
	} else {
		m["ContextId"] = nil
	}
	b := notificationPack([]any{1, map[string]any{}, nil, target, []any{m}})
	prefix := make([]byte, 5)
	n := binary.PutUvarint(prefix, uint64(len(b)))
	return append(prefix[:n], b...)
}
func TestNotificationProtocolBoundsAndVectors(t *testing.T) {
	scope := Scope{Server: "http://127.0.0.1", Account: "account"}
	id := "b6d98b09-e6b1-42b0-93f1-d7f77aab9543"
	for _, tc := range []struct {
		typ  int
		kind NotificationKind
	}{{0, NotificationSync}, {5, NotificationSync}, {11, NotificationLogout}, {15, NotificationAuthRequest}, {16, NotificationAuthResponse}} {
		b := notificationVector(tc.typ, scope.Account, id, "ReceiveMessage")
		for cut := 0; cut < len(b); cut++ {
			frame, _, e := notificationFrame(b[:cut])
			if e != nil || frame != nil {
				t.Fatalf("split %d: %v", cut, e)
			}
		}
		frame, rest, e := notificationFrame(append(append([]byte{}, b...), b...))
		if e != nil || !reflect.DeepEqual(rest, b) {
			t.Fatal("concatenated", e)
		}
		event, e := decodeNotification(frame, scope, "")
		if e != nil || event.Kind != tc.kind {
			t.Fatal(event, e)
		}
		if _, e = decodeNotification(frame, Scope{Account: "other"}, ""); !errors.Is(e, ErrIdentity) {
			t.Fatal("cross-account accepted", e)
		}
	}
	b := notificationVector(16, scope.Account, id, "AuthRequestResponseRecieved")
	f, _, _ := notificationFrame(b)
	if e, err := decodeNotification(f, scope, id); err != nil || e.Kind != NotificationAuthResponse {
		t.Fatal(e, err)
	}
	if _, e := decodeNotification(f, scope, "00000000-0000-0000-0000-000000000000"); e == nil {
		t.Fatal("foreign request accepted")
	}
	for _, bad := range [][]byte{{0}, {0x80, 0}, {0xff, 0xff, 0xff, 0xff, 0x08}, {0x81, 0x80, 0x04}} {
		if _, _, e := notificationFrame(bad); e == nil {
			t.Fatalf("bad length %x", bad)
		}
	}
	for _, bad := range [][]byte{{0xc1}, {0x91}, {0x91, 0x06, 0}, {0xdd, 0, 1, 0, 1}, {0x82, 0xa1, 'x', 0xc0, 0xa1, 'x', 0xc0}, {0xdb, 0xff, 0xff, 0xff, 0xff}} {
		if _, e := decodeNotification(bad, scope, ""); e == nil {
			t.Fatalf("bad pack %x", bad)
		}
	}
	deep := make([]byte, 20)
	for i := range deep {
		deep[i] = 0x91
	}
	if _, e := decodeNotification(deep, scope, ""); e == nil {
		t.Fatal("depth accepted")
	}
	if e, err := decodeNotification([]byte{0x91, 6}, scope, ""); err != nil || e.Kind != 0 {
		t.Fatal("ping", err)
	}
}
func TestNotificationReconnectLogoutAndClose(t *testing.T) {
	var connections atomic.Int32
	ready := make(chan struct{}, 4)
	release := make(chan struct{})
	var account string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/notifications/hub" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer access-not-persisted" {
			t.Error("wrong route/auth")
			w.WriteHeader(400)
			return
		}
		websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			var hello string
			if websocket.Message.Receive(ws, &hello) != nil || hello != "{\"protocol\":\"messagepack\",\"version\":1}\x1e" {
				t.Error("handshake")
				return
			}
			websocket.Message.Send(ws, []byte("{}\x1e"))
			number := connections.Add(1)
			ready <- struct{}{}
			if number == 1 {
				return
			}
			select {
			case <-release:
			case <-time.After(10 * time.Second):
				return
			}
			websocket.Message.Send(ws, notificationVector(11, account, "", "ReceiveMessage"))
			var b []byte
			websocket.Message.Receive(ws, &b)
		}).ServeHTTP(w, r)
	}))
	defer srv.Close()
	s, _ := resumableFixture(t, srv.URL)
	defer s.Close()
	account = s.account
	scope := Scope{Server: srv.URL, Account: account}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	events := make(chan NotificationEvent, 20)
	n, e := s.StartNotifications(ctx, scope, nil, func(ctx context.Context, event NotificationEvent) error { events <- event; return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer n.Stop()
	for i := 0; i < 2; i++ {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("no reconnect")
		}
	}
	close(release)
	seenLogout := false
	for !seenLogout {
		select {
		case event := <-events:
			seenLogout = event.Kind == NotificationLogout
		case <-ctx.Done():
			t.Fatal("no logout")
		}
	}
	select {
	case <-n.done:
	case <-ctx.Done():
		t.Fatal("stream did not terminate")
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if !closed {
		t.Fatal("server logout left session active")
	}
	if connections.Load() != 2 {
		t.Fatal("unexpected reconnection")
	}
}
func TestNotificationCancellationAndOldToken(t *testing.T) {
	ready := make(chan struct{}, 1)
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		var b []byte
		websocket.Message.Receive(ws, &b)
		websocket.Message.Send(ws, []byte("{}\x1e"))
		ready <- struct{}{}
		websocket.Message.Receive(ws, &b)
	}))
	defer srv.Close()
	s, _ := resumableFixture(t, srv.URL)
	scope := Scope{Server: srv.URL, Account: s.account}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	n, e := s.StartNotifications(ctx, scope, nil, func(context.Context, NotificationEvent) error { calls.Add(1); return nil })
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("no connection")
	}
	n.Stop()
	n.Wait()
	before := calls.Load()
	s.Close()
	if calls.Load() != before {
		t.Fatal("late callback")
	}
	if _, e = s.StartNotifications(ctx, scope, nil, func(context.Context, NotificationEvent) error { return nil }); e == nil {
		t.Fatal("closed session restarted")
	}
}
func FuzzNotificationDecoder(f *testing.F) {
	f.Add([]byte{2, 0x91, 6})
	f.Add(notificationVector(11, "account", "", "ReceiveMessage"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > notificationLimit+5 {
			return
		}
		frame, _, e := notificationFrame(b)
		if e == nil && frame != nil {
			decodeNotification(frame, Scope{Account: "account"}, "")
		}
	})
}

func TestNotificationOriginMarksOnlyOwnSyncHints(t *testing.T) {
	scope := Scope{Server: "http://127.0.0.1", Account: "account"}
	device := "4f0a2c1e-6b5d-4e3a-9c8b-7d6e5f4a3b21"
	frame := func(typ int, context any) []byte {
		m := map[string]any{"Type": typ, "Payload": map[string]any{"UserId": scope.Account, "Id": "b6d98b09-e6b1-42b0-93f1-d7f77aab9543"}, "ContextId": context}
		return notificationPack([]any{1, map[string]any{}, nil, "ReceiveMessage", []any{m}})
	}
	for _, tc := range []struct {
		name    string
		typ     int
		context any
		device  string
		own     bool
	}{
		{"own cipher update", 0, device, device, true},
		{"own echo case-insensitive", 5, "4F0A2C1E-6B5D-4E3A-9C8B-7D6E5F4A3B21", device, true},
		{"other device", 0, "00000000-0000-4000-8000-000000000000", device, false},
		{"unknown origin", 0, nil, device, false},
		{"non-string origin", 0, 7, device, false},
		{"empty device id", 0, "", "", false},
		{"logout is never skipped", 11, device, device, false},
		{"auth request is never skipped", 15, device, device, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event, err := decodeNotification(frame(tc.typ, tc.context), scope, "")
			if err != nil {
				t.Fatal(err)
			}
			event.markOrigin(tc.device)
			if event.FromThisDevice != tc.own || event.contextID != "" {
				t.Fatalf("origin %+v", event)
			}
		})
	}
}
