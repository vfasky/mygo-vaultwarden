// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestNotificationOldTokenDropsDelayedPayload(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		var hello []byte
		websocket.Message.Receive(ws, &hello)
		websocket.Message.Send(ws, []byte("{}\x1e"))
		<-release
		websocket.Message.Send(ws, notificationVector(5, "account", "", "ReceiveMessage"))
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "fixture-device-identifier")
	var current atomic.Bool
	current.Store(true)
	ready := make(chan struct{})
	done := make(chan error, 1)
	var deliveries atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		done <- c.notificationConnection(ctx, Scope{Server: srv.URL, Account: "account"}, "", "old-token", current.Load, func(_ context.Context, event NotificationEvent) error {
			if event.Reconnected {
				close(ready)
			} else {
				deliveries.Add(1)
			}
			return nil
		})
	}()
	<-ready
	current.Store(false)
	close(release)
	if e := <-done; !errors.Is(e, ErrExpired) {
		t.Fatal("late token", e)
	}
	if deliveries.Load() != 0 {
		t.Fatal("old token payload delivered")
	}
}
func TestNotificationTransportRejectsTextAndOversize(t *testing.T) {
	for _, mode := range []string{"text", "oversize", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
				defer ws.Close()
				var hello []byte
				websocket.Message.Receive(ws, &hello)
				websocket.Message.Send(ws, []byte("{}\x1e"))
				switch mode {
				case "text":
					websocket.Message.Send(ws, string(notificationVector(5, "account", "", "ReceiveMessage")))
				case "oversize":
					websocket.Message.Send(ws, make([]byte, notificationLimit+1))
				case "malformed":
					websocket.Message.Send(ws, []byte{1, 0xc1})
				}
			}))
			defer srv.Close()
			c, _ := NewClient(srv.URL, "fixture-device-identifier")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			delivered := 0
			e := c.notificationConnection(ctx, Scope{Server: srv.URL, Account: "account"}, "", "token", func() bool { return true }, func(_ context.Context, event NotificationEvent) error {
				if !event.Reconnected {
					delivered++
				}
				return nil
			})
			if e == nil || delivered != 0 {
				t.Fatal("invalid transport delivered", e, delivered)
			}
		})
	}
}
func TestNotificationSplitDuplicateAndOutOfOrderHints(t *testing.T) {
	b1 := notificationVector(1, "account", "", "ReceiveMessage")
	b2 := notificationVector(2, "account", "", "ReceiveMessage")
	all := append(append(append([]byte{}, b2...), b1...), b2...)
	srv := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		var hello []byte
		websocket.Message.Receive(ws, &hello)
		websocket.Message.Send(ws, []byte("{}\x1e"))
		for _, piece := range [][]byte{all[:3], all[3:17], all[17:]} {
			websocket.Message.Send(ws, piece)
		}
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "fixture-device-identifier")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	count := 0
	c.notificationConnection(ctx, Scope{Server: srv.URL, Account: "account"}, "", "token", func() bool { return true }, func(_ context.Context, event NotificationEvent) error {
		if !event.Reconnected {
			if event.Kind != NotificationSync || event.RequestID != "" {
				t.Error("payload treated as state")
			}
			count++
		}
		return nil
	})
	if count != 3 {
		t.Fatal("lost split/duplicate hints", count)
	}
}
