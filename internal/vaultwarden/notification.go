// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

var notificationBinary = websocket.Codec{Unmarshal: func(data []byte, kind byte, output any) error {
	if kind != websocket.BinaryFrame {
		return ErrProtocol
	}
	p, ok := output.(*[]byte)
	if !ok {
		return ErrProtocol
	}
	*p = data
	return nil
}}

// NotificationStream owns one goroutine and its current socket. Stop cancels
// immediately (safe inside callback); Wait joins. Callbacks run serially, must
// honor ctx, and must never publish without the application's current lease.
type NotificationStream struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	err    error // published by closing done
}

func (n *NotificationStream) Stop() { n.once.Do(n.cancel) }
func (n *NotificationStream) Wait() { <-n.done }

// Err returns the terminal error after Wait; nil while the stream is running.
func (n *NotificationStream) Err() error {
	select {
	case <-n.done:
		return n.err
	default:
		return nil
	}
}

type NotificationCallback func(context.Context, NotificationEvent) error

// StartNotifications does not install UI state or mutate the vault. Always Stop
// before lock/logout/account replacement, cancel the parent lifecycle context,
// and discard stale callback results. Session.Close also closes active sockets.
func (s *Session) StartNotifications(ctx context.Context, scope Scope, persist func(SessionCheckpoint) error, callback NotificationCallback) (*NotificationStream, error) {
	if callback == nil {
		return nil, ErrValidation
	}
	s.mu.Lock()
	err := s.requireScopeLocked(scope)
	if !s.itemSessionActiveLocked() {
		err = ErrExpired
	}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	prepare := func(ctx context.Context) (string, func() bool, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		ctx, finish, e := s.beginOperationLocked(ctx)
		if e != nil {
			return "", nil, e
		}
		defer finish()
		if e = s.requireScopeLocked(scope); e != nil {
			return "", nil, e
		}
		if e = s.prepareAuthenticatedDispatchLocked(ctx, false, persist, nil); e != nil {
			return "", nil, e
		}
		token := s.access
		valid := func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.itemSessionActiveLocked() && s.access == token && time.Now().Before(s.expires) && s.account == scope.Account
		}
		return token, valid, nil
	}
	deliver := func(ctx context.Context, event NotificationEvent) error {
		if event.Kind == NotificationLogout {
			s.Close()
		}
		return callback(ctx, event)
	}
	return startNotificationStream(ctx, s.client, scope, "", prepare, deliver), nil
}

// StartNotifications on a pending request subscribes directly to anonymous-hub
// using the request UUID (NOT accessCode). expected binds the known account;
// the anonymous signal only triggers Poll and is never evidence of approval.
func (p *PendingAuthRequest) StartNotifications(ctx context.Context, expected Scope, callback NotificationCallback) (*NotificationStream, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.private == nil || callback == nil || expected.Server != p.client.base.String() || expected.Account == "" {
		return nil, ErrIdentity
	}
	id := p.id
	valid := func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.private != nil && time.Now().Before(p.expires) && p.ctx.Err() == nil
	}
	prepare := func(context.Context) (string, func() bool, error) {
		if !valid() {
			return "", nil, ErrExpired
		}
		return "", valid, nil
	}
	return startNotificationStream(ctx, p.client, expected, id, prepare, callback), nil
}

type notificationPrepare func(context.Context) (string, func() bool, error)

func startNotificationStream(parent context.Context, c *Client, scope Scope, anonymous string, prepare notificationPrepare, callback NotificationCallback) *NotificationStream {
	ctx, cancel := context.WithCancel(parent)
	n := &NotificationStream{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer func() {
			if ctx.Err() != nil && n.err == nil {
				n.err = ErrCancelled
			}
			cancel()
			close(n.done)
		}()
		deliver := func(ctx context.Context, event NotificationEvent) error {
			err := callback(ctx, event)
			if err != nil {
				n.err = err
				cancel()
			}
			return err
		}
		attempt := 0
		for ctx.Err() == nil {
			token, valid, err := prepare(ctx)
			if err != nil {
				n.err = err
				return
			}
			// Recovery sync/poll also happens before a failed dial, covering missed
			// notifications when a server has websockets disabled or is unreachable.
			kind := NotificationSync
			if anonymous != "" {
				kind = NotificationAuthResponse
			}
			if !valid() {
				n.err = ErrExpired
				return
			}
			if err = deliver(ctx, NotificationEvent{Kind: kind, Scope: scope, RequestID: anonymous, Reconnected: true}); err != nil {
				return
			}
			if ctx.Err() != nil {
				return
			}
			err = c.notificationConnection(ctx, scope, anonymous, token, valid, deliver)
			if err == nil || ctx.Err() != nil {
				return
			}
			if attempt < 5 {
				attempt++
			}
			delay := time.Second * time.Duration(1<<attempt)
			var jitter [1]byte
			_, _ = rand.Read(jitter[:])
			delay = delay/2 + time.Duration(jitter[0])*delay/512
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return n
}
func (c *Client) notificationConnection(ctx context.Context, scope Scope, anonymous, token string, valid func() bool, callback NotificationCallback) error {
	u := *c.base
	u.Scheme = "wss"
	if c.base.Scheme == "http" {
		u.Scheme = "ws"
	}
	u.Path += "/notifications/hub"
	if anonymous != "" {
		u.Path = c.base.Path + "/notifications/anonymous-hub"
		u.RawQuery = url.Values{"token": {anonymous}}.Encode()
	}
	cfg, err := websocket.NewConfig(u.String(), c.base.String())
	if err != nil {
		return ErrProtocol
	}
	cfg.TlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	cfg.Header = http.Header{}
	if token != "" {
		cfg.Header.Set("Authorization", "Bearer "+token)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	ws, err := cfg.DialContext(dialCtx)
	cancel()
	if err != nil {
		return ErrNetwork
	}
	defer ws.Close()
	ws.MaxPayloadBytes = notificationLimit
	alive, stop := context.WithCancel(ctx)
	defer stop()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()
		for {
			select {
			case <-alive.Done():
				ws.Close()
				return
			case <-tick.C:
				if !valid() {
					ws.Close()
					return
				}
			case <-heartbeat.C:
				ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if websocket.Message.Send(ws, []byte{2, 0x91, 6}) != nil {
					ws.Close()
					return
				}
			}
		}
	}()
	defer func() { stop(); ws.Close(); <-watchDone }()
	ws.SetDeadline(time.Now().Add(10 * time.Second))
	if websocket.Message.Send(ws, "{\"protocol\":\"messagepack\",\"version\":1}\x1e") != nil {
		return ErrNetwork
	}
	var data []byte
	if websocket.Message.Receive(ws, &data) != nil || string(data) != "{}\x1e" {
		return ErrProtocol
	}
	ws.SetDeadline(time.Time{})
	// Subscribe before the second recovery read, closing the read/dial race.
	kind := NotificationSync
	if anonymous != "" {
		kind = NotificationAuthResponse
	}
	if ctx.Err() != nil || !valid() {
		return ErrExpired
	}
	if err = callback(ctx, NotificationEvent{Kind: kind, Scope: scope, RequestID: anonymous, Reconnected: true}); err != nil {
		return err
	}
	var pending []byte
	for {
		ws.SetReadDeadline(time.Now().Add(45 * time.Second))
		data = nil
		if notificationBinary.Receive(ws, &data) != nil {
			return ErrNetwork
		}
		if len(pending)+len(data) > notificationLimit+5 {
			return ErrProtocol
		}
		pending = append(pending, data...)
		for len(pending) > 0 {
			frame, rest, e := notificationFrame(pending)
			if e != nil {
				return e
			}
			if frame == nil {
				break
			}
			event, e := decodeNotification(frame, scope, anonymous)
			if e != nil {
				return e
			}
			event.markOrigin(c.deviceID)
			pending = rest
			if ctx.Err() != nil || !valid() {
				return ErrExpired
			}
			if event.Kind != 0 {
				if e = callback(ctx, event); e != nil {
					return e
				}
				if event.Kind == NotificationLogout {
					return nil
				}
			}
		}
	}
}
