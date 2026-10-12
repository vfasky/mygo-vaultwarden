// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

const notificationLimit = 64 * 1024

// A deliberately bounded MessagePack reader for the 1.37.4 notification schema.
// Unknown tags fail closed; timestamp extensions are opaque and never trusted.
type notificationDecoder struct {
	b     []byte
	nodes int
}

func (d *notificationDecoder) take(n int) ([]byte, error) {
	if n < 0 || n > len(d.b) {
		return nil, ErrProtocol
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v, nil
}
func (d *notificationDecoder) number(n int) (int, error) {
	b, e := d.take(n)
	if e != nil {
		return 0, e
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	if v > notificationLimit {
		return 0, ErrProtocol
	}
	return int(v), nil
}
func (d *notificationDecoder) value(depth int) (any, error) {
	d.nodes++
	if depth > 12 || d.nodes > 4096 {
		return nil, ErrProtocol
	}
	b, e := d.take(1)
	if e != nil {
		return nil, e
	}
	tag := b[0]
	var count int
	kind := byte(0)
	switch {
	case tag <= 0x7f:
		return int(tag), nil
	case tag >= 0xe0:
		return int(int8(tag)), nil
	case tag >= 0xa0 && tag <= 0xbf:
		count = int(tag & 31)
		kind = 's'
	case tag >= 0x90 && tag <= 0x9f:
		count = int(tag & 15)
		kind = 'a'
	case tag >= 0x80 && tag <= 0x8f:
		count = int(tag & 15)
		kind = 'm'
	default:
		switch tag {
		case 0xc0:
			return nil, nil
		case 0xc2:
			return false, nil
		case 0xc3:
			return true, nil
		case 0xcc, 0xcd, 0xce:
			n := 1 << uint(tag-0xcc)
			return d.number(n)
		case 0xd0, 0xd1, 0xd2:
			n := 1 << uint(tag-0xd0)
			v, e := d.take(n)
			if e != nil {
				return nil, e
			}
			if n == 1 {
				return int(int8(v[0])), nil
			}
			if n == 2 {
				return int(int16(binary.BigEndian.Uint16(v))), nil
			}
			return int(int32(binary.BigEndian.Uint32(v))), nil
		case 0xd9, 0xda, 0xdb:
			count, e = d.number(1 << uint(tag-0xd9))
			kind = 's'
		case 0xdc, 0xdd:
			count, e = d.number(2 << uint(tag-0xdc))
			kind = 'a'
		case 0xde, 0xdf:
			count, e = d.number(2 << uint(tag-0xde))
			kind = 'm'
		case 0xc4, 0xc5, 0xc6:
			count, e = d.number(1 << uint(tag-0xc4))
			kind = 'b'
		case 0xd6, 0xd7:
			count = 1 + (4 << uint(tag-0xd6))
			kind = 'b'
		case 0xc7:
			count, e = d.number(1)
			count++
			kind = 'b'
		default:
			return nil, ErrProtocol
		}
	}
	if e != nil {
		return nil, e
	}
	switch kind {
	case 's', 'b':
		v, e := d.take(count)
		if e != nil {
			return nil, e
		}
		if kind == 'b' {
			return nil, nil
		}
		if !utf8.Valid(v) {
			return nil, ErrProtocol
		}
		return string(v), nil
	case 'a':
		if count > 4096 {
			return nil, ErrProtocol
		}
		v := make([]any, count)
		for i := range v {
			v[i], e = d.value(depth + 1)
			if e != nil {
				return nil, e
			}
		}
		return v, nil
	case 'm':
		if count > 2048 {
			return nil, ErrProtocol
		}
		v := make(map[string]any, count)
		for i := 0; i < count; i++ {
			k, e := d.value(depth + 1)
			if e != nil {
				return nil, e
			}
			s, ok := k.(string)
			if !ok {
				return nil, ErrProtocol
			}
			if _, ok = v[s]; ok {
				return nil, ErrProtocol
			}
			value, e := d.value(depth + 1)
			if e != nil {
				return nil, e
			}
			v[s] = value
		}
		return v, nil
	}
	return nil, ErrProtocol
}

// notificationFrame extracts SignalR's little-endian 7-bit length, not a
// MessagePack length. It supports concatenated and split transport messages.
func notificationFrame(b []byte) (frame, rest []byte, err error) {
	n := 0
	for i := 0; i < 5; i++ {
		if i >= len(b) {
			return nil, b, nil
		}
		c := b[i]
		if i == 4 && c > 7 {
			return nil, nil, ErrProtocol
		}
		n |= int(c&127) << (7 * i)
		if n > notificationLimit {
			return nil, nil, ErrProtocol
		}
		if c&128 == 0 {
			if n == 0 || i > 0 && c == 0 {
				return nil, nil, ErrProtocol
			}
			if len(b)-i-1 < n {
				return nil, b, nil
			}
			return b[i+1 : i+1+n], b[i+1+n:], nil
		}
	}
	return nil, nil, ErrProtocol
}

type NotificationKind int

const (
	NotificationSync NotificationKind = iota + 1
	NotificationLogout
	NotificationAuthRequest
	NotificationAuthResponse
)

// NotificationEvent contains no vault payload. Scope is the connection's bound
// identity. Consumers must recheck their own current lifecycle lease when
// committing a sync, displaying a result or logging out.
type NotificationEvent struct {
	Kind        NotificationKind
	Scope       Scope
	RequestID   string
	Reconnected bool
	// FromThisDevice marks a sync hint whose ContextId names this client's own
	// device identifier: the echo of a change this device already submitted.
	// It is a hint only and never authorizes or replaces a sync on its own.
	FromThisDevice bool
	contextID      string
}

func decodeNotification(frame []byte, scope Scope, anonymousID string) (NotificationEvent, error) {
	event := NotificationEvent{Scope: scope}
	d := notificationDecoder{b: frame}
	v, e := d.value(0)
	if e != nil || len(d.b) != 0 {
		return event, ErrProtocol
	}
	a, ok := v.([]any)
	if !ok || len(a) == 0 {
		return event, ErrProtocol
	}
	typ, ok := a[0].(int)
	if !ok {
		return event, ErrProtocol
	}
	if typ == 6 && len(a) == 1 {
		return event, nil
	}
	if typ == 7 {
		return event, ErrNetwork
	}
	if typ != 1 || len(a) != 5 {
		return event, ErrProtocol
	}
	if _, ok := a[1].(map[string]any); !ok || a[2] != nil {
		return event, ErrProtocol
	}
	target, ok := a[3].(string)
	if !ok {
		return event, ErrProtocol
	}
	if anonymousID == "" && target != "ReceiveMessage" || anonymousID != "" && target != "AuthRequestResponseRecieved" {
		return event, ErrProtocol
	}
	args, ok := a[4].([]any)
	if !ok || len(args) != 1 {
		return event, ErrProtocol
	}
	m, ok := args[0].(map[string]any)
	if !ok {
		return event, ErrProtocol
	}
	t, ok := m["Type"].(int)
	if !ok {
		return event, ErrProtocol
	}
	payload, ok := m["Payload"].(map[string]any)
	if !ok {
		return event, ErrProtocol
	}
	// Absent, null or non-string ContextId simply means "unknown origin".
	if context, ok := m["ContextId"].(string); ok && len(context) <= 128 {
		event.contextID = context
	}
	if user, exists := payload["UserId"]; exists && user != nil && user != scope.Account {
		return event, ErrIdentity
	}
	if anonymousID != "" {
		if t != 16 || payload["Id"] != anonymousID || m["UserId"] != scope.Account {
			return event, ErrIdentity
		}
	}
	switch t {
	case 11:
		if payload["UserId"] != scope.Account {
			return event, ErrIdentity
		}
		event.Kind = NotificationLogout
	case 15, 16:
		event.RequestID, ok = payload["Id"].(string)
		if !ok || !validAuthID(event.RequestID) {
			return event, ErrProtocol
		}
		if t == 15 {
			event.Kind = NotificationAuthRequest
		} else {
			event.Kind = NotificationAuthResponse
		}
	default:
		event.Kind = NotificationSync
	}
	return event, nil
}

// markOrigin compares the decoded ContextId with this client's device
// identifier and then drops the raw value from the event.
func (e *NotificationEvent) markOrigin(deviceID string) {
	e.FromThisDevice = e.Kind == NotificationSync && e.contextID != "" && deviceID != "" && strings.EqualFold(e.contextID, deviceID)
	e.contextID = ""
}
