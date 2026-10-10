// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"strings"
	"testing"
	"time"
)

func sendRotationFixture(t *testing.T) (AccountRotationInput, []json.RawMessage) {
	t.Helper()
	in := AccountRotationInput{Scope: Scope{"http://127.0.0.1:12345", fixtureUUID()}, OldUserKey: bytes.Repeat([]byte{23}, 64), NewUserKey: bytes.Repeat([]byte{42}, 64)}
	t.Cleanup(func() { clear(in.OldUserKey); clear(in.NewUserKey) })
	rows := []json.RawMessage{}
	for kind := 0; kind < 2; kind++ {
		seed := bytes.Repeat([]byte{byte(kind + 1)}, 16)
		fields := sendTestFields()
		fields.Type = kind
		fields.FileName = "fixture.bin"
		w, err := encryptSend(fields, seed, in.OldUserKey)
		clear(seed)
		if err != nil {
			t.Fatal(err)
		}
		w.ID = fixtureUUID()
		w.AccessID = sendAccessID(w.ID)
		w.RevisionDate = time.Now().UTC().Format(time.RFC3339Nano)
		w.AuthType = 2
		w.AccessCount = 2
		limit := 7
		w.MaxAccessCount = &limit
		w.HideEmail = true
		w.Disabled = true
		past := time.Now().Add(-time.Hour)
		w.ExpirationDate = &past
		if kind == 1 {
			hash := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			w.Password = &hash
			w.AuthType = 1
			w.File.ID = fixtureUUID()
			w.File.Size = "9007199254740993"
		}
		raw, _ := json.Marshal(w)
		var m map[string]json.RawMessage
		_ = json.Unmarshal(raw, &m)
		m["object"] = json.RawMessage(`"send"`)
		m["unknown"] = json.RawMessage(`{"huge":900719925474099312345,"opaque":"keep"}`)
		raw, _ = json.Marshal(m)
		rows = append(rows, raw)
	}
	in.Sync = sendRotationSync(t, in.Scope, rows)
	return in, rows
}
func sendRotationSync(t *testing.T, scope Scope, rows []json.RawMessage) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"profile": map[string]string{"id": scope.Account}, "sends": rows})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func sendRotationChange(t *testing.T, raw json.RawMessage, field string, value any) json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	if value == nil {
		delete(m, field)
	} else {
		m[field], _ = json.Marshal(value)
	}
	out, _ := json.Marshal(m)
	return out
}
func sendRotationNewOwners(t *testing.T, old, requests []json.RawMessage) []json.RawMessage {
	t.Helper()
	out := make([]json.RawMessage, len(old))
	for i := range old {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(requests[i], &m)
		var k string
		_ = json.Unmarshal(m["key"], &k)
		out[i] = sendRotationChange(t, old[i], "key", k)
	}
	return out
}
func TestSendRotationConvertAndVerify(t *testing.T) {
	in, old := sendRotationFixture(t)
	before := append([]byte(nil), in.Sync...)
	requests, err := ConvertSendRotationResources(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, in.Sync) {
		t.Fatal("borrowed sync modified")
	}
	fresh := sendRotationNewOwners(t, old, requests)
	for i, row := range requests {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(row, &m)
		if string(m["password"]) != "null" || !bytes.Contains(m["unknown"], []byte("900719925474099312345")) {
			t.Fatal("owner password leaked or unknown precision lost")
		}
		_, w, e := sendRotationOwner(fresh[i])
		if e != nil {
			t.Fatal(e)
		}
		seed, e := sendRotationSeed(w, in.NewUserKey)
		clear(seed)
		if e != nil {
			t.Fatal(e)
		}
	}
	verify := func(rows []json.RawMessage, want SendRotationState) {
		t.Helper()
		r, e := VerifySendRotationResources(context.Background(), SendRotationVerificationInput{in.Scope, in.Scope, in.Sync, sendRotationSync(t, in.Scope, rows), requests, in.OldUserKey, in.NewUserKey})
		if e != nil || r.State != want || !r.Enumerated || r.BinaryContentVerified {
			t.Fatalf("verification state %s want %s, err %v", r.State, want, e)
		}
	}
	verify(old, SendRotationOld)
	verify(fresh, SendRotationNew)
	mixed := append([]json.RawMessage(nil), fresh...)
	mixed[0] = old[0]
	verify(mixed, SendRotationMixed)
	verify(fresh[:1], SendRotationMissing)
	natural := append([]json.RawMessage(nil), fresh...)
	natural[0] = sendRotationChange(t, natural[0], "accessCount", 3)
	natural[0] = sendRotationChange(t, natural[0], "revisionDate", time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	verify(natural, SendRotationNew)
	for _, field := range []string{"unknown", "disabled", "hideEmail", "password", "accessCount"} {
		changed := append([]json.RawMessage(nil), fresh...)
		value := any(false)
		switch field {
		case "unknown":
			value = json.RawMessage(`{"huge":900719925474099312346,"opaque":"keep"}`)
		case "password":
			value = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
		case "accessCount":
			value = 1
		}
		index := 0
		if field == "password" {
			index = 1
		}
		changed[index] = sendRotationChange(t, changed[index], field, value)
		verify(changed, SendRotationChanged)
	}
	broken := append([]json.RawMessage(nil), fresh...)
	broken[0] = sendRotationChange(t, broken[0], "key", "2.bad")
	verify(broken, SendRotationIndeterminate)
	extra := append(append([]json.RawMessage(nil), fresh...), sendRotationChange(t, old[0], "id", fixtureUUID()))
	verify(extra, SendRotationChanged)
	// Re-randomized valid wrapping of the same seed remains cryptographic proof.
	_, w, _ := sendRotationOwner(old[0])
	seed, _ := sendRotationSeed(w, in.OldUserKey)
	key, _ := vaultcrypto.EncryptString(seed, in.NewUserKey)
	clear(seed)
	randomized := append([]json.RawMessage(nil), fresh...)
	randomized[0] = sendRotationChange(t, randomized[0], "key", key)
	verify(randomized, SendRotationNew)
}
func TestSendRotationAuthenticatesEveryEncryptedField(t *testing.T) {
	in, rows := sendRotationFixture(t)
	corrupt := func(value string) string {
		parts := strings.Split(value[2:], "|")
		mac, _ := base64.StdEncoding.DecodeString(parts[2])
		mac[0] ^= 1
		parts[2] = base64.StdEncoding.EncodeToString(mac)
		return "2." + strings.Join(parts, "|")
	}
	for _, field := range []string{"key", "name", "notes", "text", "file"} {
		t.Run(field, func(t *testing.T) {
			index := 0
			if field == "file" {
				index = 1
			}
			var m map[string]json.RawMessage
			_ = json.Unmarshal(rows[index], &m)
			if field == "text" || field == "file" {
				var nested map[string]json.RawMessage
				_ = json.Unmarshal(m[field], &nested)
				name := "text"
				if field == "file" {
					name = "fileName"
				}
				var value string
				_ = json.Unmarshal(nested[name], &value)
				nested[name], _ = json.Marshal(corrupt(value))
				m[field], _ = json.Marshal(nested)
			} else {
				var value string
				_ = json.Unmarshal(m[field], &value)
				m[field], _ = json.Marshal(corrupt(value))
			}
			raw, _ := json.Marshal(m)
			bad := in
			bad.Sync = sendRotationSync(t, in.Scope, []json.RawMessage{raw})
			got, err := ConvertSendRotationResources(context.Background(), bad)
			if err != ErrEncryption || got != nil {
				t.Fatal("unauthenticated field accepted", err)
			}
		})
	}
	// Even matching malformed owner IDs/access IDs cannot pass identity checks.
	raw := sendRotationChange(t, rows[0], "id", "not-a-uuid")
	raw = sendRotationChange(t, raw, "accessId", "")
	bad := in
	bad.Sync = sendRotationSync(t, in.Scope, []json.RawMessage{raw})
	if _, err := ConvertSendRotationResources(context.Background(), bad); err == nil {
		t.Fatal("invalid access identity accepted")
	}
}

func TestSendRotationRejectsAndEmpty(t *testing.T) {
	in, old := sendRotationFixture(t)
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"bad-mac", "key", "2.bad"}, {"missing-id", "id", nil}, {"missing-disabled", "disabled", nil}, {"null-type", "type", json.RawMessage("null")}, {"schema", "type", 2}, {"email-auth", "authType", 0}, {"no-counter", "accessCount", nil}, {"bad-object", "object", "other"}, {"missing-notes", "notes", nil}, {"bad-text", "text", map[string]any{"text": "2.bad", "hidden": true}}, {"missing-hidden", "text", map[string]any{"text": "2.bad"}}, {"unsupported-key", "keyId", "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyIn := in
			rows := append([]json.RawMessage(nil), old...)
			rows[0] = sendRotationChange(t, rows[0], tc.field, tc.value)
			copyIn.Sync = sendRotationSync(t, in.Scope, rows)
			if _, e := ConvertSendRotationResources(context.Background(), copyIn); e == nil {
				t.Fatal("accepted invalid schema/crypto")
			}
		})
	}
	for _, size := range []int{0, 15, 17, 64} {
		key, _ := vaultcrypto.EncryptString(bytes.Repeat([]byte{3}, size), in.OldUserKey)
		bad := in
		bad.Sync = sendRotationSync(t, in.Scope, []json.RawMessage{sendRotationChange(t, old[0], "key", key)})
		if _, e := ConvertSendRotationResources(context.Background(), bad); e == nil {
			t.Fatal("bad seed length accepted")
		}
	}
	duplicate := in
	duplicate.Sync = sendRotationSync(t, in.Scope, []json.RawMessage{old[0], old[0]})
	if _, e := ConvertSendRotationResources(context.Background(), duplicate); e == nil {
		t.Fatal("duplicate accepted")
	}
	cross := in
	cross.Scope.Account = fixtureUUID()
	if _, e := ConvertSendRotationResources(context.Background(), cross); e != ErrIdentity {
		t.Fatal("scope mismatch", e)
	}
	empty := in
	empty.Sync = sendRotationSync(t, in.Scope, []json.RawMessage{})
	rows, e := ConvertSendRotationResources(context.Background(), empty)
	if e != nil || rows == nil || len(rows) != 0 {
		t.Fatal("empty enumeration", e)
	}
	result, e := VerifySendRotationResources(context.Background(), SendRotationVerificationInput{in.Scope, in.Scope, empty.Sync, empty.Sync, rows, in.OldUserKey, in.NewUserKey})
	if e != nil || !result.Empty || !result.Enumerated || result.State != SendRotationIndeterminate {
		t.Fatal("empty classification", e)
	}
	empty.Sync = sendRotationSync(t, in.Scope, nil)
	if _, e := ConvertSendRotationResources(context.Background(), empty); e == nil {
		t.Fatal("null list accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ConvertSendRotationResources(ctx, in); e != context.Canceled {
		t.Fatal("cancel", e)
	}
	requests, e := ConvertSendRotationResources(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	v := SendRotationVerificationInput{in.Scope, in.Scope, in.Sync, in.Sync, requests, in.OldUserKey, in.NewUserKey}
	if _, e := VerifySendRotationResources(ctx, v); e != context.Canceled {
		t.Fatal("verify cancel", e)
	}
	v.FreshScope.Account = fixtureUUID()
	if _, e := VerifySendRotationResources(context.Background(), v); e != ErrIdentity {
		t.Fatal("verify scope", e)
	}
	v.FreshScope = in.Scope
	v.RequestSends = append([]json.RawMessage(nil), requests...)
	v.RequestSends[0] = sendRotationChange(t, requests[0], "disabled", false)
	if _, e := VerifySendRotationResources(context.Background(), v); e == nil {
		t.Fatal("tampered request accepted")
	}
}
