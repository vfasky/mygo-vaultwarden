// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"
)

// SendRotationState describes Send resources only, never the account's recovery
// state. Empty enumeration is separately reported; it cannot prove a key rotated.
type SendRotationState string

const (
	SendRotationOld           SendRotationState = "old"
	SendRotationNew           SendRotationState = "new"
	SendRotationMixed         SendRotationState = "mixed"
	SendRotationChanged       SendRotationState = "externally-changed"
	SendRotationMissing       SendRotationState = "missing"
	SendRotationIndeterminate SendRotationState = "indeterminate"
)

type SendRotationResourceVerification struct {
	ID    string
	State SendRotationState
	// Reason contains only fixed diagnostic codes, never content or keys.
	Reason string
}
type SendRotationVerification struct {
	State      SendRotationState
	Enumerated bool
	Empty      bool
	Resources  []SendRotationResourceVerification
	// BinaryContentVerified is always false: sync contains no file bytes/MAC.
	BinaryContentVerified bool
}

// All inputs are borrowed only for this call. The caller authenticates fresh
// authority and binds the journal operation/epoch; this pure helper cannot do so.
type SendRotationVerificationInput struct {
	Scope, FreshScope      Scope
	OldSync, FreshSync     json.RawMessage
	RequestSends           []json.RawMessage
	OldUserKey, NewUserKey []byte
}

// ConvertSendRotationResources implements Vaultwarden 1.37.4 SendData for the
// rotate-user-account-keys endpoint ONLY. That endpoint consumes only id/key,
// although serde requires the complete SendData shape. Never send this result
// to PUT /sends/{id}: owner password is a server hash, not a password input.
// No Read, Session call, mutation, seed generation or binary upload occurs.
func ConvertSendRotationResources(ctx context.Context, in AccountRotationInput) ([]json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(in.OldUserKey) != 64 || len(in.NewUserKey) != 64 || bytes.Equal(in.OldUserKey, in.NewUserKey) {
		return nil, ErrEncryption
	}
	rows, err := sendRotationRows(in.Sync, in.Scope)
	if err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields, w, err := sendRotationOwner(row)
		if err != nil {
			return nil, err
		}
		seed, err := sendRotationSeed(w, in.OldUserKey)
		if err != nil {
			return nil, err
		}
		wrapped, err := vaultcrypto.EncryptString(seed, in.NewUserKey)
		clear(seed)
		if err != nil {
			return nil, err
		}
		fields["key"], _ = json.Marshal(wrapped)
		// Password in owner JSON is a server-side hash. Null preserves password even
		// in the ordinary update API; rotation itself does not read this field.
		fields["password"] = json.RawMessage("null")
		raw, err := json.Marshal(fields)
		if err != nil {
			return nil, ErrProtocol
		}
		out = append(out, raw)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func sendRotationRows(raw json.RawMessage, scope Scope) ([]json.RawMessage, error) {
	canonical, err := CanonicalServer(scope.Server)
	if err != nil || canonical != scope.Server || !validObjectID(scope.Account) {
		return nil, ErrIdentity
	}
	var sync struct {
		Profile struct{ ID string }
		Sends   []json.RawMessage
	}
	if strictJSON(raw) != nil || json.Unmarshal(raw, &sync) != nil || sync.Profile.ID != scope.Account {
		return nil, ErrIdentity
	}
	if sync.Sends == nil || len(sync.Sends) > 100000 {
		return nil, ErrProtocol
	}
	if _, err := sendRotationIndex(sync.Sends); err != nil {
		return nil, err
	}
	return sync.Sends, nil
}
func sendRotationIndex(rows []json.RawMessage) (map[string]json.RawMessage, error) {
	if rows == nil || len(rows) > 100000 {
		return nil, ErrProtocol
	}
	index := make(map[string]json.RawMessage, len(rows))
	for _, row := range rows {
		var id struct{ ID string }
		if strictJSON(row) != nil || json.Unmarshal(row, &id) != nil || !validObjectID(id.ID) {
			return nil, ErrProtocol
		}
		if _, ok := index[id.ID]; ok {
			return nil, ErrProtocol
		}
		index[id.ID] = row
	}
	return index, nil
}

func sendRotationOwner(raw json.RawMessage) (map[string]json.RawMessage, sendWire, error) {
	var fields map[string]json.RawMessage
	var w sendWire
	fail := func() (map[string]json.RawMessage, sendWire, error) { return nil, sendWire{}, ErrProtocol }
	if strictJSON(raw) != nil || json.Unmarshal(raw, &fields) != nil || json.Unmarshal(raw, &w) != nil {
		return fail()
	}
	for _, name := range []string{"id", "accessId", "type", "name", "notes", "text", "file", "key", "maxAccessCount", "accessCount", "password", "authType", "disabled", "hideEmail", "revisionDate", "expirationDate", "deletionDate", "object"} {
		v, ok := fields[name]
		if !ok {
			return fail()
		}
		switch name {
		case "notes", "text", "file", "maxAccessCount", "password", "expirationDate":
		default:
			if bytes.Equal(v, []byte("null")) {
				return fail()
			}
		}
	}
	var object string
	if json.Unmarshal(fields["object"], &object) != nil || object != "send" || !validObjectID(w.ID) || !validSendAccess(w.AccessID) || w.AccessID != sendAccessID(w.ID) || w.Name == "" || w.Key == "" || w.DeletionDate.IsZero() || w.AccessCount < 0 || w.AccessCount > 2147483647 {
		return fail()
	}
	if _, err := time.Parse(time.RFC3339Nano, w.RevisionDate); err != nil {
		return fail()
	}
	if w.MaxAccessCount != nil && (*w.MaxAccessCount < 0 || *w.MaxAccessCount > 2147483647) {
		return fail()
	}
	if w.AuthType != 1 && w.AuthType != 2 || (w.Password == nil) != (w.AuthType == 2) {
		return fail()
	}
	if w.Password != nil {
		b, err := base64.RawURLEncoding.Strict().DecodeString(*w.Password)
		defer clear(b)
		if err != nil || len(b) != 32 {
			return fail()
		}
	}
	// Explicitly refuse alternate key hierarchies and unsupported email auth.
	for _, name := range []string{"encryptedByKeyId", "keyId", "emails", "organizationId"} {
		if v, ok := fields[name]; ok && !bytes.Equal(v, []byte("null")) {
			return fail()
		}
	}
	var nested map[string]json.RawMessage
	switch w.Type {
	case 0:
		if w.Text == nil || w.File != nil || json.Unmarshal(fields["text"], &nested) != nil {
			return fail()
		}
		if nested["text"] == nil || nested["hidden"] == nil || bytes.Equal(nested["hidden"], []byte("null")) || w.Text.Text == "" {
			return fail()
		}
	case 1:
		if w.File == nil || w.Text != nil || !validObjectID(w.File.ID) || w.File.FileName == "" || json.Unmarshal(fields["file"], &nested) != nil {
			return fail()
		}
		size, err := strconv.ParseInt(w.File.Size, 10, 64)
		if err != nil || size < 0 {
			return fail()
		}
	default:
		return fail()
	}
	return fields, w, nil
}

// Authenticate every supported encrypted metadata field without allocating
// immutable plaintext strings. Seed and derived key buffers are always cleared.
func sendRotationSeed(w sendWire, userKey []byte) ([]byte, error) {
	seed, err := vaultcrypto.DecryptString(w.Key, userKey)
	if err != nil {
		clear(seed)
		return nil, err
	}
	key, err := sendKey(seed)
	if err != nil {
		clear(seed)
		return nil, err
	}
	defer clear(key)
	encrypted := []string{w.Name}
	if w.Notes != nil {
		encrypted = append(encrypted, *w.Notes)
	}
	if w.Text != nil {
		encrypted = append(encrypted, w.Text.Text)
	}
	if w.File != nil {
		encrypted = append(encrypted, w.File.FileName)
	}
	for _, value := range encrypted {
		plain, e := vaultcrypto.DecryptString(value, key)
		valid := e == nil && utf8.Valid(plain)
		clear(plain)
		if !valid {
			clear(seed)
			return nil, ErrEncryption
		}
	}
	return seed, nil
}

// VerifySendRotationResources compares authoritative fresh sync with journal
// old sync and the exact saved request. It never encrypts, retries or writes.
// Mixed, missing, changed and indeterminate outcomes must keep recovery pending.
func VerifySendRotationResources(ctx context.Context, in SendRotationVerificationInput) (SendRotationVerification, error) {
	result := SendRotationVerification{State: SendRotationIndeterminate, Resources: []SendRotationResourceVerification{}}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if in.Scope != in.FreshScope {
		return result, ErrIdentity
	}
	if len(in.OldUserKey) != 64 || len(in.NewUserKey) != 64 || bytes.Equal(in.OldUserKey, in.NewUserKey) {
		return result, ErrEncryption
	}
	oldRows, err := sendRotationRows(in.OldSync, in.Scope)
	if err != nil {
		return result, err
	}
	freshRows, err := sendRotationRows(in.FreshSync, in.FreshScope)
	if err != nil {
		return result, err
	}
	requests, err := sendRotationIndex(in.RequestSends)
	if err != nil {
		return result, err
	}
	if len(requests) != len(oldRows) {
		return result, ErrProtocol
	}
	fresh, _ := sendRotationIndex(freshRows)
	result.Enumerated = true
	result.Empty = len(oldRows) == 0 && len(freshRows) == 0
	states := map[SendRotationState]bool{}
	for _, row := range oldRows {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		fields, w, err := sendRotationOwner(row)
		if err != nil {
			return result, err
		}
		oldSeed, err := sendRotationSeed(w, in.OldUserKey)
		if err != nil {
			return result, err
		}
		state, reason, e := sendRotationVerifyOne(fields, w, oldSeed, requests[w.ID], fresh[w.ID], in)
		clear(oldSeed)
		if e != nil {
			return result, e
		}
		result.Resources = append(result.Resources, SendRotationResourceVerification{w.ID, state, reason})
		states[state] = true
		delete(fresh, w.ID)
	}
	// Preserve fresh enumeration order, making reports deterministic.
	for _, row := range freshRows {
		var v struct{ ID string }
		_ = json.Unmarshal(row, &v)
		if _, ok := fresh[v.ID]; ok {
			result.Resources = append(result.Resources, SendRotationResourceVerification{v.ID, SendRotationChanged, "unexpected-id"})
			states[SendRotationChanged] = true
		}
	}
	switch {
	case states[SendRotationIndeterminate]:
		result.State = SendRotationIndeterminate
	case states[SendRotationChanged]:
		result.State = SendRotationChanged
	case states[SendRotationMissing]:
		result.State = SendRotationMissing
	case states[SendRotationOld] && states[SendRotationNew]:
		result.State = SendRotationMixed
	case states[SendRotationNew]:
		result.State = SendRotationNew
	case states[SendRotationOld]:
		result.State = SendRotationOld
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}
func sendRotationVerifyOne(old map[string]json.RawMessage, w sendWire, seed []byte, request, current json.RawMessage, in SendRotationVerificationInput) (SendRotationState, string, error) {
	var target map[string]json.RawMessage
	var wrapped string
	if strictJSON(request) != nil || json.Unmarshal(request, &target) != nil || json.Unmarshal(target["key"], &wrapped) != nil {
		return SendRotationIndeterminate, "", ErrProtocol
	}
	requestSeed, err := vaultcrypto.DecryptString(wrapped, in.NewUserKey)
	matches := err == nil && bytes.Equal(seed, requestSeed)
	clear(requestSeed)
	if !matches {
		return SendRotationIndeterminate, "", ErrEncryption
	}
	// Compare all request fields, including unknown values, against exactly the
	// conversion policy. Do not trust a journal request that edits other data.
	expected := make(map[string]json.RawMessage, len(old))
	for k, v := range old {
		expected[k] = v
	}
	expected["key"] = target["key"]
	expected["password"] = json.RawMessage("null")
	if !sendRotationEqual(expected, target) {
		return SendRotationIndeterminate, "", ErrProtocol
	}
	if current == nil {
		return SendRotationMissing, "expected-id-absent", nil
	}
	fields, fresh, err := sendRotationOwner(current)
	if err != nil {
		return SendRotationIndeterminate, "unsupported-fresh-schema", nil
	}
	// Only these two server fields may naturally advance. Every unknown field
	// and every ciphertext, file descriptor, password hash and limit is compared.
	oldTime, _ := time.Parse(time.RFC3339Nano, w.RevisionDate)
	newTime, _ := time.Parse(time.RFC3339Nano, fresh.RevisionDate)
	if newTime.Before(oldTime) || fresh.AccessCount < w.AccessCount {
		return SendRotationChanged, "server-counter-regressed", nil
	}
	for _, name := range []string{"key", "revisionDate", "accessCount"} {
		delete(expected, name)
		delete(fields, name)
	}
	expected["password"] = old["password"]
	if !sendRotationEqual(expected, fields) {
		return SendRotationChanged, "content-or-metadata-changed", nil
	}
	oldSeed, oldErr := sendRotationSeed(fresh, in.OldUserKey)
	newSeed, newErr := sendRotationSeed(fresh, in.NewUserKey)
	defer clear(oldSeed)
	defer clear(newSeed)
	oldOK := oldErr == nil && bytes.Equal(seed, oldSeed)
	newOK := newErr == nil && bytes.Equal(seed, newSeed)
	switch {
	case oldOK && !newOK:
		return SendRotationOld, "old-key-authenticated", nil
	case newOK && !oldOK:
		return SendRotationNew, "new-key-authenticated", nil
	default:
		return SendRotationIndeterminate, "seed-or-mac-unverifiable", nil
	}
}
func sendRotationEqual(a, b map[string]json.RawMessage) bool {
	// UseNumber avoids float64 rounding of unknown large integers; maps compare
	// independently of JSON member ordering. Numeric spelling is conservative.
	decode := func(v map[string]json.RawMessage) any {
		raw, _ := json.Marshal(v)
		var out any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&out) != nil {
			return nil
		}
		return out
	}
	return reflect.DeepEqual(decode(a), decode(b))
}
