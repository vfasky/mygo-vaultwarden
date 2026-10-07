// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// SendFields is the editable plaintext form. Password nil preserves an existing
// password; removal is a separate operation. Email verification is unsupported
// by Vaultwarden 1.37.4 and deliberately has no request field.
type SendFields struct {
	Name, Notes, Text, FileName string
	CreatorIdentifier           string // receiver-only server projection; never submitted
	Type                        int
	Hidden, Disabled, HideEmail bool
	DeletionDate                time.Time
	ExpirationDate              *time.Time
	MaxAccessCount              *int
	Password                    *string
}
type sendText struct {
	Text   string `json:"text"`
	Hidden bool   `json:"hidden"`
}
type sendFile struct {
	ID       string `json:"id,omitempty"`
	FileName string `json:"fileName"`
	Size     string `json:"size,omitempty"`
}
type sendWire struct {
	ID                string     `json:"id,omitempty"`
	CreatorIdentifier string     `json:"creatorIdentifier,omitempty"`
	AccessID          string     `json:"accessId,omitempty"`
	Type              int        `json:"type"`
	Name              string     `json:"name"`
	Notes             *string    `json:"notes"`
	Key               string     `json:"key"`
	Text              *sendText  `json:"text"`
	File              *sendFile  `json:"file"`
	Password          *string    `json:"password"`
	Disabled          bool       `json:"disabled"`
	HideEmail         bool       `json:"hideEmail"`
	DeletionDate      time.Time  `json:"deletionDate"`
	ExpirationDate    *time.Time `json:"expirationDate"`
	MaxAccessCount    *int       `json:"maxAccessCount"`
	AccessCount       int        `json:"accessCount,omitempty"`
	RevisionDate      string     `json:"revisionDate,omitempty"`
	FileLength        *int64     `json:"fileLength,omitempty"`
	AuthType          int        `json:"authType,omitempty"`
}

// SendDraft is session-bound. Do not serialize it or log it. Close when the
// editor closes, on lock, account change, and on snapshot replacement.
type SendDraft struct {
	Fields   SendFields
	wire     sendWire
	seed     []byte
	scope    Scope
	epoch    uint64
	revision string
	consumed bool
	owner    *Session
}

func (d *SendDraft) ID() string {
	if d == nil {
		return ""
	}
	return d.wire.ID
}
func (d *SendDraft) AccessCount() int {
	if d == nil {
		return 0
	}
	return d.wire.AccessCount
}
func (d *SendDraft) HasPassword() bool { return d != nil && d.wire.Password != nil }
func (d *SendDraft) Close() {
	if d != nil {
		clear(d.seed)
		*d = SendDraft{consumed: true}
	}
}
func sendKey(seed []byte) ([]byte, error) {
	if len(seed) != 16 {
		return nil, ErrEncryption
	}
	key := make([]byte, 64)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("bitwarden-send"), []byte("send")), key); err != nil {
		clear(key)
		return nil, ErrEncryption
	}
	return key, nil
}
func sendPassword(password string, seed []byte) string {
	b := pbkdf2.Key([]byte(password), seed, 100000, 32, sha256.New)
	defer clear(b)
	return base64.StdEncoding.EncodeToString(b)
}
func sendAccessID(id string) string {
	b, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(b) != 16 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func validSendAccess(id string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(id)
	return e == nil && len(b) == 16
}

// CanEdit reports whether this draft still has its original session lease.
// It never renews the lease and is intended for retaining pre-dispatch errors.
func (d *SendDraft) CanEdit() bool {
	if d == nil || d.owner == nil {
		return false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	return d.owner.sendGuardLocked(context.Background(), d) == nil
}
func (d *SendDraft) ShareLink() (string, error) {
	if d == nil || d.owner == nil {
		return "", ErrExpired
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.checkpointPending {
		return "", ErrCheckpoint
	}
	if err := d.owner.sendGuardLocked(context.Background(), d); err != nil {
		return "", err
	}
	if d.consumed || !validSendAccess(d.wire.AccessID) || len(d.seed) != 16 {
		return "", ErrExpired
	}
	return d.scope.Server + "/#/send/" + d.wire.AccessID + "/" + base64.RawURLEncoding.EncodeToString(d.seed), nil
}
func validateSendFields(f SendFields) error {
	if f.Type != 0 && f.Type != 1 {
		return ErrValidation
	}
	if strings.TrimSpace(f.Name) == "" || len(f.Name) > 4096 || len(f.Notes) > 65536 || len(f.Text) > 1024*1024 || len(f.FileName) > 4096 || !utf8.ValidString(f.Name+f.Notes+f.Text+f.FileName) {
		return ErrValidation
	}
	if !f.DeletionDate.After(time.Now()) || f.DeletionDate.After(time.Now().Add(31*24*time.Hour)) {
		return ErrValidation
	}
	if f.ExpirationDate != nil && (f.ExpirationDate.After(f.DeletionDate) || !f.ExpirationDate.After(time.Now())) {
		return ErrValidation
	}
	if f.MaxAccessCount != nil && (*f.MaxAccessCount < 1 || *f.MaxAccessCount > 2147483647) {
		return ErrValidation
	}
	if f.Password != nil && (len(*f.Password) == 0 || len(*f.Password) > 4096 || !utf8.ValidString(*f.Password)) {
		return ErrValidation
	}
	if f.Type == 1 && strings.TrimSpace(f.FileName) == "" {
		return ErrValidation
	}
	return nil
}
func encryptSend(f SendFields, seed, userKey []byte) (sendWire, error) {
	if err := validateSendFields(f); err != nil {
		return sendWire{}, err
	}
	key, err := sendKey(seed)
	if err != nil {
		return sendWire{}, err
	}
	defer clear(key)
	w := sendWire{Type: f.Type, Disabled: f.Disabled, HideEmail: f.HideEmail, DeletionDate: f.DeletionDate.Truncate(time.Millisecond), MaxAccessCount: f.MaxAccessCount}
	if f.ExpirationDate != nil {
		v := f.ExpirationDate.Truncate(time.Millisecond)
		w.ExpirationDate = &v
	}
	if w.Key, err = EncryptString(seed, userKey); err != nil {
		return w, err
	}
	if w.Name, err = EncryptString([]byte(f.Name), key); err != nil {
		return w, err
	}
	notes, e := EncryptString([]byte(f.Notes), key)
	if e != nil {
		return w, e
	}
	w.Notes = &notes
	if f.Type == 0 {
		text, e := EncryptString([]byte(f.Text), key)
		if e != nil {
			return w, e
		}
		w.Text = &sendText{text, f.Hidden}
	} else {
		name, e := EncryptString([]byte(f.FileName), key)
		if e != nil {
			return w, e
		}
		w.File = &sendFile{FileName: name}
	}
	if f.Password != nil {
		p := sendPassword(*f.Password, seed)
		w.Password = &p
	}
	return w, nil
}
func decryptSend(w sendWire, userKey []byte) (*SendDraft, error) {
	if !validObjectID(w.ID) || sendAccessID(w.ID) != w.AccessID || w.RevisionDate == "" || w.AuthType != 1 && w.AuthType != 2 || (w.Password == nil) != (w.AuthType == 2) {
		return nil, ErrProtocol
	}
	seed, e := DecryptString(w.Key, userKey)
	if e != nil {
		return nil, e
	}
	defer clear(seed)
	f, e := decryptSendFields(w, seed)
	if e != nil {
		return nil, e
	}
	return &SendDraft{Fields: f, wire: w, seed: append([]byte(nil), seed...)}, nil
}
func decryptSendFields(w sendWire, seed []byte) (SendFields, error) {
	key, e := sendKey(seed)
	if e != nil {
		return SendFields{}, e
	}
	defer clear(key)
	f := SendFields{Type: w.Type, CreatorIdentifier: w.CreatorIdentifier, Disabled: w.Disabled, HideEmail: w.HideEmail, DeletionDate: w.DeletionDate}
	if w.ExpirationDate != nil {
		v := *w.ExpirationDate
		f.ExpirationDate = &v
	}
	if w.MaxAccessCount != nil {
		v := *w.MaxAccessCount
		f.MaxAccessCount = &v
	}
	text := func(s string) (string, error) {
		b, e := DecryptString(s, key)
		defer clear(b)
		if e != nil {
			return "", e
		}
		if !utf8.Valid(b) {
			return "", ErrEncryption
		}
		return string(b), nil
	}
	if f.Name, e = text(w.Name); e != nil {
		return f, e
	}
	if w.Notes != nil {
		if f.Notes, e = text(*w.Notes); e != nil {
			return f, e
		}
	}
	switch w.Type {
	case 0:
		if w.Text == nil || w.File != nil {
			return f, ErrProtocol
		}
		f.Text, e = text(w.Text.Text)
		f.Hidden = w.Text.Hidden
	case 1:
		if w.File == nil || w.Text != nil || !validObjectID(w.File.ID) {
			return f, ErrProtocol
		}
		f.FileName, e = text(w.File.FileName)
	default:
		return f, ErrProtocol
	}
	return f, e
}
func newSendSeed() ([]byte, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return nil, ErrEncryption
	}
	return b, nil
}
func decodeSend(body []byte) (sendWire, error) {
	var w sendWire
	if strictJSON(body) != nil || json.Unmarshal(body, &w) != nil {
		return w, ErrProtocol
	}
	return w, nil
}

// ParseSendLink accepts only links for the explicitly selected server, including
// a base path. No request is made to a pasted host. The seed stays in fragment.
func ParseSendLink(server, link string) (string, []byte, error) {
	canonical, e := CanonicalServer(server)
	if e != nil {
		return "", nil, e
	}
	u, e := url.Parse(link)
	if e != nil || len(link) > 8192 || u.User != nil || u.RawQuery != "" || u.RawPath != "" {
		return "", nil, ErrValidation
	}
	frag := u.Fragment
	u.Fragment = ""
	if strings.TrimRight(u.String(), "/") != canonical {
		return "", nil, ErrIdentity
	}
	parts := strings.Split(strings.TrimPrefix(frag, "/"), "/")
	if len(parts) != 3 || parts[0] != "send" || !validSendAccess(parts[1]) {
		return "", nil, ErrValidation
	}
	seed, e := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if e != nil || len(seed) != 16 {
		clear(seed)
		return "", nil, ErrValidation
	}
	return parts[1], seed, nil
}
