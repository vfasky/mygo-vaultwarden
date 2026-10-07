// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sync"
	"time"
)

// WebAuthnBinding must be created from the authenticated server's challenge,
// never from an arbitrary browser/navigation message. A response is single use.
type WebAuthnBinding struct {
	mu                    sync.Mutex
	challenge, origin, rp string
	register              bool
	epoch                 uint64
	expires               time.Time
	used                  bool
	allowed               []string
}

func NewWebAuthnBinding(server, rp, challenge string, register bool, allowed []string, epoch uint64) (*WebAuthnBinding, error) {
	canonical, err := CanonicalServer(server)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(canonical)
	// VW uses its configured domain as RP. Exact host avoids suffix/public-suffix confusion.
	if rp != u.Hostname() || u.Scheme != "https" {
		return nil, ErrValidation
	}
	b, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(b) < 16 || len(b) > 1024 {
		return nil, ErrValidation
	}
	return &WebAuthnBinding{challenge: challenge, origin: u.Scheme + "://" + u.Host, rp: rp, register: register, epoch: epoch, expires: time.Now().Add(2 * time.Minute), allowed: append([]string(nil), allowed...)}, nil
}
func (b *WebAuthnBinding) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used = true
	b.challenge = ""
	b.allowed = nil
}

// Validate checks browser binding, not the authenticator signature. The server
// performs attestation/signature/counter validation before accepting MFA.
func (b *WebAuthnBinding) Validate(raw json.RawMessage, epoch uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used || epoch != b.epoch || time.Now().After(b.expires) {
		return ErrExpired
	}
	if len(raw) > 65536 || strictJSON(raw) != nil {
		return ErrValidation
	}
	var credential struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			Client      string `json:"clientDataJSON"`
			Auth        string `json:"authenticatorData"`
			Signature   string `json:"signature"`
			Attestation string `json:"attestationObject"`
		} `json:"response"`
	}
	if json.Unmarshal(raw, &credential) != nil || credential.Type != "public-key" || credential.ID == "" || credential.ID != credential.RawID {
		return ErrValidation
	}
	id, err := base64.RawURLEncoding.DecodeString(credential.ID)
	if err != nil || len(id) == 0 {
		return ErrValidation
	}
	client, err := base64.RawURLEncoding.DecodeString(credential.Response.Client)
	if err != nil || strictJSON(client) != nil {
		return ErrValidation
	}
	var data struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	expected := "webauthn.get"
	if b.register {
		expected = "webauthn.create"
	}
	if json.Unmarshal(client, &data) != nil || data.Type != expected || data.Origin != b.origin || data.CrossOrigin || subtle.ConstantTimeCompare([]byte(data.Challenge), []byte(b.challenge)) != 1 {
		return ErrValidation
	}
	if b.register {
		a, e := base64.RawURLEncoding.DecodeString(credential.Response.Attestation)
		if e != nil || len(a) == 0 {
			return ErrValidation
		}
	} else {
		if len(b.allowed) > 0 {
			found := false
			for _, a := range b.allowed {
				if a == credential.ID {
					found = true
				}
			}
			if !found {
				return ErrValidation
			}
		}
		auth, e := base64.RawURLEncoding.DecodeString(credential.Response.Auth)
		hash := sha256.Sum256([]byte(b.rp))
		if e != nil || len(auth) < 37 || subtle.ConstantTimeCompare(auth[:32], hash[:]) != 1 || auth[32]&1 == 0 {
			return ErrValidation
		}
		sig, e := base64.RawURLEncoding.DecodeString(credential.Response.Signature)
		if e != nil || len(sig) == 0 {
			return ErrValidation
		}
	}
	b.used = true
	return nil
}
