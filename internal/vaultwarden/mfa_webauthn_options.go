// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"encoding/base64"
	"encoding/json"
)

// WebAuthnOptions is the native bridge input, parsed from provider 7 metadata or
// get-webauthn-challenge. No DOM/JavaScript challenge reconstruction is required.
type WebAuthnOptions struct {
	RPID              string
	Challenge, UserID []byte
	UserName          string
	Allowed, Excluded [][]byte
	Binding           *WebAuthnBinding
}

func ParseWebAuthnOptions(server string, raw json.RawMessage, register bool, epoch uint64) (WebAuthnOptions, error) {
	var wire struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"user"`
		Allowed []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"allowCredentials"`
		Excluded []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"excludeCredentials"`
	}
	if len(raw) > 65536 || strictJSON(raw) != nil || json.Unmarshal(raw, &wire) != nil {
		return WebAuthnOptions{}, ErrProtocol
	}
	rp := wire.RPID
	if register {
		rp = wire.RP.ID
	}
	allowed := []string{}
	result := WebAuthnOptions{RPID: rp}
	for _, credential := range wire.Allowed {
		decoded, e := base64.RawURLEncoding.DecodeString(credential.ID)
		if e != nil || len(decoded) == 0 || credential.Type != "public-key" {
			return WebAuthnOptions{}, ErrProtocol
		}
		allowed = append(allowed, credential.ID)
		result.Allowed = append(result.Allowed, decoded)
	}
	for _, credential := range wire.Excluded {
		decoded, e := base64.RawURLEncoding.DecodeString(credential.ID)
		if e != nil || len(decoded) == 0 || credential.Type != "public-key" {
			return WebAuthnOptions{}, ErrProtocol
		}
		result.Excluded = append(result.Excluded, decoded)
	}
	binding, e := NewWebAuthnBinding(server, rp, wire.Challenge, register, allowed, epoch)
	if e != nil {
		return WebAuthnOptions{}, e
	}
	result.Binding = binding
	result.Challenge, _ = base64.RawURLEncoding.DecodeString(wire.Challenge)
	if register {
		result.UserID, e = base64.RawURLEncoding.DecodeString(wire.User.ID)
		result.UserName = wire.User.Name
		if e != nil || len(result.UserID) == 0 || len(result.UserID) > 64 || result.UserName == "" {
			binding.Close()
			return WebAuthnOptions{}, ErrProtocol
		}
	}
	return result, nil
}
