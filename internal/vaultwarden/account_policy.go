// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/passwordstrength"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// AccountPasswordPolicy is the merged, authenticated verify-password/identity
// response. Authentication lanes may check EnforceOnLogin before granting access.
// Unknown/malformed policy fields must be rejected by the response decoder.
type AccountPasswordPolicy struct {
	MinComplexity  int  `json:"minComplexity"`
	MinLength      int  `json:"minLength"`
	RequireLower   bool `json:"requireLower"`
	RequireUpper   bool `json:"requireUpper"`
	RequireNumbers bool `json:"requireNumbers"`
	RequireSpecial bool `json:"requireSpecial"`
	EnforceOnLogin bool `json:"enforceOnLogin"`
}

func (p AccountPasswordPolicy) Check(ctx context.Context, password []byte, email string, login bool) error {
	if len(password) == 0 || len(password) > 8192 || !utf8.Valid(password) {
		return ErrCredentials
	}
	if login && !p.EnforceOnLogin {
		return nil
	}
	if p.MinComplexity < 0 || p.MinComplexity > 4 || p.MinLength < 0 || p.MinLength > 8192 {
		return ErrProtocol
	}
	text := string(password)
	if len(utf16.Encode([]rune(text))) < p.MinLength {
		return ErrValidation
	}
	lower, upper, number, special := cases.Upper(language.Und).String(text) != text, cases.Lower(language.Und).String(text) != text, false, false
	for _, r := range text {
		number = number || (r >= '0' && r <= '9')
		special = special || strings.ContainsRune("!@#$%^&*", r)
	}
	if p.RequireLower && !lower || p.RequireUpper && !upper || p.RequireNumbers && !number || p.RequireSpecial && !special {
		return ErrValidation
	}
	ok, err := passwordstrength.CheckMinimum(ctx, text, email, nil, p.MinComplexity)
	if err != nil {
		return err
	}
	if !ok {
		return ErrValidation
	}
	return nil
}

// AccountSensitiveInput accepts exactly one of a master password or a protected
// action email OTP. OTP is NOT a TOTP/login provider token. Callers clear Password.
type AccountSensitiveInput struct {
	Password []byte
	OTP      string
}
type accountProof struct {
	Hash string `json:"masterPasswordHash,omitempty"`
	OTP  string `json:"otp,omitempty"`
}

func (s *Session) accountProofLocked(input AccountSensitiveInput) (accountProof, error) {
	if (len(input.Password) == 0) == (input.OTP == "") {
		return accountProof{}, ErrValidation
	}
	if input.OTP != "" {
		if len(input.OTP) > 128 {
			return accountProof{}, ErrValidation
		}
		return accountProof{OTP: input.OTP}, nil
	}
	if s.passwordUnlock == nil {
		return accountProof{}, ErrExpired
	}
	master, err := vaultcrypto.DeriveMaster(input.Password, s.email, s.passwordUnlock.Config.KDF)
	if err != nil {
		return accountProof{}, err
	}
	defer clear(master)
	stretched, err := vaultcrypto.StretchMaster(master)
	if err != nil {
		return accountProof{}, err
	}
	defer clear(stretched)
	key, err := vaultcrypto.DecryptString(s.wrapped, stretched)
	if err != nil {
		return accountProof{}, ErrCredentials
	}
	defer clear(key)
	if !hmac.Equal(key, s.key) {
		return accountProof{}, ErrCredentials
	}
	return accountProof{Hash: vaultcrypto.AuthorizationHash(master, input.Password)}, nil
}
func (s *Session) accountPolicyLocked(ctx context.Context, password []byte, persist func(SessionCheckpoint) error) (AccountPasswordPolicy, error) {
	proof, err := s.accountProofLocked(AccountSensitiveInput{Password: password})
	if err != nil {
		return AccountPasswordPolicy{}, err
	}
	return s.accountPolicyProofLocked(ctx, proof, persist)
}
func (s *Session) accountPolicyProofLocked(ctx context.Context, proof accountProof, persist func(SessionCheckpoint) error) (AccountPasswordPolicy, error) {
	body, _ := json.Marshal(proof)
	defer clear(body)
	status, data, err := s.authenticatedLocked(ctx, "POST", "/api/accounts/verify-password", "application/json", string(body), persist)
	if err != nil {
		return AccountPasswordPolicy{}, err
	}
	if status != 200 {
		return AccountPasswordPolicy{}, statusError(status)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return AccountPasswordPolicy{}, ErrProtocol
	}
	var object string
	objectRaw := fields["Object"]
	if len(objectRaw) == 0 {
		objectRaw = fields["object"]
	}
	if json.Unmarshal(objectRaw, &object) != nil || object != "masterPasswordPolicy" {
		return AccountPasswordPolicy{}, ErrProtocol
	}
	for key := range fields {
		switch key {
		case "Object", "object", "minComplexity", "minLength", "requireLower", "requireUpper", "requireNumbers", "requireSpecial", "enforceOnLogin":
		default:
			return AccountPasswordPolicy{}, ErrProtocol
		}
	}
	var p AccountPasswordPolicy
	if strictJSON(data) != nil || json.Unmarshal(data, &p) != nil || p.MinComplexity < 0 || p.MinComplexity > 4 || p.MinLength < 0 || p.MinLength > 8192 {
		return p, ErrProtocol
	}
	return p, nil
}
func (s *Session) AccountVerifyPassword(ctx context.Context, password []byte, persist func(SessionCheckpoint) error) (AccountPasswordPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return AccountPasswordPolicy{}, err
	}
	defer done()
	return s.accountPolicyLocked(ctx, password, persist)
}
