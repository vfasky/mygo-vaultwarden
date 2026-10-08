// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

var ErrRecoveryCompatibility = errors.New("无法确认支持恢复核验的 Vaultwarden 1.37.4 实现，未解除恢复屏障")

func (c *Client) requireRecoveryCompatibility(ctx context.Context) error {
	_, _, err := c.rotationCompatibility(ctx)
	if errors.Is(err, ErrRotationCompatibility) {
		return ErrRecoveryCompatibility
	}
	return err
}

// RecoveryVerificationExpectation contains only immutable, non-password
// witnesses of the request actually prepared. Value fields intentionally avoid
// exposing mutable aliases through Summary, BeforeDispatch, and result copies.
// A zero value denotes a legacy journal, never an inferred successful action.
type RecoveryVerificationExpectation struct {
	Version                     int
	ResetPassword               bool
	ResetMFA                    bool
	RemoveNonOwnerMemberships   bool
	ExpectedUserKeySHA256       string
	ExpectedMasterWrapperSHA256 string
}

func recoveryWitness(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func recoveryWitnessValid(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
func (e RecoveryVerificationExpectation) Validate(kind string) error {
	if e.Version != 1 || !recoveryWitnessValid(e.ExpectedUserKeySHA256) {
		return ErrValidation
	}
	if e.ResetPassword {
		if !recoveryWitnessValid(e.ExpectedMasterWrapperSHA256) {
			return ErrValidation
		}
	} else if e.ExpectedMasterWrapperSHA256 != "" {
		return ErrValidation
	}
	switch kind {
	case "administrator-recovery":
		if (!e.ResetPassword && !e.ResetMFA) || e.RemoveNonOwnerMemberships {
			return ErrValidation
		}
	case "emergency-takeover":
		if !e.ResetPassword || !e.ResetMFA || !e.RemoveNonOwnerMemberships {
			return ErrValidation
		}
	default:
		return ErrValidation
	}
	return nil
}

// DecodeRecoveryDispatch preserves legacy records for inspection, while a present
// versioned expectation must have every typed field and no unknown/duplicate key.
func DecodeRecoveryDispatch(raw []byte) (RecoveryDispatch, error) {
	var d RecoveryDispatch
	if len(raw) == 0 || len(raw) > 32768 || strictJSON(raw) != nil {
		return d, ErrProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil {
		return d, ErrProtocol
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return d, ErrProtocol
	}
	if value, present := object["Verification"]; present {
		var fields map[string]json.RawMessage
		if json.Unmarshal(value, &fields) != nil || len(fields) != 6 {
			return d, ErrProtocol
		}
		for _, key := range []string{"Version", "ResetPassword", "ResetMFA", "RemoveNonOwnerMemberships", "ExpectedUserKeySHA256", "ExpectedMasterWrapperSHA256"} {
			value, ok := fields[key]
			if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return d, ErrProtocol
			}
		}
		if !d.RequireTargetLogin || d.Verification.Validate(d.Kind) != nil {
			return d, ErrValidation
		}
	}
	return d, nil
}

func recoveryExpectation(kind string, key []byte, wrapper string, password, mfa bool) (RecoveryVerificationExpectation, error) {
	if len(key) != 64 {
		return RecoveryVerificationExpectation{}, ErrEncryption
	}
	e := RecoveryVerificationExpectation{Version: 1, ResetPassword: password, ResetMFA: mfa, RemoveNonOwnerMemberships: kind == "emergency-takeover", ExpectedUserKeySHA256: recoveryWitness(key)}
	if password {
		if wrapper == "" {
			return e, ErrValidation
		}
		e.ExpectedMasterWrapperSHA256 = recoveryWitness([]byte(wrapper))
	} else if wrapper != "" {
		return e, ErrValidation
	}
	return e, e.Validate(kind)
}
