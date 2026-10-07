// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"strings"
)

// MFAManageOperation is a closed endpoint set. Fields never accept a password hash.
type MFAManageOperation string

const (
	MFAList       MFAManageOperation = "list"
	MFARecovery   MFAManageOperation = "get-recover"
	MFADisable    MFAManageOperation = "disable"
	MFARequestOTP MFAManageOperation = "request-otp"
	MFAVerifyOTP  MFAManageOperation = "verify-otp"
)

// MFAManage uses the account module's local password verification and protected
// action proof. Returned setup secrets/recovery codes must not be logged.
// Mutations are never retried: a transport failure can mean an unknown outcome.
func (s *Session) MFAManage(ctx context.Context, op MFAManageOperation, input AccountSensitiveInput, fields map[string]json.RawMessage, confirmed bool, persist func(SessionCheckpoint) error) (json.RawMessage, error) {
	method, endpoint, allowed, proofNeeded, mutation := "POST", "/api/two-factor/"+string(op), "", true, false
	switch op {
	case MFAList:
		method, endpoint, proofNeeded = "GET", "/api/two-factor", false
	case MFARecovery:
	case MFADisable:
		method, allowed, mutation = "PUT", "type", true
	case MFARequestOTP:
		endpoint, proofNeeded = "/api/accounts/request-otp", false
	case MFAVerifyOTP:
		endpoint, allowed, proofNeeded = "/api/accounts/verify-otp", "otp", false
	case "get-authenticator", "get-email", "get-duo", "get-yubikey", "get-webauthn", "get-webauthn-challenge":
	case "authenticator":
		allowed, mutation = "key token", true
	case "send-email":
		allowed, mutation = "email", true
	case "email":
		method, allowed, mutation = "PUT", "email token", true
	case "duo":
		allowed, mutation = "host clientSecret clientId", true
	case "yubikey":
		allowed, mutation = "key1 key2 key3 key4 key5 nfc", true
	case "webauthn":
		allowed, mutation = "id name deviceResponse", true
	case "delete-webauthn":
		method, endpoint, allowed, mutation = "DELETE", "/api/two-factor/webauthn", "id", true
	default:
		return nil, ErrValidation
	}
	if (mutation || op == MFARecovery) && !confirmed {
		return nil, ErrValidation
	}
	payload := map[string]json.RawMessage{}
	for k, v := range fields {
		if !strings.Contains(" "+allowed+" ", " "+k+" ") || k == "" || !json.Valid(v) {
			return nil, ErrValidation
		}
		payload[k] = append(json.RawMessage(nil), v...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if proofNeeded {
		proof, err := s.accountProofLocked(input)
		if err != nil {
			return nil, err
		}
		if op == "delete-webauthn" && proof.Hash == "" {
			return nil, ErrValidation
		}
		if proof.Hash != "" {
			payload["masterPasswordHash"], _ = json.Marshal(proof.Hash)
		}
		if proof.OTP != "" {
			payload["otp"], _ = json.Marshal(proof.OTP)
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrValidation
	}
	defer clear(body)
	for _, v := range payload {
		defer clear(v)
	}
	status, data, err := s.authenticatedLocked(ctx, method, endpoint, "application/json", string(body), persist)
	if err != nil {
		if mutation {
			return nil, &MutationUncertainError{Cause: err}
		}
		return nil, err
	}
	if status != 200 && status != 204 {
		if mutation {
			return nil, &MutationUncertainError{Cause: statusError(status)}
		}
		return nil, statusError(status)
	}
	if len(data) != 0 && !json.Valid(data) {
		return nil, ErrProtocol
	}
	return data, nil
}
