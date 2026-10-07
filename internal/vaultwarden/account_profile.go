// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"regexp"
)

type AccountProfile struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	Name          string  `json:"name"`
	EmailVerified bool    `json:"emailVerified"`
	AvatarColor   *string `json:"avatarColor"`
	Key           string  `json:"key"`
}

func (s *Session) accountProfileLocked(ctx context.Context, method, path string, payload any, persist func(SessionCheckpoint) error) (AccountProfile, error) {
	body, _ := json.Marshal(payload)
	defer clear(body)
	status, data, err := s.authenticatedLocked(ctx, method, path, "application/json", string(body), persist)
	if err != nil {
		return AccountProfile{}, err
	}
	if status != 200 {
		if method != "GET" {
			return AccountProfile{}, mutationStatusError(status)
		}
		return AccountProfile{}, statusError(status)
	}
	var p AccountProfile
	if strictJSON(data) != nil || json.Unmarshal(data, &p) != nil || p.ID != s.account || NormalizeEmail(p.Email) != s.email || p.Key != s.wrapped {
		if method != "GET" {
			return AccountProfile{}, &MutationUncertainError{Cause: ErrIdentity}
		}
		return AccountProfile{}, ErrIdentity
	}
	return p, nil
}
func (s *Session) AccountProfile(ctx context.Context, persist func(SessionCheckpoint) error) (AccountProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return AccountProfile{}, err
	}
	defer done()
	return s.accountProfileLocked(ctx, "GET", "/api/accounts/profile", nil, persist)
}
func (s *Session) AccountUpdateProfile(ctx context.Context, name string, persist func(SessionCheckpoint) error) (AccountProfile, error) {
	if len(name) > 50 {
		return AccountProfile{}, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return AccountProfile{}, err
	}
	defer done()
	if _, err = s.accountProfileLocked(ctx, "GET", "/api/accounts/profile", nil, persist); err != nil {
		return AccountProfile{}, err
	}
	return s.accountProfileLocked(ctx, "PUT", "/api/accounts/profile", map[string]string{"name": name}, persist)
}
func (s *Session) AccountUpdateAvatar(ctx context.Context, color *string, persist func(SessionCheckpoint) error) (AccountProfile, error) {
	if color != nil && !regexp.MustCompile(`^#[0-9a-fA-F]{6}$`).MatchString(*color) {
		return AccountProfile{}, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return AccountProfile{}, err
	}
	defer done()
	if _, err = s.accountProfileLocked(ctx, "GET", "/api/accounts/profile", nil, persist); err != nil {
		return AccountProfile{}, err
	}
	return s.accountProfileLocked(ctx, "PUT", "/api/accounts/avatar", map[string]*string{"avatarColor": color}, persist)
}
func (s *Session) AccountSendVerificationEmail(ctx context.Context, persist func(SessionCheckpoint) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer done()
	status, _, err := s.authenticatedLocked(ctx, "POST", "/api/accounts/verify-email", "application/json", "{}", persist)
	if err != nil {
		return err
	}
	if status != 200 {
		return mutationStatusError(status)
	}
	return nil
}

type AccountAPIKey struct {
	APIKey       string `json:"apiKey"`
	RevisionDate string `json:"revisionDate"`
}

func (s *Session) AccountAPIKey(ctx context.Context, input AccountSensitiveInput, rotate, confirmed bool, persist func(SessionCheckpoint) error) (AccountAPIKey, error) {
	if !confirmed {
		return AccountAPIKey{}, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return AccountAPIKey{}, err
	}
	defer done()
	proof, err := s.accountProofLocked(input)
	if err != nil {
		return AccountAPIKey{}, err
	}
	body, _ := json.Marshal(proof)
	defer clear(body)
	path := "/api/accounts/api-key"
	if rotate {
		path = "/api/accounts/rotate-api-key"
	}
	status, data, err := s.authenticatedLocked(ctx, "POST", path, "application/json", string(body), persist)
	if err != nil {
		return AccountAPIKey{}, err
	}
	if status != 200 {
		return AccountAPIKey{}, mutationStatusError(status)
	}
	var result AccountAPIKey
	if json.Unmarshal(data, &result) != nil || result.APIKey == "" || len(result.APIKey) > 1024 {
		return result, &MutationUncertainError{Cause: ErrProtocol}
	}
	return result, nil
}
func (s *Session) AccountRequestEmailChange(ctx context.Context, password []byte, email string, persist func(SessionCheckpoint) error) error {
	email, err := accountEmail(email)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer done()
	proof, err := s.accountProofLocked(AccountSensitiveInput{Password: password})
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"masterPasswordHash": proof.Hash, "newEmail": email})
	defer clear(body)
	status, _, err := s.authenticatedLocked(ctx, "POST", "/api/accounts/email-token", "application/json", string(body), persist)
	if err != nil {
		return err
	}
	if status != 200 {
		return mutationStatusError(status)
	}
	return nil
}
