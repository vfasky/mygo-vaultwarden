// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
)

// This JSON is secret material, carried only inside the encrypted snapshot.
// Access tokens and the raw master password are deliberately not persisted.
type savedSession struct {
	Version        int             `json:"version"`
	Scope          Scope           `json:"scope"`
	Email          string          `json:"email"`
	DeviceID       string          `json:"deviceID"`
	RefreshToken   string          `json:"refreshToken"`
	WrappedKey     string          `json:"wrappedKey"`
	UserKey        []byte          `json:"userKey"`
	PasswordUnlock *PasswordUnlock `json:"passwordUnlock"`
}

// SessionCheckpoint is borrowed by the callback, then cleared by the caller.
// A callback must durably save a rotated refresh token before Sync continues.
type SessionCheckpoint struct {
	Scope     Scope
	Session   []byte
	UnlockKey []byte
	receipt   *checkpointPolicyReceipt
}

func (s *Session) savedLocked() ([]byte, error) {
	if s.closed || s.account == "" || s.passwordUnlock == nil {
		return nil, ErrExpired
	}
	state := savedSession{Version: 1, Scope: Scope{Server: s.client.base.String(), Account: s.account},
		Email: s.email, DeviceID: s.client.deviceID, RefreshToken: s.refresh,
		WrappedKey: s.wrapped, UserKey: s.key, PasswordUnlock: s.passwordUnlock}
	data, err := json.Marshal(state)
	if err != nil || len(data) > 64*1024 {
		clear(data)
		return nil, ErrProtocol
	}
	return data, nil
}

func (s *Session) checkpointLocked(persist func(SessionCheckpoint) error) error {
	// This callback persists isolation, not a token-only update. Its result may
	// be unknown; neither success nor failure can retain old offline authority.
	defer func() {
		s.offlinePolicies = nil
		s.checkpointPolicies = nil
		s.advanceAuthorizationLocked()
	}()
	return s.checkpointWithReceiptLocked(persist, nil)
}

func (s *Session) checkpointWithReceiptLocked(persist func(SessionCheckpoint) error, receipt *checkpointPolicyReceipt) error {
	if persist == nil {
		return nil
	}
	data, err := s.savedLocked()
	if err != nil {
		return err
	}
	defer clear(data)
	key := append([]byte(nil), s.passwordUnlock.Key...)
	defer clear(key)
	return persist(SessionCheckpoint{Scope: Scope{Server: s.client.base.String(), Account: s.account}, Session: data, UnlockKey: key, receipt: receipt})
}

// RestoreSession restores network credentials without installing snapshot policy
// authority. It performs no network request; the next Sync refreshes the access
// token. Trusted snapshot callers use RestoreSessionFromAuthenticatedSnapshot.
func RestoreSession(data []byte, scope Scope, config *PasswordUnlockConfig) (*Session, error) {
	if len(data) == 0 || len(data) > 64*1024 || config == nil {
		return nil, ErrProtocol
	}
	var state savedSession
	defer func() {
		clear(state.UserKey)
		if state.PasswordUnlock != nil {
			clear(state.PasswordUnlock.Key)
		}
	}()
	if json.Unmarshal(data, &state) != nil || state.Version != 1 || state.Scope != scope ||
		state.Scope.Account == "" || len(state.Scope.Account) > 256 ||
		state.Email == "" || state.Email != NormalizeEmail(state.Email) || len(state.Email) > 1024 ||
		state.RefreshToken == "" || len(state.RefreshToken) > 16384 ||
		state.WrappedKey == "" || len(state.WrappedKey) > 4096 || len(state.UserKey) != 64 ||
		state.PasswordUnlock == nil || len(state.PasswordUnlock.Key) != 32 || state.PasswordUnlock.Config.Email != state.Email {
		return nil, ErrIdentity
	}
	storedConfig, _ := json.Marshal(state.PasswordUnlock.Config)
	expectedConfig, _ := json.Marshal(config)
	if !bytes.Equal(storedConfig, expectedConfig) {
		return nil, ErrIdentity
	}
	client, err := NewClient(scope.Server, state.DeviceID)
	if err != nil || client.base.String() != scope.Server {
		return nil, ErrIdentity
	}
	return &Session{client: client, email: state.Email, account: scope.Account, wrapped: state.WrappedKey,
		refresh: state.RefreshToken, key: append([]byte(nil), state.UserKey...),
		passwordUnlock: &PasswordUnlock{Config: state.PasswordUnlock.Config, Key: append([]byte(nil), state.PasswordUnlock.Key...)}}, nil
}
