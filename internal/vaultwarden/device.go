// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/url"
)

// Device is server metadata; none of its strings is trusted markup.
type Device struct {
	ID           string `json:"id"`
	Identifier   string `json:"identifier"`
	Name         string `json:"name"`
	Type         int    `json:"type"`
	CreationDate string `json:"creationDate"`
	RevisionDate string `json:"revisionDate"`
}

// deviceCall uses the existing cancellable authenticated operation and durable
// refresh checkpoint. It never retries a mutation or exposes response errors.
func (s *Session) deviceCall(ctx context.Context, scope Scope, method, endpoint string, input, output any, persist func(SessionCheckpoint) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err = s.requireScopeLocked(scope); err != nil {
		return err
	}
	var body []byte
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return ErrValidation
		}
		defer clear(body)
	}
	status, data, err := s.authenticatedLocked(ctx, method, endpoint, "application/json", string(body), persist)
	if err != nil {
		return err
	}
	defer clear(data)
	if status != 200 && status != 204 {
		if method != "GET" {
			return mutationStatusError(status)
		}
		return statusError(status)
	}
	if ctx.Err() != nil || !s.itemSessionActiveLocked() {
		if method != "GET" {
			return &MutationUncertainError{Cause: ErrExpired}
		}
		return ErrExpired
	}
	if output != nil && (len(data) > 1024*1024 || strictJSON(data) != nil || json.Unmarshal(data, output) != nil) {
		if method != "GET" {
			return &MutationUncertainError{Cause: ErrProtocol}
		}
		return ErrProtocol
	}
	return nil
}
func (s *Session) Devices(ctx context.Context, scope Scope, persist func(SessionCheckpoint) error) ([]Device, error) {
	var list struct {
		Data              []Device
		ContinuationToken *string
	}
	if err := s.deviceCall(ctx, scope, "GET", "/api/devices", nil, &list, persist); err != nil {
		return nil, err
	}
	if list.Data == nil || len(list.Data) > 10000 || list.ContinuationToken != nil {
		return nil, ErrProtocol
	}
	return list.Data, nil
}
func (s *Session) CurrentDevice(ctx context.Context, scope Scope, persist func(SessionCheckpoint) error) (Device, error) {
	var device Device
	err := s.deviceCall(ctx, scope, "GET", "/api/devices/identifier/"+url.PathEscape(s.client.deviceID), nil, &device, persist)
	return device, err
}
func (s *Session) RegisterDevicePushToken(ctx context.Context, scope Scope, token string, persist func(SessionCheckpoint) error) error {
	if len(token) == 0 || len(token) > 4096 {
		return ErrValidation
	}
	return s.deviceCall(ctx, scope, "PUT", "/api/devices/identifier/"+url.PathEscape(s.client.deviceID)+"/token", struct {
		PushToken string `json:"pushToken"`
	}{token}, nil, persist)
}

// ClearDevicePushToken clears only this device identifier's push registration.
// Vaultwarden may clear that identifier across accounts. This is NOT logout or
// session revocation and does not implement an APNs delivery service.
func (s *Session) ClearDevicePushToken(ctx context.Context, scope Scope, confirmed bool, persist func(SessionCheckpoint) error) error {
	if !confirmed {
		return ErrPermission
	}
	return s.deviceCall(ctx, scope, "PUT", "/api/devices/identifier/"+url.PathEscape(s.client.deviceID)+"/clear-token", nil, nil, persist)
}
