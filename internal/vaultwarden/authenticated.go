// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"net/http"
	"time"
)

// statusError never includes server-controlled text or credentials.
func statusError(status int) error {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return ErrValidation
	case http.StatusUnauthorized:
		return ErrExpired
	case http.StatusForbidden:
		return ErrPermission
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict, http.StatusPreconditionFailed:
		return ErrConflict
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return ErrNetwork
	}
}

// A successful but unrecognized status, or server failure, cannot prove that a
// mutation was rolled back. Never offer it as an ordinary retryable failure.
func mutationStatusError(status int) error {
	if (status >= 200 && status < 300) || status >= 500 {
		return &MutationUncertainError{Cause: statusError(status)}
	}
	return statusError(status)
}

// beginOperationLocked gives Close a way to cancel the network operation before
// waiting for the session mutex. The caller owns mu for the operation's lifetime.
func (s *Session) beginOperationLocked(ctx context.Context) (context.Context, func(), error) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.stopping || s.closed {
		return nil, nil, ErrExpired
	}
	if ctx.Err() != nil {
		return nil, nil, ErrCancelled
	}
	operation, cancel := context.WithCancel(ctx)
	s.cancelOperation = cancel
	return operation, func() {
		cancel()
		s.operationMu.Lock()
		s.cancelOperation = nil
		s.operationMu.Unlock()
	}, nil
}

func (s *Session) persistPendingLocked(persist func(SessionCheckpoint) error) error {
	if !s.checkpointPending {
		return nil
	}
	if persist == nil {
		return ErrCheckpoint
	}
	if err := s.checkpointLocked(persist); err != nil {
		return err
	}
	s.checkpointPending = false
	return nil
}

func (s *Session) refreshAndCheckpointLocked(ctx context.Context, persist func(SessionCheckpoint) error) error {
	// A bound, durable session may not rotate a token without its persistence hook.
	if s.account != "" && s.passwordUnlock != nil && persist == nil {
		return ErrCheckpoint
	}
	if err := s.refreshLocked(ctx); err != nil {
		return err
	}
	if s.account != "" && s.passwordUnlock != nil {
		s.checkpointPending = true
		return s.persistPendingLocked(persist)
	}
	return nil
}

// authenticatedLocked is internal to typed API operations. Mutations are never
// retried, including a 401: the caller must reconcile server state before retry.
func (s *Session) authenticatedLocked(ctx context.Context, method, endpoint, contentType, body string, persist func(SessionCheckpoint) error) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, ErrCancelled
	}
	if err := s.persistPendingLocked(persist); err != nil {
		return 0, nil, err
	}
	if time.Until(s.expires) < 30*time.Second {
		if err := s.refreshAndCheckpointLocked(ctx, persist); err != nil {
			return 0, nil, err
		}
	}
	status, data, err := s.client.request(ctx, method, endpoint, contentType, body, s.access)
	if err != nil {
		if method != http.MethodGet && method != http.MethodHead {
			return status, nil, &MutationUncertainError{Cause: err}
		}
		return status, nil, err
	}
	if status == http.StatusUnauthorized && method == http.MethodGet {
		if err := s.refreshAndCheckpointLocked(ctx, persist); err != nil {
			return status, nil, err
		}
		return s.client.request(ctx, method, endpoint, contentType, body, s.access)
	}
	return status, data, nil
}
