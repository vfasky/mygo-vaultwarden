// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
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

// Vaultwarden 1.37.4 reports its stale cipher check as HTTP 400. Recognize
// only its exact fixed message; never surface arbitrary server response text.
func cipherUpdateStatusError(status int, data []byte) error {
	if status == http.StatusBadRequest {
		var response struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &response) == nil && response.Message == "The client copy of this cipher is out of date. Resync the client and try again." {
			return ErrConflict
		}
	}
	return mutationStatusError(status)
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
	s.writePolicies = nil
	return operation, func() {
		s.writePolicies = nil
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
	receipt := &checkpointPolicyReceipt{prior: s.checkpointPolicies}
	if err := s.checkpointWithReceiptLocked(persist, receipt); err != nil {
		s.offlinePolicies = nil
		s.checkpointPolicies = nil
		return err
	}
	s.checkpointPending = false
	// Grants always expire, even when a same-content receipt continues policy.
	s.authorizationEpoch++
	s.offlinePolicies = nil
	s.checkpointPolicies = nil
	if p := receipt.prior; p != nil && receipt.revision != "" {
		p.epoch, p.revision = s.authorizationEpoch, receipt.revision
		s.authorizationRevision = receipt.revision
		s.offlinePolicies = p
	}
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
	return s.authenticatedGuardedLocked(ctx, method, endpoint, contentType, body, persist, nil)
}

// guard runs after refresh/checkpoint, immediately before dispatch. A slow key
// store or refresh must not extend an expired item authorization.
func (s *Session) authenticatedGuardedLocked(ctx context.Context, method, endpoint, contentType, body string, persist func(SessionCheckpoint) error, guard func() error) (int, []byte, error) {
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
	if method != http.MethodGet && method != http.MethodHead && s.writePolicies != nil {
		if err := s.checkOperationPoliciesLocked(ctx, s.writePolicies); err != nil {
			return 0, nil, err
		}
	}
	if guard != nil {
		if err := guard(); err != nil {
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
