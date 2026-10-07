// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// RecoveryDispatch is borrowed by BeforeDispatch while the Session is locked.
// It identifies the target independently from the actor. The host must durably
// isolate any locally stored target account/AutoFill before returning success.
// Never call Session methods from this callback. This is not AccountRecovery:
// an administrator has no target oldSession/oldUnlock to journal.
type RecoveryDispatch struct {
	OperationID        string
	Actor              Scope
	Target             Scope
	Kind               string
	ResourceID         string
	PreviousRevision   string
	AuthorizationEpoch uint64
	OrganizationID     string
	MembershipID       string
	ConfirmedImpact    string
	TargetEmail        string
	CounterpartyID     string
	CounterpartyEmail  string
	EmergencyType      int
	WaitTimeDays       int
	RequireTargetLogin bool
}
type RecoveryOperationResult struct {
	RecoveryDispatch
	Dispatched, Confirmed, Unknown bool
	// IsolationAttempted requires host query even when no HTTP was dispatched.
	IsolationAttempted bool
}
type RecoveryBeforeDispatch func(RecoveryDispatch) error

// RecoveryPlan is single-use, bound to a Session and its authorization epoch.
// Close cancels an uncommitted plan and clears its encrypted request/proof.
type RecoveryPlan struct {
	mu                                 sync.Mutex
	owner                              *Session
	epoch                              uint64
	record                             RecoveryDispatch
	method, path, confirmation, impact string
	body                               []byte
	consumed                           bool
	revalidate                         func(context.Context, func(SessionCheckpoint) error, func() error) error
}

func (p *RecoveryPlan) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.body)
	p.body = nil
	p.consumed = true
	p.revalidate = nil
}
func (p *RecoveryPlan) ConfirmationText() string {
	if p == nil {
		return ""
	}
	return p.confirmation
}
func (p *RecoveryPlan) Summary() RecoveryDispatch {
	if p == nil {
		return RecoveryDispatch{}
	}
	return p.record
}
func (p *RecoveryPlan) Impact() string {
	if p == nil {
		return ""
	}
	return p.impact
}
func (s *Session) recoveryPlanLocked(kind, method, path, resource, target, impact string, body any) (*RecoveryPlan, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, ErrProtocol
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		clear(encoded)
		return nil, ErrEncryption
	}
	return &RecoveryPlan{owner: s, epoch: s.authorizationEpoch, method: method, path: path, body: encoded, confirmation: kind, impact: impact, record: RecoveryDispatch{OperationID: hex.EncodeToString(nonce), Actor: Scope{Server: s.client.base.String(), Account: s.account}, Target: Scope{Server: s.client.base.String(), Account: target}, Kind: kind, ResourceID: resource, PreviousRevision: s.authorizationRevision, AuthorizationEpoch: s.authorizationEpoch, ConfirmedImpact: impact}}, nil
}

// CommitRecoveryOperation never automatically retries a mutation, including an
// HTTP rejection: upstream may have persisted before SMTP or a later step fails.
// A host callback is mandatory even for grants, so unknown operations survive UI
// recreation. Completion must never silently restore a target's offline lease.
func (s *Session) CommitRecoveryOperation(ctx context.Context, p *RecoveryPlan, confirmation string, persist func(SessionCheckpoint) error, before RecoveryBeforeDispatch) (RecoveryOperationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return RecoveryOperationResult{}, err
	}
	defer done()
	if p == nil {
		return RecoveryOperationResult{}, ErrValidation
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result := RecoveryOperationResult{RecoveryDispatch: p.record}
	guard := s.recoveryGuardLocked(p.epoch, p.record.PreviousRevision)
	if p.owner != s || p.consumed {
		return result, ErrExpired
	}
	if err = guard(); err != nil {
		return result, err
	}
	if confirmation != p.confirmation || before == nil {
		return result, ErrValidation
	}
	if p.revalidate != nil {
		if err = p.revalidate(ctx, persist, guard); err != nil {
			return result, err
		}
	}
	dispatchGuard := func() error {
		if err := guard(); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrCancelled
		}
		// Consume before the durable callback: its result itself can be unknown.
		p.consumed = true
		result.IsolationAttempted = true
		if err := before(p.record); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrCancelled
		}
		result.Dispatched = true
		return nil
	}
	status, _, err := s.authenticatedGuardedLocked(ctx, p.method, p.path, "application/json", string(p.body), persist, dispatchGuard)
	if p.consumed {
		clear(p.body)
		p.body = nil
		p.revalidate = nil
	}
	if !result.Dispatched {
		return result, err
	}
	result.Confirmed = err == nil && (status == 200 || status == 204) && ctx.Err() == nil
	result.Unknown = !result.Confirmed
	if p.record.RequireTargetLogin && p.record.Target == p.record.Actor {
		s.accountInvalidateLocked()
	}
	if !result.Confirmed {
		if err == nil {
			err = mutationStatusError(status)
		}
		return result, &MutationUncertainError{Cause: err}
	}
	return result, nil
}
