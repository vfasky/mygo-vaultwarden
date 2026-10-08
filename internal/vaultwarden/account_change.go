// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
)

type AccountChangeKind string

const (
	AccountChangePassword AccountChangeKind = "password"
	AccountChangeKDF      AccountChangeKind = "kdf"
	AccountChangeEmail    AccountChangeKind = "email"
	AccountSecurityStamp  AccountChangeKind = "security-stamp"
	AccountDelete         AccountChangeKind = "delete"
	AccountPurge          AccountChangeKind = "purge"
	AccountRotateKey      AccountChangeKind = "rotate-user-key"
)

// AccountRecovery is SECRET material. Persist it encrypted, scoped and atomically
// with a durable pending-operation barrier BEFORE dispatch. Never put it in logs.
// OldVault retains the entire previous encrypted vault, including unknown fields.
// OldSession/OldUnlock preserve decryption even if the server is partially changed.
type AccountRecovery struct {
	Version       int               `json:"version"`
	OperationID   string            `json:"operationId"`
	Scope         Scope             `json:"scope"`
	Kind          AccountChangeKind `json:"kind"`
	OldRevision   string            `json:"oldRevision"`
	OldSession    []byte            `json:"oldSession"`
	OldUnlock     *PasswordUnlock   `json:"oldUnlock"`
	OldVault      []byte            `json:"oldVault"`
	NewUnlock     *PasswordUnlock   `json:"newUnlock,omitempty"`
	NewUserKey    []byte            `json:"newUserKey,omitempty"`
	NewWrappedKey string            `json:"newWrappedKey,omitempty"`
	Request       []byte            `json:"request"`
}

func (r *AccountRecovery) Close() {
	if r == nil {
		return
	}
	clear(r.OldSession)
	clear(r.OldVault)
	clear(r.NewUserKey)
	clear(r.Request)
	if r.OldUnlock != nil {
		clear(r.OldUnlock.Key)
	}
	if r.NewUnlock != nil {
		clear(r.NewUnlock.Key)
	}
	*r = AccountRecovery{}
}

// AccountChangeResult never claims a new server session exists. After dispatch
// the old session is revoked. Login + full sync + authenticated storage receipt
// are required before the integration may replace its current account snapshot.
type AccountChangeResult struct {
	OperationID      string
	Scope            Scope
	Kind             AccountChangeKind
	PreviousRevision string
	Dispatched       bool
	Confirmed        bool
	Unknown          bool
	RequireLogin     bool
}

// AccountChangePlan is single-use, bound to the current session/epoch/revision.
// Close on cancel. Lock ordering is Session.mu then plan.mu.
type AccountChangePlan struct {
	mu        sync.Mutex
	owner     *Session
	epoch     uint64
	revision  string
	kind      AccountChangeKind
	path      string
	recovery  AccountRecovery
	consumed  bool
	policy    *AccountPasswordPolicy
	proof     accountProof
	preflight func(context.Context) error
}

func (p *AccountChangePlan) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recovery.Close()
	p.proof = accountProof{}
	p.preflight = nil
	p.consumed = true
}
func (p *AccountChangePlan) Kind() AccountChangeKind {
	if p == nil {
		return ""
	}
	return p.kind
}
func (p *AccountChangePlan) ConfirmationText() string {
	if p == nil {
		return ""
	}
	return string(p.kind)
}

func (s *Session) accountPlanLocked(vault *VaultData, kind AccountChangeKind, path string, body []byte) (*AccountChangePlan, error) {
	if _, err := s.snapshotPoliciesLocked(vault); err != nil {
		return nil, err
	}
	old, err := s.savedLocked()
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(vault)
	if err != nil {
		clear(old)
		return nil, ErrProtocol
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		clear(old)
		clear(encoded)
		return nil, ErrEncryption
	}
	return &AccountChangePlan{owner: s, epoch: s.authorizationEpoch, revision: s.authorizationRevision, kind: kind, path: path, recovery: AccountRecovery{
		Version: 1, OperationID: hex.EncodeToString(id), Scope: vault.Scope, Kind: kind, OldRevision: s.authorizationRevision, OldSession: old, OldUnlock: &PasswordUnlock{Config: s.passwordUnlock.Config, Key: append([]byte(nil), s.passwordUnlock.Key...)}, OldVault: encoded, Request: append([]byte(nil), body...),
	}}, nil
}

type accountAuthentication struct {
	Salt string `json:"salt"`
	KDF  KDF    `json:"kdf"`
	Hash string `json:"masterPasswordAuthenticationHash"`
}
type accountUnlock struct {
	Salt string `json:"salt"`
	KDF  KDF    `json:"kdf"`
	Key  string `json:"masterKeyWrappedUserKey"`
}

// PrepareAccountCredentials verifies current password locally and with the
// server, consumes the actual merged type-1 policy and rewraps the SAME user key.
// Email changes preserve the password; KDF changes preserve email and password.
func (s *Session) PrepareAccountCredentials(ctx context.Context, vault *VaultData, kind AccountChangeKind, oldPassword, newPassword []byte, newEmail string, kdf KDF, hint, emailToken string, persist func(SessionCheckpoint) error) (*AccountChangePlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err = s.snapshotPoliciesLocked(vault); err != nil {
		return nil, err
	}
	if s.passwordUnlock == nil {
		return nil, ErrExpired
	}
	if kind != AccountChangePassword && kind != AccountChangeKDF && kind != AccountChangeEmail {
		return nil, ErrValidation
	}
	email := s.email
	switch kind {
	case AccountChangePassword:
		kdf = s.passwordUnlock.Config.KDF
	case AccountChangeKDF:
		newPassword = oldPassword
	case AccountChangeEmail:
		email, err = accountEmail(newEmail)
		if err != nil {
			return nil, err
		}
		if email == s.email || len(emailToken) > 16384 {
			return nil, ErrValidation
		}
		newPassword = oldPassword
		kdf = s.passwordUnlock.Config.KDF
		kdf.Salt = nil
	}
	if err = accountNewKDF(kdf); err != nil {
		return nil, err
	}
	if len(hint) > 1024 {
		return nil, ErrValidation
	}
	// Refresh/checkpoint may replace the trusted revision, so check the complete
	// snapshot again after server verification before creating a bound plan.
	policy, err := s.accountPolicyLocked(ctx, oldPassword, persist)
	if err != nil {
		return nil, err
	}
	if kind == AccountChangePassword {
		if err = (AccountPasswordPolicy{MinLength: 12}).Check(ctx, newPassword, email, false); err != nil {
			return nil, err
		}
	}
	if err = policy.Check(ctx, newPassword, email, false); err != nil {
		return nil, err
	}
	if _, err = s.accountProfileLocked(ctx, "GET", "/api/accounts/profile", nil, persist); err != nil {
		return nil, err
	}
	master, err := DeriveMaster(newPassword, email, kdf)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	stretched, err := StretchMaster(master)
	if err != nil {
		return nil, err
	}
	defer clear(stretched)
	wrapped, err := EncryptString(s.key, stretched)
	if err != nil {
		return nil, err
	}
	proof, err := s.accountProofLocked(AccountSensitiveInput{Password: oldPassword})
	if err != nil {
		return nil, err
	}
	hash := AuthorizationHash(master, newPassword)
	var payload any
	if kind == AccountChangeEmail {
		payload = map[string]string{"masterPasswordHash": proof.Hash, "newEmail": email, "key": wrapped, "newMasterPasswordHash": hash, "token": emailToken}
	} else {
		payload = struct {
			Hash   string                `json:"masterPasswordHash"`
			Hint   string                `json:"masterPasswordHint"`
			Auth   accountAuthentication `json:"authenticationData"`
			Unlock accountUnlock         `json:"unlockData"`
		}{proof.Hash, hint, accountAuthentication{email, kdf, hash}, accountUnlock{email, kdf, wrapped}}
	}
	body, _ := json.Marshal(payload)
	defer clear(body)
	plan, err := s.accountPlanLocked(vault, kind, "/api/accounts/"+string(kind), body)
	if err != nil {
		return nil, err
	}
	unlock, err := snapshotUnlockKey(master)
	if err != nil {
		plan.Close()
		return nil, err
	}
	plan.policy = &policy
	plan.proof = proof
	plan.recovery.NewUnlock = &PasswordUnlock{Config: PasswordUnlockConfig{Email: email, KDF: kdf}, Key: unlock}
	plan.recovery.NewWrappedKey = wrapped
	return plan, nil
}
func (s *Session) PrepareAccountDestructive(ctx context.Context, vault *VaultData, kind AccountChangeKind, input AccountSensitiveInput, persist func(SessionCheckpoint) error) (*AccountChangePlan, error) {
	path := "/api/accounts/" + string(kind)
	if kind == AccountPurge {
		path = "/api/ciphers/purge"
	} else if kind != AccountDelete && kind != AccountSecurityStamp {
		return nil, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err = s.snapshotPoliciesLocked(vault); err != nil {
		return nil, err
	}
	if _, err = s.accountProfileLocked(ctx, "GET", "/api/accounts/profile", nil, persist); err != nil {
		return nil, err
	}
	proof, err := s.accountProofLocked(input)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(proof)
	defer clear(body)
	return s.accountPlanLocked(vault, kind, path, body)
}

// AccountRecoveryPersistence is a privileged storage adapter. A nil adapter or
// persistence failure blocks dispatch. It must save a deep copy, encrypted,
// before returning, and revoke offline/AutoFill authority in that same commit.
// The callback may not call Session methods (the session lock is held).
type AccountRecoveryPersistence func(AccountRecovery) error

func (s *Session) CommitAccountChange(ctx context.Context, plan *AccountChangePlan, confirmation string, persist func(SessionCheckpoint) error, saveRecovery AccountRecoveryPersistence) (AccountChangeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return AccountChangeResult{}, err
	}
	defer done()
	if plan == nil {
		return AccountChangeResult{}, ErrValidation
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	result := AccountChangeResult{OperationID: plan.recovery.OperationID, Scope: plan.recovery.Scope, Kind: plan.kind, PreviousRevision: plan.revision}
	if plan.owner != s || plan.consumed || plan.epoch != s.authorizationEpoch || plan.revision != s.authorizationRevision {
		return result, ErrExpired
	}
	if confirmation != string(plan.kind) || saveRecovery == nil {
		return result, ErrValidation
	}
	if _, err = s.accountProfileLocked(ctx, "GET", "/api/accounts/profile", nil, persist); err != nil {
		return result, err
	}
	if plan.policy != nil {
		current, err := s.accountPolicyProofLocked(ctx, plan.proof, persist)
		if err != nil {
			return result, err
		}
		if current != *plan.policy {
			return result, ErrConflict
		}
	}
	if plan.preflight != nil {
		if err = plan.preflight(ctx); err != nil {
			return result, err
		}
	}
	guard := func() error {
		if ctx.Err() != nil {
			return ErrCancelled
		}
		if plan.epoch != s.authorizationEpoch || plan.revision != s.authorizationRevision {
			return ErrExpired
		}
		// Recheck immediately before dispatch, after refresh/checkpoint.
		if err := saveRecovery(plan.recovery); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ErrCancelled
		}
		plan.consumed = true
		result.Dispatched = true
		return nil
	}
	status, _, err := s.authenticatedGuardedLocked(ctx, "POST", plan.path, "application/json", string(plan.recovery.Request), persist, guard)
	if !result.Dispatched {
		return result, err
	}
	// No blind retries, including definite HTTP errors: rotate/purge/delete may
	// have made partial changes. The durable recovery record remains authoritative.
	result.RequireLogin = true
	result.Confirmed = err == nil && status == 200 && ctx.Err() == nil
	result.Unknown = !result.Confirmed
	s.accountInvalidateLocked()
	plan.recovery.Close()
	plan.proof = accountProof{}
	plan.preflight = nil
	if !result.Confirmed {
		if err == nil {
			err = mutationStatusError(status)
		}
		return result, &MutationUncertainError{Cause: err}
	}
	return result, nil
}
func (s *Session) accountInvalidateLocked() {
	clear(s.key)
	s.key = nil
	if s.passwordUnlock != nil {
		clear(s.passwordUnlock.Key)
		s.passwordUnlock = nil
	}
	s.access = ""
	s.refresh = ""
	s.closed = true
	s.advanceAuthorizationLocked()
	s.authorizationRevision = ""
	s.offlinePolicies = nil
	s.checkpointPolicies = nil
	s.writePolicies = nil
}
