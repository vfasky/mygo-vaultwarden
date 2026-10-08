// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

var errTargetRecovery = errors.New("target recovery binding or receipt invalid")

type targetRecoveryBinding struct {
	OperationID        string            `json:"operationId"`
	Actor              vaultwarden.Scope `json:"actor"`
	Target             vaultwarden.Scope `json:"target"`
	StorageRevision    string            `json:"storageRevision"`
	HostEpoch          uint64            `json:"hostEpoch"`
	AuthorizationEpoch uint64            `json:"authorizationEpoch"`
	SummaryHash        string            `json:"summaryHash"`
}
type targetRecoveryRecord struct {
	Verification        *targetRecoveryResolution `json:"verification,omitempty"`
	Protection          *targetRecoveryProtection `json:"protection,omitempty"`
	Binding             targetRecoveryBinding     `json:"binding"`
	Summary             []byte                    `json:"summary"`
	Phase               string                    `json:"phase"`
	RequireTargetLogin  bool                      `json:"requireTargetLogin"`
	NoLocalTarget       bool                      `json:"noLocalTarget"`
	VerifiedVaultHash   string                    `json:"verifiedVaultHash,omitempty"`
	VerifiedSessionHash string                    `json:"verifiedSessionHash,omitempty"`
	VerifiedUnlockHash  string                    `json:"verifiedUnlockHash,omitempty"`
}

func (r *targetRecoveryRecord) Close() { clear(r.Summary); *r = targetRecoveryRecord{} }

type targetRecoveryResolution struct {
	Binding             targetRecoveryBinding `json:"binding"`
	ExpectedRevision    string                `json:"expectedRevision"`
	Target              vaultwarden.Scope     `json:"target"`
	VaultHash           string                `json:"vaultHash"`
	SessionHash         string                `json:"sessionHash"`
	UnlockHash          string                `json:"unlockHash"`
	AuthorityHash       string                `json:"authorityHash"`
	KeyHash             string                `json:"keyHash"`
	MembershipHash      string                `json:"membershipHash"`
	MFAHash             string                `json:"mfaHash"`
	ConfirmationHash    string                `json:"confirmationHash"`
	AuthenticationEpoch uint64                `json:"authenticationEpoch"`
}

// Controller-owned evidence from this fresh authentication and full sync.
// Each digest must identify the actual verified data (including an explicit
// verified 'not applicable' result for MFA/membership), not arbitrary UI flags.
// The storage layer cannot attest remote server truth or validate other users' keys.
type targetRecoveryVerification struct {
	AuthorityHash, KeyHash, MembershipHash, MFAHash, ConfirmationHash string
	AuthenticationEpoch                                               uint64
}
type targetRecoveryStorage struct {
	runtime      *targetRecoveryRuntimeAuthority
	receipt      *snapshotStatus
	snapshotID   string
	login        *targetRecoveryResolution
	loginVault   *vaultwarden.VaultData
	loginSession []byte
	loginUnlock  *vaultwarden.PasswordUnlock
	localScope   *vaultwarden.Scope
	mu           sync.Mutex
	scope        vaultwarden.Scope
	revision     string
	epoch        uint64
	currentEpoch func() uint64
	key          []byte
	call         func(storageRequest) storageReply
	binding      *targetRecoveryBinding
	summary      []byte
}

func targetRecoveryHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func targetValidHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func newTargetRecoveryStorage(state *snapshotStatus, epoch uint64, currentEpoch func() uint64, key []byte, call func(storageRequest) storageReply) (*targetRecoveryStorage, error) {
	if state == nil || state.Scope == nil || !state.Available || state.Revision == "" || epoch == 0 || currentEpoch == nil || currentEpoch() != epoch || len(key) != 32 || call == nil {
		return nil, errTargetRecovery
	}
	return &targetRecoveryStorage{snapshotID: state.SnapshotID, localScope: state.Scope, scope: *state.Scope, revision: state.Revision, epoch: epoch, currentEpoch: currentEpoch, key: bytes.Clone(key), call: call}, nil
}
func (s *targetRecoveryStorage) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.runtime = nil
	s.receipt = nil
	clear(s.loginSession)
	if s.loginUnlock != nil {
		clear(s.loginUnlock.Key)
	}
	if s.loginVault != nil {
		clear(s.loginVault.Sync)
	}
	s.login = nil
	s.key = nil
	clear(s.summary)
	s.summary = nil
	s.binding = nil
}
func (s *targetRecoveryStorage) active() bool {
	return (len(s.key) == 32 || s.runtime != nil) && s.currentEpoch() != 0 && s.currentEpoch() == s.epoch
}
func (s *targetRecoveryStorage) request(operation string) storageRequest {
	scope := s.scope
	req := storageRequest{Operation: operation, Scope: &scope, ExpectedRevision: s.revision, UnlockKey: s.key, TargetBinding: s.binding}
	req.TargetRuntime = s.runtime
	if s.login != nil {
		proof := *s.login
		proof.ExpectedRevision = s.revision
		req.TargetLogin = &proof
		req.Vault = s.loginVault
		req.Session = s.loginSession
		req.PasswordUnlock = s.loginUnlock
	}
	return req
}
func validTargetRecord(r targetRecoveryRecord) bool {
	var d vaultwarden.RecoveryDispatch
	if len(r.Summary) > 32768 || json.Unmarshal(r.Summary, &d) != nil {
		return false
	}
	b := r.Binding
	return b.OperationID == d.OperationID && b.Actor == d.Actor && b.Target == d.Target && b.AuthorizationEpoch == d.AuthorizationEpoch && b.AuthorizationEpoch > 0 && b.HostEpoch > 0 && b.StorageRevision != "" && b.SummaryHash == targetRecoveryHash(r.Summary) && r.RequireTargetLogin == d.RequireTargetLogin && (r.Phase == "prepared" || r.Phase == "unknown" || r.Phase == "confirmed" || r.Phase == "not-dispatched" || r.Phase == "verified" || r.Phase == "resolved")
}
func (s *targetRecoveryStorage) receive(req storageRequest) (storageReply, error) {
	s.receipt = nil
	if !s.active() {
		return storageReply{}, errTargetRecovery
	}
	reply := s.call(req)
	if !s.active() {
		return storageReply{}, errTargetRecovery
	}
	if !reply.OK {
		return reply, reply.failure()
	}
	if reply.State == nil || (s.login == nil && s.runtime == nil && (reply.State.Scope == nil || *reply.State.Scope != s.scope)) || (!reply.State.TargetRecoveryPresent && req.Operation != "targetRecoveryPending") || reply.State.Revision == "" {
		return storageReply{}, errTargetRecovery
	}
	query := req.Operation == "targetRecoveryQuery" || req.Operation == "targetRecoveryPending" || req.Operation == "targetRecoveryInspectLocal"
	if query && reply.State.Revision != s.revision {
		return storageReply{}, errTargetRecovery
	}
	if !query && reply.State.Revision == s.revision {
		return storageReply{}, errTargetRecovery
	}
	if req.Operation == "targetRecoveryBegin" && s.runtime == nil && !reply.State.Available {
		return storageReply{}, errTargetRecovery
	}
	if (req.Operation == "targetRecoveryResolve" || req.Operation == "targetRecoveryResolveLocal") && (!reply.State.Available || reply.State.Scope == nil || *reply.State.Scope != req.TargetResolution.Target) {
		return storageReply{}, errTargetRecovery
	}
	if len(reply.TargetRecords) > 1024 {
		return storageReply{}, errTargetRecovery
	}
	seen := map[string]bool{}
	for _, record := range reply.TargetRecords {
		if !validTargetRecord(record) || seen[record.Binding.OperationID] || (record.Binding.Actor != s.scope && record.Binding.Target != s.scope) {
			return storageReply{}, errTargetRecovery
		}
		seen[record.Binding.OperationID] = true
	}
	if req.Operation != "targetRecoveryPending" {
		if len(reply.TargetRecords) != 1 || req.TargetBinding == nil || reply.TargetRecords[0].Binding != *req.TargetBinding {
			return storageReply{}, errTargetRecovery
		}
		r := reply.TargetRecords[0]
		if req.Operation == "targetRecoveryBegin" {
			local := r.RequireTargetLogin && s.localScope != nil && r.Binding.Target == *s.localScope
			if s.runtime == nil && ((local && (reply.State.SnapshotID == s.snapshotID || reply.State.Count != 0)) || (!local && reply.State.SnapshotID != s.snapshotID)) {
				return storageReply{}, errTargetRecovery
			}
		}
		if req.Operation == "targetRecoveryBegin" && (r.Phase != "prepared" || !bytes.Equal(r.Summary, req.TargetSummary) || r.NoLocalTarget != (s.localScope == nil || r.Binding.Target != *s.localScope) || reply.State.Revision == req.ExpectedRevision) {
			return storageReply{}, errTargetRecovery
		}
		if req.Operation == "targetRecoveryVerify" || req.Operation == "targetRecoveryResolve" || req.Operation == "targetRecoveryResolveLocal" {
			if r.Verification == nil || req.TargetResolution == nil || *r.Verification != *req.TargetResolution {
				return storageReply{}, errTargetRecovery
			}
		}
		if req.Operation == "targetRecoveryResult" && r.Phase != req.TargetPhase {
			return storageReply{}, errTargetRecovery
		}
		if req.Operation == "targetRecoveryVerify" && (r.Phase != "verified" || req.TargetResolution == nil || r.VerifiedVaultHash != req.TargetResolution.VaultHash || r.VerifiedSessionHash != req.TargetResolution.SessionHash || r.VerifiedUnlockHash != req.TargetResolution.UnlockHash) {
			return storageReply{}, errTargetRecovery
		}
		if (req.Operation == "targetRecoveryResolve" || req.Operation == "targetRecoveryResolveLocal") && (r.Phase != "resolved" || req.TargetResolution == nil || r.VerifiedVaultHash != req.TargetResolution.VaultHash || r.VerifiedSessionHash != req.TargetResolution.SessionHash || r.VerifiedUnlockHash != req.TargetResolution.UnlockHash || reply.Vault == nil || targetRecoveryHash(reply.Vault.Sync) != req.TargetResolution.VaultHash) {
			return storageReply{}, errTargetRecovery
		}
	}
	s.revision = reply.State.Revision
	rawState, _ := json.Marshal(reply.State)
	_ = json.Unmarshal(rawState, &s.receipt)
	s.snapshotID = reply.State.SnapshotID
	s.localScope = reply.State.Scope
	return reply, nil
}

// Exact RecoveryBeforeDispatch hook. It calls no Session methods or app fields.
// Unknown native/fsync/receipt failures remain errors: zero mutation POST.
func (s *targetRecoveryStorage) Begin(d vaultwarden.RecoveryDispatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active() || s.login != nil || s.binding != nil || d.Actor != s.scope || d.AuthorizationEpoch == 0 || d.PreviousRevision == "" || d.OperationID == "" || d.Kind == "" || (d.RequireTargetLogin && d.Target.Account == "") || d.Target.Server != s.scope.Server {
		return errTargetRecovery
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > 32768 {
		return errTargetRecovery
	}
	b := targetRecoveryBinding{d.OperationID, d.Actor, d.Target, s.revision, s.epoch, d.AuthorizationEpoch, targetRecoveryHash(raw)}
	// Keep the exact binding even on unknown commit, for explicit Query only.
	s.binding = &b
	s.summary = raw
	req := s.request("targetRecoveryBegin")
	req.TargetSummary = raw
	_, err = s.receive(req)
	return err
}

// Reopen selects a durable operation after Pending on a new authenticated adapter.
func (s *targetRecoveryStorage) Select(record targetRecoveryRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active() || s.binding != nil || !validTargetRecord(record) || (record.Binding.Actor != s.scope && record.Binding.Target != s.scope) {
		return errTargetRecovery
	}
	b := record.Binding
	s.binding = &b
	s.summary = bytes.Clone(record.Summary)
	_, err := s.receive(s.request("targetRecoveryQuery"))
	return err
}
func (s *targetRecoveryStorage) Pending() (storageReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receive(s.request("targetRecoveryPending"))
}
func (s *targetRecoveryStorage) Query() (storageReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding == nil {
		return storageReply{}, errTargetRecovery
	}
	return s.receive(s.request("targetRecoveryQuery"))
}
func (s *targetRecoveryStorage) Result(result vaultwarden.RecoveryOperationResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !result.IsolationAttempted {
		if s.binding == nil && !result.Dispatched && !result.Confirmed && !result.Unknown {
			return nil
		}
		return errTargetRecovery
	}
	raw, err := json.Marshal(result.RecoveryDispatch)
	if err != nil || s.binding == nil || !bytes.Equal(raw, s.summary) || (result.Confirmed && (!result.Dispatched || result.Unknown)) || (result.Unknown && !result.Dispatched) {
		return errTargetRecovery
	}
	phase := "not-dispatched"
	if result.Dispatched {
		phase = "unknown"
		if result.Confirmed {
			phase = "confirmed"
		}
	}
	req := s.request("targetRecoveryResult")
	req.TargetPhase = phase
	_, err = s.receive(req)
	return err
}

// ResolveVerified never overwrites an unrelated actor snapshot. That case stores
// a verified, still-blocked target record; after logout, ordinary target publish
// accepts only these exact fresh vault/session/unlock digests, atomically consuming
// the permission. Same-target resolve atomically publishes through the native path.
func (s *targetRecoveryStorage) ResolveVerified(fresh vaultwarden.SyncResult, evidence targetRecoveryVerification) (storageReply, error) {
	return s.resolveVerified(fresh, evidence, false, false)
}
func (s *targetRecoveryStorage) ResolveVerifiedWithLocalAuthentication(fresh vaultwarden.SyncResult, evidence targetRecoveryVerification) (storageReply, error) {
	return s.resolveVerified(fresh, evidence, true, false)
}
func (s *targetRecoveryStorage) StageVerified(fresh vaultwarden.SyncResult, evidence targetRecoveryVerification) (storageReply, error) {
	return s.resolveVerified(fresh, evidence, false, true)
}
func (s *targetRecoveryStorage) resolveVerified(fresh vaultwarden.SyncResult, evidence targetRecoveryVerification, localAuthentication, verifyOnly bool) (storageReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding == nil || fresh.Vault == nil || fresh.PasswordUnlock == nil || fresh.Scope != fresh.Vault.Scope || fresh.Vault.Scope != s.binding.Target || len(fresh.Session) == 0 || len(fresh.PasswordUnlock.Key) != 32 || evidence.AuthenticationEpoch == 0 {
		return storageReply{}, errTargetRecovery
	}
	for _, h := range []string{evidence.AuthorityHash, evidence.KeyHash, evidence.MembershipHash, evidence.MFAHash, evidence.ConfirmationHash} {
		if !targetValidHash(h) {
			return storageReply{}, errTargetRecovery
		}
	}
	proof := targetRecoveryResolution{*s.binding, s.revision, s.binding.Target, targetRecoveryHash(fresh.Vault.Sync), targetRecoveryHash(fresh.Session), targetRecoveryHash(fresh.PasswordUnlock.Key), evidence.AuthorityHash, evidence.KeyHash, evidence.MembershipHash, evidence.MFAHash, evidence.ConfirmationHash, evidence.AuthenticationEpoch}
	req := s.request("targetRecoveryVerify")
	if !verifyOnly && (s.localScope == nil || *s.localScope == s.binding.Target) {
		req.Operation = "targetRecoveryResolve"
		if localAuthentication && s.localScope != nil {
			req.Operation = "targetRecoveryResolveLocal"
		}
		target := s.binding.Target
		req.Scope = &target
	} else if localAuthentication {
		return storageReply{}, errTargetRecovery
	}
	req.TargetResolution = &proof
	req.Vault = fresh.Vault
	req.Session = fresh.Session
	req.PasswordUnlock = fresh.PasswordUnlock
	req.Credentials = fresh.Credentials
	return s.receive(req)
}
