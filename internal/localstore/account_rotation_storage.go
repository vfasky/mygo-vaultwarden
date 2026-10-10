// SPDX-License-Identifier: GPL-3.0-only
package localstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type accountRecoveryBinding struct {
	OperationID string `json:"operationId"`
	OldRevision string `json:"oldRevision"`
	Epoch       uint64 `json:"epoch"`
	RecordHash  string `json:"recordHash"`
}
type accountRecoveryJournal struct {
	Version    int                    `json:"version"`
	Binding    accountRecoveryBinding `json:"binding"`
	Record     []byte                 `json:"record"`
	Phase      string                 `json:"phase"`
	Checkpoint []byte                 `json:"checkpoint,omitempty"`
}

func (r *accountRecoveryJournal) Close() {
	if r != nil {
		clear(r.Record)
		clear(r.Checkpoint)
		*r = accountRecoveryJournal{}
	}
}
func recoveryHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type accountRecoveryResolution struct {
	Binding           accountRecoveryBinding `json:"binding"`
	Mode              string                 `json:"mode"`
	UserConfirmed     bool                   `json:"userConfirmed"`
	AuthorityVerified bool                   `json:"authorityVerified"`
	ResourcesVerified bool                   `json:"resourcesVerified"`
	VaultHash         string                 `json:"vaultHash,omitempty"`
}

// Privileged controller adapter, like AcceptAuthenticatedSnapshot. currentEpoch
// MUST be a concurrency-safe read of the UI lifecycle epoch (never Session.mu).
// Call Close on lock/account switch. Recreate and Query after authenticating the
// old snapshot password to enter recovery after restart. Never restore OldSession
// as offline/network authority. No method sends or retries a server request.
type AccountRecoveryStorage struct {
	mu           sync.Mutex
	scope        vaultwarden.Scope
	revision     string
	epoch        uint64
	currentEpoch func() uint64
	unlockKey    []byte
	binding      *accountRecoveryBinding
	kind         vaultwarden.AccountChangeKind
	call         func(Request) Reply
	closed       bool
}

func NewAccountRecoveryStorage(state *SnapshotStatus, epoch uint64, currentEpoch func() uint64, key []byte, call func(Request) Reply) (*AccountRecoveryStorage, error) {
	if state == nil || !state.Available || state.Scope == nil || state.Revision == "" || len(key) != 32 || epoch == 0 || currentEpoch == nil || currentEpoch() != epoch || call == nil {
		return nil, vaultwarden.ErrIdentity
	}
	return &AccountRecoveryStorage{scope: *state.Scope, revision: state.Revision, epoch: epoch, currentEpoch: currentEpoch, unlockKey: bytes.Clone(key), call: call}, nil
}
func (s *AccountRecoveryStorage) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.unlockKey)
	s.closed = true
	s.binding = nil
}
func (s *AccountRecoveryStorage) active() bool {
	return !s.closed && s.currentEpoch() != 0 && s.currentEpoch() == s.epoch
}
func (s *AccountRecoveryStorage) request(operation string) Request {
	return Request{Operation: operation, Scope: &s.scope, ExpectedRevision: s.revision, UnlockKey: s.unlockKey, RecoveryBinding: s.binding}
}
func (s *AccountRecoveryStorage) receive(request Request) (Reply, error) {
	if !s.active() {
		return Reply{}, vaultwarden.ErrExpired
	}
	reply := s.call(request)
	if !s.active() {
		if reply.Recovery != nil {
			reply.Recovery.Close()
		}
		clear(reply.Session)
		return Reply{}, vaultwarden.ErrExpired
	}
	if !reply.OK {
		return reply, reply.Failure()
	}
	if reply.State == nil || reply.State.Revision == "" || (request.Operation != "accountRecoveryQuery" && reply.State.Revision == s.revision) {
		return Reply{}, vaultwarden.ErrIdentity
	}
	if reply.State.RecoveryPending != (request.Operation != "accountRecoveryResolve") ||
		(request.Operation == "accountRecoveryQuery" && reply.State.Revision != s.revision) {
		if reply.Recovery != nil {
			reply.Recovery.Close()
		}
		return Reply{}, vaultwarden.ErrIdentity
	}
	deleting := request.RecoveryResolution != nil && request.RecoveryResolution.Mode == "delete"
	if deleting {
		if reply.State.Available || reply.State.Scope != nil || reply.Recovery != nil {
			return Reply{}, vaultwarden.ErrIdentity
		}
	} else if !reply.State.Available || reply.State.Scope == nil || *reply.State.Scope != s.scope || reply.State.SnapshotID == "" {
		return Reply{}, vaultwarden.ErrIdentity
	}
	if request.Operation != "accountRecoveryResolve" {
		r := reply.Recovery
		validPhase := r != nil && (r.Phase == "prepared" || r.Phase == "unknown" || r.Phase == "confirmed" || r.Phase == "not-dispatched")
		if !validPhase || r.Version != 1 || r.Binding.Epoch == 0 || recoveryHash(r.Record) != r.Binding.RecordHash || (request.RecoveryBinding != nil && *request.RecoveryBinding != r.Binding) ||
			(request.Operation == "accountRecoveryBegin" && r.Phase != "prepared") ||
			(request.Operation == "accountRecoveryResult" && r.Phase != request.RecoveryPhase) {
			if r != nil {
				r.Close()
			}
			return Reply{}, vaultwarden.ErrIdentity
		}
		var original vaultwarden.AccountRecovery
		if json.Unmarshal(r.Record, &original) != nil || original.Version != 1 || original.Scope != s.scope || original.OperationID != r.Binding.OperationID || original.OldRevision != r.Binding.OldRevision {
			original.Close()
			r.Close()
			return Reply{}, vaultwarden.ErrIdentity
		}
		s.kind = original.Kind
		original.Close()
		b := r.Binding
		s.binding = &b
	}
	s.revision = reply.State.Revision
	return reply, nil
}

// Begin is the exact AccountRecoveryPersistence hook for CommitAccountChange.
// It runs synchronously under the Session lock and never calls Session methods.
// If receipt delivery fails, do NOT dispatch: recreate/query the same operation.
func (s *AccountRecoveryStorage) Begin(record vaultwarden.AccountRecovery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active() || s.binding != nil || record.Version != 1 || record.Scope != s.scope || record.OldRevision != s.revision || record.OldUnlock == nil || !bytes.Equal(record.OldUnlock.Key, s.unlockKey) {
		return vaultwarden.ErrIdentity
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return vaultwarden.ErrProtocol
	}
	defer clear(raw)
	binding := accountRecoveryBinding{record.OperationID, record.OldRevision, s.epoch, recoveryHash(raw)}
	request := s.request("accountRecoveryBegin")
	request.RecoveryBinding = &binding
	request.RecoveryRecord = raw
	reply, err := s.receive(request)
	if reply.Recovery != nil {
		reply.Recovery.Close()
	}
	return err
}
func (s *AccountRecoveryStorage) Query() (Reply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receive(s.request("accountRecoveryQuery"))
}

// Result only annotates the durable record; even Confirmed leaves the barrier.
func (s *AccountRecoveryStorage) Result(result vaultwarden.AccountChangeResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding == nil || result.Scope != s.scope || result.OperationID != s.binding.OperationID || result.PreviousRevision != s.binding.OldRevision || result.Kind != s.kind || (result.Confirmed && (!result.Dispatched || result.Unknown)) {
		return vaultwarden.ErrIdentity
	}
	phase := "not-dispatched"
	if result.Dispatched || result.Unknown {
		phase = "unknown"
	}
	if result.Confirmed {
		phase = "confirmed"
	}
	request := s.request("accountRecoveryResult")
	request.RecoveryPhase = phase
	reply, err := s.receive(request)
	if reply.Recovery != nil {
		reply.Recovery.Close()
	}
	return err
}

// New login may rotate a refresh token during recovery. Save it separately; the
// immutable original OldSession and both user keys remain intact. This callback
// is for a newly logged-in session without installed offline snapshot authority.
func (s *AccountRecoveryStorage) Checkpoint(checkpoint vaultwarden.SessionCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding == nil || checkpoint.Scope != s.scope {
		return vaultwarden.ErrIdentity
	}
	request := s.request("accountRecoveryCheckpoint")
	request.Session = checkpoint.Session
	reply, err := s.receive(request)
	if reply.Recovery != nil {
		reply.Recovery.Close()
	}
	return err
}

// ResolveVerified is called ONLY after explicit user confirmation, authoritative
// new login/full-sync verification, and complete cipher/folder/Send/emergency/
// organization recovery verification (including partial rotation). These are
// trusted controller attestations, not facts inferred from HTTP 200 or Sync alone.
// Failed/unknown/partial conversion keeps the journal: there is no retry/rollback.
// On success caller installs reply.Vault via freshSession.AcceptAuthenticatedSnapshot
// only after its own current UI epoch check; reply includes merged local policies.
func (s *AccountRecoveryStorage) ResolveVerified(fresh vaultwarden.SyncResult, userConfirmed, authorityVerified, resourcesVerified bool) (Reply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding == nil || fresh.Scope != s.scope || fresh.Vault == nil || fresh.Vault.Scope != s.scope || fresh.PasswordUnlock == nil || len(fresh.Session) == 0 || !userConfirmed || !authorityVerified || !resourcesVerified {
		return Reply{}, vaultwarden.ErrIdentity
	}
	request := s.request("accountRecoveryResolve")
	request.PasswordUnlock = fresh.PasswordUnlock
	request.Session = fresh.Session
	request.Vault = fresh.Vault
	request.Credentials = fresh.Credentials
	request.RecoveryResolution = &accountRecoveryResolution{*s.binding, "verified", true, true, true, recoveryHash(fresh.Vault.Sync)}
	reply, err := s.receive(request)
	if err == nil {
		if reply.Recovery != nil || reply.Vault == nil || reply.Vault.Scope != s.scope || !bytes.Equal(reply.Vault.Sync, fresh.Vault.Sync) {
			return Reply{}, vaultwarden.ErrIdentity
		}
		clear(s.unlockKey)
		s.closed = true
		s.binding = nil
	}
	return reply, err
}
func (s *AccountRecoveryStorage) DeleteConfirmed(userConfirmed bool) (Reply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.binding == nil || s.kind != vaultwarden.AccountDelete || !userConfirmed {
		return Reply{}, vaultwarden.ErrIdentity
	}
	request := s.request("accountRecoveryResolve")
	request.RecoveryResolution = &accountRecoveryResolution{Binding: *s.binding, Mode: "delete", UserConfirmed: true, AuthorityVerified: true}
	reply, err := s.receive(request)
	if err == nil {
		clear(s.unlockKey)
		s.closed = true
		s.binding = nil
	}
	return reply, err
}
