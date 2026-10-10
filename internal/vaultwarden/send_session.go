// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"net/http"
	"reflect"
	"time"
)

// NewSend binds a new editor to the authenticated current snapshot. The caller
// must discard drafts on a replacement snapshot; refresh also revokes drafts.
func (s *Session) NewSend(vault *VaultData, kind int) (*SendDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e := s.snapshotPoliciesLocked(vault); e != nil {
		return nil, e
	}
	if kind != 0 && kind != 1 {
		return nil, ErrValidation
	}
	seed, e := newSendSeed()
	if e != nil {
		return nil, e
	}
	return &SendDraft{Fields: SendFields{Type: kind, DeletionDate: time.Now().Add(7 * 24 * time.Hour)}, seed: seed, owner: s, scope: vault.Scope, revision: s.authorizationRevision, epoch: s.authorizationEpoch}, nil
}

// Sends derives offline owner data only from a snapshot installed by the trusted
// receipt API. Returned drafts own their plaintext and must each be closed.
func (s *Session) Sends(vault *VaultData) ([]*SendDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e := s.snapshotPoliciesLocked(vault); e != nil {
		return nil, e
	}
	var body struct{ Sends []sendWire }
	if json.Unmarshal(vault.Sync, &body) != nil || body.Sends == nil || len(body.Sends) > 100000 {
		return nil, ErrProtocol
	}
	return s.sendDraftsLocked(body.Sends, vault.Scope)
}
func (s *Session) sendDraftsLocked(rows []sendWire, scope Scope) (out []*SendDraft, err error) {
	defer func() {
		if err != nil {
			for _, d := range out {
				d.Close()
			}
			out = nil
		}
	}()
	seen := map[string]bool{}
	for _, w := range rows {
		if seen[w.ID] {
			return out, ErrProtocol
		}
		seen[w.ID] = true
		d, e := decryptSend(w, s.key)
		if e != nil {
			return out, e
		}
		d.owner = s
		d.scope, d.revision, d.epoch = scope, s.authorizationRevision, s.authorizationEpoch
		out = append(out, d)
	}
	return out, nil
}
func (s *Session) ListSends(ctx context.Context, scope Scope, persist func(SessionCheckpoint) error) ([]*SendDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, e := s.beginOperationLocked(ctx)
	if e != nil {
		return nil, e
	}
	defer finish()
	if e = s.requireScopeLocked(scope); e != nil {
		return nil, e
	}
	status, body, e := s.authenticatedLocked(ctx, http.MethodGet, "/api/sends", "", "", persist)
	if e != nil {
		return nil, e
	}
	defer clear(body)
	if status != 200 {
		return nil, statusError(status)
	}
	var list struct {
		Data              []sendWire
		ContinuationToken *string
	}
	if strictJSON(body) != nil || json.Unmarshal(body, &list) != nil || list.Data == nil || list.ContinuationToken != nil || len(list.Data) > 100000 {
		return nil, ErrProtocol
	}
	if !s.itemSessionActiveLocked() || ctx.Err() != nil {
		return nil, ErrExpired
	}
	return s.sendDraftsLocked(list.Data, scope)
}
func (s *Session) sendGuardLocked(ctx context.Context, d *SendDraft) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if d == nil || d.owner != s || d.consumed || len(d.seed) != 16 || !s.itemSessionActiveLocked() || d.epoch != s.authorizationEpoch || d.revision == "" || d.revision != s.authorizationRevision {
		return ErrExpired
	}
	return s.requireScopeLocked(d.scope)
}

// The Send lane reads and validates the same authoritative full sync as other
// writes, but keeps type 6/7 interpretation here to avoid modifying shared core.
func (s *Session) sendPolicyLocked(ctx context.Context, d *SendDraft, remove bool, persist func(SessionCheckpoint) error) (func() error, error) {
	status, body, e := s.authenticatedLocked(ctx, http.MethodGet, "/api/sync", "", "", persist)
	if e != nil {
		return nil, e
	}
	defer clear(body)
	if status != 200 {
		return nil, statusError(status)
	}
	if e = s.sendGuardLocked(ctx, d); e != nil {
		return nil, e
	}
	p, e := parseOperationPolicies(body, d.scope, s.email, s.wrapped)
	if e != nil {
		return nil, e
	}
	p.epoch, p.revision = s.authorizationEpoch, s.authorizationRevision
	s.writePolicies = p
	if !remove {
		for _, pending := range s.pendingPolicyMutations {
			if pending.PolicyType == 6 || pending.PolicyType == 7 {
				return nil, ErrPermission
			}
		}
		var parsed struct{ Policies []syncPolicy }
		if json.Unmarshal(body, &parsed) != nil {
			return nil, ErrProtocol
		}
		for _, policy := range parsed.Policies {
			m := p.memberships[policy.OrganizationID]
			if !*policy.Enabled || *m.Type == 0 || *m.Type == 1 {
				continue
			}
			if *policy.Type == 6 {
				return nil, ErrPermission
			}
			if *policy.Type == 7 && d.Fields.HideEmail {
				var opt struct {
					DisableHideEmail bool `json:"disableHideEmail"`
				}
				if json.Unmarshal(policy.Data, &opt) != nil {
					return nil, ErrProtocol
				}
				if opt.DisableHideEmail {
					return nil, ErrPermission
				}
			}
		}
	}
	return func() error {
		if e := s.checkOperationPoliciesLocked(ctx, p); e != nil {
			return e
		}
		return s.sendGuardLocked(ctx, d)
	}, nil
}
func (s *Session) sendCurrentLocked(ctx context.Context, d *SendDraft, persist func(SessionCheckpoint) error, guard func() error) error {
	if d.ID() == "" {
		return guard()
	}
	status, b, e := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/sends/"+d.ID(), "", "", persist, guard)
	if e != nil {
		return e
	}
	defer clear(b)
	if status != 200 {
		return statusError(status)
	}
	w, e := decodeSend(b)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(w, d.wire) {
		return ErrConflict
	}
	return guard()
}

// SaveSend executes one metadata mutation and, for new files, one binary upload.
// Every dispatched mutation consumes the draft, including known server errors:
// explicit reconciliation is required before another attempt. File metadata is
// never returned as a completed Send when upload fails.
func (s *Session) SaveSend(ctx context.Context, d *SendDraft, source io.Reader, size int64, persist func(SessionCheckpoint) error) (*SendDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, e := s.beginOperationLocked(ctx)
	if e != nil {
		return nil, e
	}
	defer finish()
	if e = s.sendGuardLocked(ctx, d); e != nil {
		return nil, e
	}
	if e = validateSendFields(d.Fields); e != nil {
		return nil, e
	}
	if d.ID() != "" && d.Fields.Type != d.wire.Type {
		return nil, ErrValidation
	}
	guard, e := s.sendPolicyLocked(ctx, d, false, persist)
	if e != nil {
		return nil, e
	}
	if e = s.sendCurrentLocked(ctx, d, persist, guard); e != nil {
		return nil, e
	}
	w, e := encryptSend(d.Fields, d.seed, s.key)
	if e != nil {
		return nil, e
	}
	var encrypted *vaultcrypto.AttachmentSpool
	if d.Fields.Type == 1 && d.ID() == "" {
		if source == nil {
			return nil, ErrValidation
		}
		key, e := sendKey(d.seed)
		if e != nil {
			return nil, e
		}
		encrypted, e = vaultcrypto.EncryptAttachment(ctx, source, size, key)
		clear(key)
		if e != nil {
			return nil, e
		}
		defer encrypted.Close()
		w.FileLength = &encrypted.Size
	} else if source != nil {
		return nil, ErrValidation
	}
	if d.ID() != "" {
		w.Key = d.wire.Key
		if w.Type == 1 {
			if d.Fields.FileName != func() string { f, _ := decryptSendFields(d.wire, d.seed); return f.FileName }() {
				return nil, ErrValidation
			}
			w.File = nil
		}
	}
	body, e := json.Marshal(w)
	if e != nil {
		return nil, ErrProtocol
	}
	defer clear(body)
	method, endpoint := http.MethodPost, "/api/sends"
	if d.ID() != "" {
		method, endpoint = http.MethodPut, endpoint+"/"+d.ID()
	} else if encrypted != nil {
		endpoint += "/file/v2"
	}
	status, reply, e := s.authenticatedGuardedLocked(ctx, method, endpoint, "application/json", string(body), persist, guard)
	// guard failures before dispatch may also consume the editor: fail closed.
	d.consumed = true
	if e != nil {
		return nil, e
	}
	defer clear(reply)
	if status != 200 {
		return nil, mutationStatusError(status)
	}
	var result sendWire
	if encrypted != nil {
		var receipt struct {
			FileUploadType *int
			URL            string
			SendResponse   sendWire
		}
		if strictJSON(reply) != nil || json.Unmarshal(reply, &receipt) != nil || receipt.FileUploadType == nil || *receipt.FileUploadType != 0 {
			return nil, &MutationUncertainError{Cause: ErrProtocol}
		}
		result = receipt.SendResponse
		if result.File == nil || !validObjectID(result.ID) || !validObjectID(result.File.ID) || receipt.URL != "/sends/"+result.ID+"/file/"+result.File.ID {
			return nil, &MutationUncertainError{Cause: ErrProtocol}
		}
	} else {
		result, e = decodeSend(reply)
		if e != nil {
			return nil, &MutationUncertainError{Cause: e}
		}
	}
	next, e := decryptSend(result, s.key)
	if e != nil {
		return nil, &MutationUncertainError{Cause: e}
	}
	next.owner = s
	next.scope, next.epoch, next.revision = d.scope, d.epoch, d.revision
	success := false
	defer func() {
		if !success {
			next.Close()
		}
	}()
	if (d.ID() != "" && next.ID() != d.ID()) || !sendMatches(w, result, d.wire, encrypted != nil) {
		return nil, &MutationUncertainError{Cause: ErrProtocol}
	}
	if encrypted != nil {
		// Recheck policies after expensive spooling and between both writes. Use a
		// temporary, unconsumed lease; never permit refresh to silently renew it.
		stage := *d
		stage.consumed = false
		uploadGuard, e := s.sendPolicyLocked(ctx, &stage, false, persist)
		if e != nil {
			return nil, &SendUploadError{ID: result.ID, Cause: e}
		}
		if e = uploadGuard(); e != nil {
			return nil, &SendUploadError{ID: result.ID, Cause: e}
		}
		status, e = s.client.uploadSend(ctx, result.ID, result.File.ID, result.File.FileName, s.access, encrypted)
		if e != nil {
			return nil, &SendUploadError{ID: result.ID, Cause: &MutationUncertainError{Cause: e}}
		}
		if status != 200 && status != 204 {
			return nil, &SendUploadError{ID: result.ID, Cause: mutationStatusError(status)}
		}
	}
	if ctx.Err() != nil || !s.itemSessionActiveLocked() {
		return nil, &MutationUncertainError{Cause: ErrCancelled}
	}
	success = true
	return next, nil
}
func sendMatches(w, r, prior sendWire, file bool) bool {
	if w.Name != r.Name || w.Key != r.Key || !reflect.DeepEqual(w.Notes, r.Notes) || w.Type != r.Type || w.Disabled != r.Disabled || w.HideEmail != r.HideEmail || !w.DeletionDate.Equal(r.DeletionDate) || !reflect.DeepEqual(w.MaxAccessCount, r.MaxAccessCount) {
		return false
	}
	if (w.ExpirationDate == nil) != (r.ExpirationDate == nil) || (w.ExpirationDate != nil && !w.ExpirationDate.Equal(*r.ExpirationDate)) {
		return false
	}
	if w.Password != nil && r.Password == nil {
		return false
	}
	if w.Password == nil && !reflect.DeepEqual(prior.Password, r.Password) {
		return false
	}
	if w.Type == 0 {
		return reflect.DeepEqual(w.Text, r.Text)
	}
	if file {
		return r.File != nil && w.File.FileName == r.File.FileName && r.File.Size == sendSize(*w.FileLength)
	}
	return reflect.DeepEqual(prior.File, r.File)
}

// SendUploadError means metadata exists, but the file is not confirmed uploaded.
// UI must offer list/sync and explicit deletion, never automatic retry/cleanup.
type SendUploadError struct {
	ID    string
	Cause error
}

func (e *SendUploadError) Error() string {
	return i18n.T("server.send.status_upload_unconfirmed")
}
func (e *SendUploadError) Unwrap() error { return e.Cause }
func (s *Session) DeleteSend(ctx context.Context, d *SendDraft, persist func(SessionCheckpoint) error) error {
	return s.changeSend(ctx, d, true, persist)
}
func (s *Session) RemoveSendPassword(ctx context.Context, d *SendDraft, persist func(SessionCheckpoint) error) error {
	return s.changeSend(ctx, d, false, persist)
}
func (s *Session) changeSend(ctx context.Context, d *SendDraft, remove bool, persist func(SessionCheckpoint) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, e := s.beginOperationLocked(ctx)
	if e != nil {
		return e
	}
	defer finish()
	if e = s.sendGuardLocked(ctx, d); e != nil {
		return e
	}
	if !validObjectID(d.ID()) {
		return ErrValidation
	}
	policyDraft := *d
	// Removing a password does not resubmit hideEmail; the fixed server applies
	// DisableSend here, but not SendOptions.
	if !remove {
		policyDraft.Fields.HideEmail = false
	}
	guard, e := s.sendPolicyLocked(ctx, &policyDraft, remove, persist)
	if e != nil {
		return e
	}
	if e = s.sendCurrentLocked(ctx, d, persist, guard); e != nil {
		return e
	}
	method, endpoint := http.MethodDelete, "/api/sends/"+d.ID()
	if !remove {
		method, endpoint = http.MethodPut, endpoint+"/remove-password"
	}
	status, b, e := s.authenticatedGuardedLocked(ctx, method, endpoint, "", "", persist, guard)
	d.consumed = true
	if e != nil {
		return e
	}
	defer clear(b)
	if status != 200 && status != 204 {
		return mutationStatusError(status)
	}
	if !remove {
		w, e := decodeSend(b)
		if e != nil || w.ID != d.ID() || w.Password != nil {
			return &MutationUncertainError{Cause: ErrProtocol}
		}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
