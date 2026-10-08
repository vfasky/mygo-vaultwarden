// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"sort"
	"time"
)

func recoveryOperationIDValid(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (s *Session) clearFreshRecoveryLogin() { s.freshRecoveryDeadline = time.Time{} }

const (
	TargetEvidenceDiscovery  = "target-discovery-v1"
	TargetEvidenceEffects    = "target-observed-effects-v1"
	TargetEvidenceAdminEmail = "target-confirmed-email-fallback-v1"
	TargetEvidenceNoDispatch = "target-authenticated-nondispatch-v1"
)

type TargetRecoveryOriginalResult struct {
	Version int    `json:"version"`
	Phase   string `json:"phase"`
}
type TargetRecoveryEvidence struct {
	Kind                                                              string
	AuthorityHash, KeyHash, MembershipHash, MFAHash, ConfirmationHash string
	AuthenticationEpoch                                               uint64
	Notes                                                             []string
}

// This observation is minted only from a fresh password/MFA login and a new
// authoritative Sync. Discovery is metadata-only; it does not attest that any
// recovery action has completed. Mutating its exported fresh material invalidates
// the observation. No key, password, OTP, or password-authentication hash is logged.
type TargetRecoveryInspection struct {
	Fresh                                                                               SyncResult
	owner                                                                               *Session
	epoch                                                                               uint64
	deadline                                                                            time.Time
	freshDigest, vaultDigest, sessionDigest, unlockDigest, authority, key, members, mfa string
	enabled                                                                             []int
	organizations                                                                       []Organization
	userKeyDigest, wrapperDigest                                                        string
}

func (p *TargetRecoveryInspection) Close() {
	if p == nil {
		return
	}
	clear(p.Fresh.Session)
	if p.Fresh.PasswordUnlock != nil {
		clear(p.Fresh.PasswordUnlock.Key)
	}
	p.Fresh = SyncResult{}
	p.owner = nil
	p.enabled = nil
	p.organizations = nil
}
func targetEvidenceHash(value any) string {
	raw, _ := json.Marshal(value)
	defer clear(raw)
	return recoveryWitness(raw)
}
func (p *TargetRecoveryInspection) validLocked(s *Session) bool {
	return p != nil && p.owner == s && s.itemSessionActiveLocked() && s.authorizationEpoch == p.epoch && time.Now().Before(p.deadline) && !s.freshRecoveryDeadline.IsZero() && p.Fresh.Vault != nil && p.Fresh.PasswordUnlock != nil && p.Fresh.Scope == p.Fresh.Vault.Scope && p.Fresh.Scope == (Scope{s.client.base.String(), s.account}) && targetEvidenceHash(p.Fresh) == p.freshDigest && targetEvidenceHash(p.Fresh.Vault) == p.vaultDigest && recoveryWitness(p.Fresh.Session) == p.sessionDigest && recoveryWitness(p.Fresh.PasswordUnlock.Key) == p.unlockDigest
}
func (p *TargetRecoveryInspection) evidence(kind, operation, summary, confirmation string) TargetRecoveryEvidence {
	return TargetRecoveryEvidence{Kind: kind, AuthorityHash: p.authority, KeyHash: p.key, MembershipHash: p.members, MFAHash: p.mfa, ConfirmationHash: targetEvidenceHash(struct{ Kind, Operation, Summary, Confirmation, Authority string }{kind, operation, summary, confirmation, p.authority}), AuthenticationEpoch: p.epoch}
}
func (s *Session) TargetRecoveryDiscoveryEvidence(p *TargetRecoveryInspection, queryID string) (TargetRecoveryEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !p.validLocked(s) || !recoveryOperationIDValid(queryID) {
		return TargetRecoveryEvidence{}, ErrRecoveryUnverified
	}
	return p.evidence(TargetEvidenceDiscovery, queryID, "", "inspect-authenticated-target-records"), nil
}
func (s *Session) InspectFreshTargetRecovery(ctx context.Context) (*TargetRecoveryInspection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if s.runtimeOnly || s.passwordUnlock == nil || s.authorizationRevision != "" || !time.Now().Before(s.freshRecoveryDeadline) {
		return nil, ErrRecoveryUnverified
	}
	if err = s.client.requireRecoveryCompatibility(ctx); err != nil {
		return nil, err
	}
	fresh, err := s.syncLocked(ctx, nil)
	p := &TargetRecoveryInspection{Fresh: fresh, owner: s, deadline: s.freshRecoveryDeadline}
	fail := func(err error) (*TargetRecoveryInspection, error) { p.Close(); return nil, err }
	if err != nil {
		return fail(err)
	}
	var body struct{ Profile json.RawMessage }
	var profile struct {
		ID, Key, PrivateKey, Email string
		OrganizationsNew           []json.RawMessage
	}
	if json.Unmarshal(fresh.Vault.Sync, &body) != nil || json.Unmarshal(body.Profile, &profile) != nil || profile.ID != fresh.Scope.Account || profile.Key != s.wrapped || NormalizeEmail(profile.Email) != s.email || profile.OrganizationsNew == nil {
		return fail(ErrIdentity)
	}
	private, err := accountPrivateKey(body.Profile, s.key)
	if err != nil {
		return fail(err)
	}
	public, e := x509.MarshalPKIXPublicKey(&private.PublicKey)
	clearAccountPrivateKey(private)
	if e != nil {
		return fail(ErrEncryption)
	}
	status, keysRaw, err := s.authenticatedLocked(ctx, "GET", "/api/accounts/keys", "", "", nil)
	var keys struct{ Key, PrivateKey, PublicKey string }
	if err != nil {
		return fail(err)
	}
	if status != 200 || strictJSON(keysRaw) != nil || json.Unmarshal(keysRaw, &keys) != nil || keys.Key != s.wrapped || keys.PrivateKey != profile.PrivateKey {
		return fail(ErrIdentity)
	}
	expected, e := base64.StdEncoding.Strict().DecodeString(keys.PublicKey)
	if e != nil || !bytes.Equal(public, expected) {
		return fail(ErrEncryption)
	}
	if _, err = AnalyzeAccountRotationCipherResources(ctx, AccountRotationInput{Scope: fresh.Scope, Sync: fresh.Vault.Sync, OldUserKey: s.key}); err != nil {
		return fail(err)
	}
	rows, err := sendRotationRows(fresh.Vault.Sync, fresh.Scope)
	if err != nil {
		return fail(err)
	}
	for _, row := range rows {
		_, wire, e := sendRotationOwner(row)
		if e != nil {
			return fail(e)
		}
		seed, e := sendRotationSeed(wire, s.key)
		clear(seed)
		if e != nil {
			return fail(e)
		}
	}
	data, err := s.decodeOrganizationVaultLocked(fresh.Vault)
	if err != nil {
		return fail(err)
	}
	data.close()
	for _, raw := range profile.OrganizationsNew {
		var flags struct {
			Type, Status *int
			Enabled      *bool
		}
		var org Organization
		if json.Unmarshal(raw, &flags) != nil || flags.Type == nil || flags.Status == nil || flags.Enabled == nil || json.Unmarshal(raw, &org) != nil || org.Status < 0 || org.Status > 3 {
			return fail(ErrProtocol)
		}
		switch org.Type {
		case 0, 1, 2, 4:
		default:
			return fail(ErrProtocol)
		}
		org.Key = ""
		p.organizations = append(p.organizations, org)
	}
	status, mfaRaw, err := s.authenticatedLocked(ctx, "GET", "/api/two-factor", "", "", nil)
	if err != nil {
		return fail(err)
	}
	var mfa struct {
		Data   []json.RawMessage
		Object string
	}
	if status != 200 || strictJSON(mfaRaw) != nil || json.Unmarshal(mfaRaw, &mfa) != nil || mfa.Object != "list" || mfa.Data == nil {
		return fail(ErrProtocol)
	}
	seen := map[int]bool{}
	for _, raw := range mfa.Data {
		var provider struct {
			Type    *int
			Enabled *bool
		}
		if json.Unmarshal(raw, &provider) != nil || provider.Type == nil || provider.Enabled == nil || seen[*provider.Type] {
			return fail(ErrProtocol)
		}
		seen[*provider.Type] = true
		switch *provider.Type {
		case 0, 1, 2, 3, 4, 6, 7:
		default:
			return fail(ErrProtocol)
		}
		if *provider.Enabled {
			p.enabled = append(p.enabled, *provider.Type)
		}
	}
	sort.Ints(p.enabled)
	if err = s.completeRecoveryVerificationLocked(ctx, &p.Fresh); err != nil {
		return fail(err)
	}
	p.freshDigest = targetEvidenceHash(p.Fresh)
	p.epoch = s.authorizationEpoch
	p.vaultDigest = targetEvidenceHash(p.Fresh.Vault)
	p.sessionDigest = recoveryWitness(p.Fresh.Session)
	p.unlockDigest = recoveryWitness(p.Fresh.PasswordUnlock.Key)
	p.userKeyDigest = recoveryWitness(s.key)
	p.wrapperDigest = recoveryWitness([]byte(s.wrapped))
	p.authority = targetEvidenceHash(struct {
		Scope                                Scope
		Sync, Keys, Session, Release, Commit string
		Epoch                                uint64
	}{fresh.Scope, recoveryWitness(fresh.Vault.Sync), recoveryWitness(keysRaw), p.sessionDigest, "1.37.4", rotationGit1374, p.epoch})
	p.key = targetEvidenceHash(struct{ Key, Wrapper, Public string }{p.userKeyDigest, p.wrapperDigest, recoveryWitness(public)})
	p.members = targetEvidenceHash(profile.OrganizationsNew)
	p.mfa = recoveryWitness(mfaRaw)
	if !p.validLocked(s) {
		return fail(ErrRecoveryUnverified)
	}
	return p, nil
}

// origin is trusted ONLY when read from the authenticated native record with the
// identical immutable dispatch summary. UI success flags cannot supply it.
func (s *Session) VerifyTargetRecovery(p *TargetRecoveryInspection, dispatch RecoveryDispatch, origin TargetRecoveryOriginalResult, summaryHash, confirmation string) (TargetRecoveryEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reject := func() (TargetRecoveryEvidence, error) { return TargetRecoveryEvidence{}, ErrRecoveryUnverified }
	raw, err := json.Marshal(dispatch)
	if !p.validLocked(s) || err != nil || dispatch.Verification.Validate(dispatch.Kind) != nil || !dispatch.RequireTargetLogin || dispatch.Target != p.Fresh.Scope || dispatch.Actor.Server != dispatch.Target.Server || !recoveryOperationIDValid(dispatch.OperationID) || dispatch.AuthorizationEpoch == 0 || dispatch.PreviousRevision == "" || dispatch.Actor.Account == "" || summaryHash != recoveryWitness(raw) || confirmation != dispatch.OperationID {
		return reject()
	}
	if dispatch.Kind == "administrator-recovery" && (!validObjectID(dispatch.OrganizationID) || !validObjectID(dispatch.MembershipID)) {
		return reject()
	}
	if dispatch.Kind == "emergency-takeover" && (!validObjectID(dispatch.ResourceID) || dispatch.CounterpartyID != dispatch.Target.Account || dispatch.EmergencyType != 1) {
		return reject()
	}
	if origin.Version != 0 && (origin.Version != 1 || (origin.Phase != "confirmed" && origin.Phase != "unknown" && origin.Phase != "not-dispatched")) {
		return reject()
	}
	if origin.Version == 0 && origin.Phase != "" {
		return reject()
	}
	expected := dispatch.Verification
	if expected.ExpectedUserKeySHA256 != p.userKeyDigest {
		return reject()
	}
	noDispatch := origin.Version == 1 && origin.Phase == "not-dispatched"
	kind := TargetEvidenceEffects
	notes := []string{"fresh password/MFA login and actual full Sync; authority wrapper, RSA key relationship, current personal cipher/folder/Send cryptography and organization identity/policy/key chain checked", "binary files and hidden server remember-device credentials were not independently read back"}
	if noDispatch {
		kind = TargetEvidenceNoDispatch
		notes = append(notes, "原操作确定未派发，仅解除本机预隔离；当前MFA和成员关系未被声明已删除")
	} else {
		if expected.ResetPassword && expected.ExpectedMasterWrapperSHA256 != p.wrapperDigest {
			return reject()
		}
		if expected.ResetMFA && len(p.enabled) != 0 {
			if dispatch.Kind != "administrator-recovery" || origin.Version != 1 || origin.Phase != "confirmed" || len(p.enabled) != 1 || p.enabled[0] != 1 {
				return reject()
			}
			kind = TargetEvidenceAdminEmail
			notes = append(notes, "已确认管理员MFA reset；本人新读取确认Email回退仍启用，并非所有MFA关闭")
		}
		if expected.RemoveNonOwnerMemberships {
			for _, org := range p.organizations {
				if org.Type != 0 {
					return reject()
				}
			}
		}
	}
	// Lost/revoked administrator-org membership must never restore its old access.
	// The native dedicated resolution still merges every pre-existing protection.
	if dispatch.Kind == "administrator-recovery" {
		active := false
		for _, org := range p.organizations {
			if org.ID == dispatch.OrganizationID && org.OrganizationUserID == dispatch.MembershipID && org.Status == 2 && org.Enabled {
				active = true
			}
		}
		if !active {
			present := false
			for _, id := range p.Fresh.Vault.QuarantinedOrganizations {
				if id == dispatch.OrganizationID {
					present = true
				}
			}
			if !present {
				p.Fresh.Vault.QuarantinedOrganizations = append(p.Fresh.Vault.QuarantinedOrganizations, dispatch.OrganizationID)
			}
			notes = append(notes, "管理员组织的成员资格/授权当前已不存在或不可用；保留额外组织隔离")
		}
	}
	p.vaultDigest = targetEvidenceHash(p.Fresh.Vault)
	p.freshDigest = targetEvidenceHash(p.Fresh)
	evidence := p.evidence(kind, dispatch.OperationID, summaryHash, confirmation)
	evidence.KeyHash = targetEvidenceHash(struct {
		Observed   string
		Expected   RecoveryVerificationExpectation
		NoDispatch bool
	}{p.key, expected, noDispatch})
	evidence.MFAHash = targetEvidenceHash(struct {
		Observed                 string
		Requested, NotDispatched bool
		Origin                   TargetRecoveryOriginalResult
	}{p.mfa, expected.ResetMFA, noDispatch, origin})
	evidence.MembershipHash = targetEvidenceHash(struct {
		Observed                 string
		Requested, NotDispatched bool
	}{p.members, expected.RemoveNonOwnerMemberships, noDispatch})
	evidence.Notes = notes
	return evidence, nil
}
