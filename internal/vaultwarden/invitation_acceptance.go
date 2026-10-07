// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var ErrInvitationAlreadyAccepted = errors.New("此邀请已接受，不能重复提交；请同步核对成员确认与账号恢复登记状态")

// InvitationAcceptance binds consent to the authenticated account, snapshot,
// invitation, policies and exact recovery public key. It contains no user key.
type InvitationAcceptance struct {
	scope                                       Scope
	epoch                                       uint64
	revision, link, organization, member, token string
	policies                                    string
	recoveryPublicKey                           string
	recoveryRequired                            bool
	consumed                                    bool
}

func (d *InvitationAcceptance) Clone() *InvitationAcceptance {
	if d == nil {
		return nil
	}
	copy := *d
	return &copy
}
func (d *InvitationAcceptance) Close() {
	if d != nil {
		*d = InvitationAcceptance{}
	}
}
func (d *InvitationAcceptance) RecoveryRequired() bool { return d != nil && d.recoveryRequired }
func (d *InvitationAcceptance) RecoveryPublicKey() string {
	if d == nil {
		return ""
	}
	return d.recoveryPublicKey
}

func invitationParameters(link string, base *url.URL, email string) (url.Values, error) {
	if len(link) > 32768 {
		return nil, ErrValidation
	}
	invitation, err := url.Parse(link)
	if err != nil || invitation.User != nil || invitation.RawQuery != "" || invitation.ForceQuery || invitation.RawPath != "" {
		return nil, ErrValidation
	}
	// Fragment is already percent-decoded by net/url. Preserve its escaped form
	// so token '+' and '&' bytes are decoded once, by ParseQuery below.
	fragment, err := url.Parse(invitation.EscapedFragment())
	if err != nil || fragment.Path != "/accept-organization/" || fragment.RawPath != "" || fragment.Fragment != "" || fragment.Host != "" || fragment.IsAbs() {
		return nil, ErrValidation
	}
	query, err := url.ParseQuery(fragment.RawQuery)
	if err != nil {
		return nil, ErrValidation
	}
	for _, values := range query {
		if len(values) != 1 {
			return nil, ErrValidation
		}
	}
	if !validObjectID(query.Get("organizationId")) || !validObjectID(query.Get("organizationUserId")) || query.Get("token") == "" || len(query.Get("token")) > 16384 {
		return nil, ErrValidation
	}
	if invitation.Scheme != base.Scheme || invitation.Host != base.Host || strings.TrimSuffix(invitation.Path, "/") != strings.TrimSuffix(base.Path, "/") || query.Get("email") != email {
		return nil, ErrIdentity
	}
	return query, nil
}

func (s *Session) PrepareInvitationAcceptance(ctx context.Context, vault *VaultData, link string, persist func(SessionCheckpoint) error) (*InvitationAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	return s.prepareInvitationLocked(ctx, vault, link, persist)
}
func (s *Session) prepareInvitationLocked(ctx context.Context, vault *VaultData, link string, persist func(SessionCheckpoint) error) (*InvitationAcceptance, error) {
	query, err := invitationParameters(link, s.client.base, s.email)
	if err != nil {
		return nil, err
	}
	org := query.Get("organizationId")
	guard := s.organizationManagementGuardLocked(s.authorizationRevision)
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/accounts/profile", "", "", persist, guard)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, cipherUpdateStatusError(status, body)
	}
	var profile struct {
		ID, Email                       string
		Organizations, OrganizationsNew []Organization
	}
	if json.Unmarshal(body, &profile) != nil || profile.ID != s.account || profile.Email != s.email || profile.Organizations == nil || profile.OrganizationsNew == nil {
		return nil, ErrIdentity
	}
	for _, membership := range append(profile.Organizations, profile.OrganizationsNew...) {
		if membership.ID == org {
			if membership.OrganizationUserID != query.Get("organizationUserId") || membership.UserID != s.account {
				return nil, ErrIdentity
			}
			if membership.Status == 1 || membership.Status == 2 {
				return nil, ErrInvitationAlreadyAccepted
			}
			return nil, ErrPermission
		}
	}
	status, body, err = s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/organizations/"+org+"/policies/token?"+url.Values{"token": {query.Get("token")}}.Encode(), "", "", persist, guard)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, cipherUpdateStatusError(status, body)
	}
	var policies struct {
		Data []struct {
			OrganizationID string          `json:"organizationId"`
			Type           int             `json:"type"`
			Enabled        bool            `json:"enabled"`
			Data           json.RawMessage `json:"data"`
		}
		ContinuationToken *string `json:"continuationToken"`
	}
	if json.Unmarshal(body, &policies) != nil || policies.Data == nil || policies.ContinuationToken != nil {
		return nil, ErrProtocol
	}
	required := false
	seen := map[int]bool{}
	for _, policy := range policies.Data {
		if policy.OrganizationID != org || seen[policy.Type] {
			return nil, ErrIdentity
		}
		seen[policy.Type] = true
		if policy.Type == 8 && policy.Enabled {
			var options struct {
				AutoEnrollEnabled bool `json:"autoEnrollEnabled"`
			}
			if json.Unmarshal(policy.Data, &options) != nil {
				return nil, ErrProtocol
			}
			required = options.AutoEnrollEnabled
		}
	}
	canonical, err := json.Marshal(policies)
	if err != nil {
		return nil, ErrProtocol
	}
	draft := &InvitationAcceptance{scope: vault.Scope, revision: s.authorizationRevision, link: link, organization: org, member: query.Get("organizationUserId"), token: query.Get("token"), policies: string(canonical), recoveryRequired: required}
	if required {
		status, body, err = s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/organizations/"+org+"/public-key", "", "", persist, guard)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, cipherUpdateStatusError(status, body)
		}
		var reply struct {
			PublicKey string `json:"publicKey"`
		}
		if json.Unmarshal(body, &reply) != nil {
			return nil, ErrProtocol
		}
		if _, err = decodeRecoveryPublicKey(reply.PublicKey); err != nil {
			return nil, err
		}
		draft.recoveryPublicKey = reply.PublicKey
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	draft.epoch = s.authorizationEpoch
	return draft, nil
}

func decodeRecoveryPublicKey(encoded string) (*rsa.PublicKey, error) {
	if len(encoded) > 16384 {
		return nil, ErrProtocol
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, ErrProtocol
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, ErrProtocol
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E != 65537 {
		return nil, ErrProtocol
	}
	return key, nil
}

// AcceptPreparedInvitation re-reads policies and the recovery key immediately
// before writing. Consent never survives a changed policy, key or local revision.
// There is no server CAS between those reads and the acceptance write.
func (s *Session) AcceptPreparedInvitation(ctx context.Context, vault *VaultData, draft *InvitationAcceptance, recoveryConsent bool, trustedPublicKey string, persist func(SessionCheckpoint) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	if draft == nil || draft.consumed || draft.epoch != s.authorizationEpoch || draft.scope != vault.Scope || draft.revision == "" || draft.revision != s.authorizationRevision {
		return ErrExpired
	}
	if draft.recoveryRequired && (!recoveryConsent || trustedPublicKey != draft.recoveryPublicKey) {
		return ErrPermission
	}
	current, err := s.prepareInvitationLocked(ctx, vault, draft.link, persist)
	if err != nil {
		return err
	}
	defer current.Close()
	if current.epoch != draft.epoch {
		return ErrExpired
	}
	if current.policies != draft.policies || current.recoveryPublicKey != draft.recoveryPublicKey || current.recoveryRequired != draft.recoveryRequired {
		return ErrConflict
	}
	payload := map[string]string{"token": draft.token}
	if current.recoveryRequired {
		key, err := decodeRecoveryPublicKey(current.recoveryPublicKey)
		if err != nil {
			return err
		}
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, s.key, nil)
		if err != nil {
			return ErrEncryption
		}
		payload["resetPasswordKey"] = "3." + base64.StdEncoding.EncodeToString(wrapped)
	}
	draft.consumed = true // A dispatched or uncertain acceptance is never replayed from this consent.
	guard := s.organizationManagementGuardLocked(draft.revision)
	return s.memberWriteGuardedLocked(ctx, http.MethodPost, "/api/organizations/"+draft.organization+"/users/"+draft.member+"/accept", payload, persist, func() error {
		if s.authorizationEpoch != draft.epoch {
			return ErrExpired
		}
		return guard()
	})
}
