// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// AccountSharingPublicKey derives the public half from the authenticated local
// private key, so recipients can supply it through an independent trusted channel.
func (s *Session) AccountSharingPublicKey(vault *VaultData) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return "", err
	}
	defer data.close()
	var sync struct{ Profile json.RawMessage }
	if json.Unmarshal(vault.Sync, &sync) != nil {
		return "", ErrProtocol
	}
	private, err := accountPrivateKey(sync.Profile, s.key)
	if err != nil {
		return "", err
	}
	defer clearAccountPrivateKey(private)
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return "", ErrEncryption
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// AcceptOrganizationInvitation consumes the exact same-server email link emitted
// by 1.37.4. It never follows the link or sends its token to its URL. Server JWT
// verification remains authoritative; acceptance alone does not release a key.
func (s *Session) AcceptOrganizationInvitation(ctx context.Context, vault *VaultData, link string, persist func(SessionCheckpoint) error) error {
	if len(link) > 32768 {
		return ErrValidation
	}
	invitation, err := url.Parse(link)
	if err != nil || invitation.User != nil || invitation.RawQuery != "" {
		return ErrValidation
	}
	fragment, err := url.Parse(invitation.Fragment)
	if err != nil || fragment.Path != "/accept-organization/" {
		return ErrValidation
	}
	query, err := url.ParseQuery(fragment.RawQuery)
	if err != nil {
		return ErrValidation
	}
	for _, values := range query {
		if len(values) != 1 {
			return ErrValidation
		}
	}
	org, member, token := query.Get("organizationId"), query.Get("organizationUserId"), query.Get("token")
	if !validObjectID(org) || !validObjectID(member) || token == "" || len(token) > 16384 {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if invitation.Scheme != s.client.base.Scheme || invitation.Host != s.client.base.Host || strings.TrimSuffix(invitation.Path, "/") != strings.TrimSuffix(s.client.base.Path, "/") || query.Get("email") != s.email {
		return ErrIdentity
	}
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	return s.memberWriteLocked(ctx, http.MethodPost, "/api/organizations/"+org+"/users/"+member+"/accept", map[string]string{"token": token}, persist)
}
