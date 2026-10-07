// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	draft, err := s.PrepareInvitationAcceptance(ctx, vault, link, persist)
	if err != nil {
		return err
	}
	defer draft.Close()
	return s.AcceptPreparedInvitation(ctx, vault, draft, false, "", persist)
}
