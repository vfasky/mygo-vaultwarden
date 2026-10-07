// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

type organizationKeyPair struct {
	PublicKey           string `json:"publicKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
}

func makeOrganizationKeyPair(key []byte) (organizationKeyPair, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return organizationKeyPair{}, ErrEncryption
	}
	defer clearAccountPrivateKey(private)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return organizationKeyPair{}, ErrEncryption
	}
	defer clear(der)
	encrypted, err := EncryptString(der, key)
	if err != nil {
		return organizationKeyPair{}, err
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return organizationKeyPair{}, ErrEncryption
	}
	return organizationKeyPair{base64.StdEncoding.EncodeToString(public), encrypted}, nil
}

// OrganizationRecoveryPublicKey loads the public key for trusted-channel sharing.
// initialize must follow explicit UI consent; it creates only a missing key pair.
// Existing keys are never rotated. The server also rejects replacement atomically.
func (s *Session) OrganizationRecoveryPublicKey(ctx context.Context, vault *VaultData, orgID string, initialize bool, persist func(SessionCheckpoint) error) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return "", err
	}
	defer finish()
	if err = s.organizationManagementLocked(vault, orgID, true); err != nil {
		return "", err
	}
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return "", err
	}
	defer data.close()
	guard := s.organizationManagementGuardLocked(s.authorizationRevision)
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/organizations/"+orgID+"/public-key", "", "", persist, guard)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", cipherUpdateStatusError(status, body)
	}
	var response struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields["publicKey"] == nil || json.Unmarshal(body, &response) != nil {
		return "", ErrProtocol
	}
	if response.PublicKey != "" {
		if _, err = decodeRecoveryPublicKey(response.PublicKey); err != nil {
			return "", err
		}
		return response.PublicKey, nil
	}
	if !initialize {
		return "", nil
	}
	pair, err := makeOrganizationKeyPair(data.keys[orgID])
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(pair)
	if err != nil {
		return "", ErrProtocol
	}
	status, body, err = s.authenticatedGuardedLocked(ctx, http.MethodPost, "/api/organizations/"+orgID+"/keys", "application/json", string(encoded), persist, guard)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", &MutationUncertainError{Cause: cipherUpdateStatusError(status, body)}
	}
	if json.Unmarshal(body, &response) != nil || response.PublicKey != pair.PublicKey || response.PrivateKey != pair.EncryptedPrivateKey {
		return "", &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return "", &MutationUncertainError{Cause: ErrCancelled}
	}
	return pair.PublicKey, nil
}
