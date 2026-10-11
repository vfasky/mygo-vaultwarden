// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"time"
)

// WithOrganizationAPIKey borrows the returned secret only during consume. The
// callback must not re-enter Session. Retrieval can create a key server-side;
// rotation invalidates the previous key. Both require explicit confirmation.
// The UI owns clearing the borrowed password and must never log the secret.
func (s *Session) WithOrganizationAPIKey(ctx context.Context, vault *VaultData, orgID string, password []byte, rotate, confirmed bool, consume func(clientID string, secret []byte, revision time.Time) error, persist func(SessionCheckpoint) error) error {
	if !confirmed || consume == nil || !validObjectID(orgID) || len(password) == 0 || len(password) > 4096 {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := s.organizationManagementLocked(vault, orgID, true); err != nil {
		return err
	}
	if s.passwordUnlock == nil {
		return ErrPermission
	}
	config := s.passwordUnlock.Config
	master, err := vaultcrypto.DeriveOnlineMaster(password, config.Email, config.KDF)
	if err != nil {
		return err
	}
	defer clear(master)
	body, err := json.Marshal(map[string]string{"masterPasswordHash": vaultcrypto.AuthorizationHash(master, password)})
	if err != nil {
		return ErrProtocol
	}
	defer clear(body)
	path := "/api/organizations/" + orgID + "/api-key"
	if rotate {
		path = "/api/organizations/" + orgID + "/rotate-api-key"
	}
	status, response, err := s.authenticatedGuardedLocked(ctx, http.MethodPost, path, "application/json", string(body), persist, s.orgOperationGuardLocked())
	if err != nil {
		return err
	}
	defer clear(response)
	if status != http.StatusOK {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	var result struct{ APIKey, RevisionDate, Object string }
	if json.Unmarshal(response, &result) != nil || result.Object != "apiKey" || result.APIKey == "" || len(result.APIKey) > 4096 {
		return &MutationUncertainError{Cause: ErrProtocol}
	}
	revision, err := time.Parse(time.RFC3339Nano, result.RevisionDate)
	if err != nil {
		return &MutationUncertainError{Cause: ErrProtocol}
	}
	secret := []byte(result.APIKey)
	defer clear(secret)
	result.APIKey = ""
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return consume("organization."+orgID, secret, revision)
}
