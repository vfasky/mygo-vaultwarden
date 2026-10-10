// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/http"
	"net/mail"
	"strings"
)

// OrganizationProfile contains server plaintext metadata, never organization keys.
type OrganizationProfile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	BillingEmail string `json:"billingEmail"`
}

type OrganizationSettings struct {
	Name           string
	BillingEmail   string
	CollectionName string
}

func validateOrganizationSettings(settings OrganizationSettings, create bool) error {
	if strings.TrimSpace(settings.Name) == "" || len(settings.Name) > 1024 || len(settings.BillingEmail) > 320 || (create && (strings.TrimSpace(settings.CollectionName) == "" || len(settings.CollectionName) > 1024)) {
		return ErrValidation
	}
	address, err := mail.ParseAddress(settings.BillingEmail)
	if err != nil || address.Address != settings.BillingEmail {
		return ErrValidation
	}
	return nil
}

func (s *Session) organizationManagementLocked(vault *VaultData, orgID string, owner bool) error {
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	for _, org := range data.organizations {
		if org.ID == orgID && (!owner || org.Type == 0) {
			return nil
		}
	}
	return ErrPermission
}

// Management reads use the same checkpoint and snapshot guard as writes: a
// refreshed session must be durable before even an authenticated GET proceeds.
func (s *Session) organizationManagementGuardLocked(revision string) func() error {
	return func() error {
		if !s.itemSessionActiveLocked() || revision == "" || revision != s.authorizationRevision {
			return ErrExpired
		}
		return nil
	}
}

func (s *Session) OrganizationProfile(ctx context.Context, vault *VaultData, orgID string, persist func(SessionCheckpoint) error) (OrganizationProfile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return OrganizationProfile{}, err
	}
	defer finish()
	if err := s.organizationManagementLocked(vault, orgID, true); err != nil {
		return OrganizationProfile{}, err
	}
	guard := s.organizationManagementGuardLocked(s.authorizationRevision)
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/organizations/"+orgID, "", "", persist, guard)
	if err != nil {
		return OrganizationProfile{}, err
	}
	if status != http.StatusOK {
		return OrganizationProfile{}, cipherUpdateStatusError(status, body)
	}
	var profile OrganizationProfile
	if json.Unmarshal(body, &profile) != nil || profile.ID != orgID {
		return OrganizationProfile{}, ErrIdentity
	}
	if ctx.Err() != nil {
		return OrganizationProfile{}, ErrCancelled
	}
	return profile, nil
}

// SaveOrganization creates a fresh organization key and encrypts only the default
// collection name. The creator's verified account RSA public key wraps that key.
// Server creation is multi-step; every response failure requires sync, never retry.
func (s *Session) SaveOrganization(ctx context.Context, vault *VaultData, orgID string, settings OrganizationSettings, persist func(SessionCheckpoint) error) (OrganizationProfile, error) {
	if err := validateOrganizationSettings(settings, orgID == ""); err != nil {
		return OrganizationProfile{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return OrganizationProfile{}, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return OrganizationProfile{}, err
	}
	defer data.close()
	body := map[string]any{"name": settings.Name, "billingEmail": settings.BillingEmail}
	method, path := http.MethodPut, "/api/organizations/"+orgID
	guard := s.organizationManagementGuardLocked(s.authorizationRevision)
	if orgID == "" {
		policies, err := s.operationPoliciesLocked(ctx, persist)
		if err != nil {
			return OrganizationProfile{}, err
		}
		if policies.singleOrganization {
			return OrganizationProfile{}, fmt.Errorf(i18n.T("server.organization.err_single_organization_policy"), ErrPermission)
		}
		previousGuard := guard
		guard = func() error {
			if err := s.checkOperationPoliciesLocked(ctx, policies); err != nil {
				return err
			}
			return previousGuard()
		}
		if err := guard(); err != nil {
			return OrganizationProfile{}, err
		}
		var sync struct{ Profile json.RawMessage }
		if json.Unmarshal(vault.Sync, &sync) != nil {
			return OrganizationProfile{}, ErrProtocol
		}
		private, err := accountPrivateKey(sync.Profile, s.key)
		if err != nil {
			return OrganizationProfile{}, err
		}
		defer clearAccountPrivateKey(private)
		key := make([]byte, 64)
		defer clear(key)
		if _, err := rand.Read(key); err != nil {
			return OrganizationProfile{}, ErrEncryption
		}
		encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &private.PublicKey, key, nil)
		if err != nil {
			return OrganizationProfile{}, ErrEncryption
		}
		collection, err := vaultcrypto.EncryptString([]byte(settings.CollectionName), key)
		if err != nil {
			return OrganizationProfile{}, err
		}
		pair, err := makeOrganizationKeyPair(key)
		if err != nil {
			return OrganizationProfile{}, err
		}
		body["keys"] = pair
		body["key"], body["collectionName"], body["planType"] = "3."+base64.StdEncoding.EncodeToString(encrypted), collection, 0
		method, path = http.MethodPost, "/api/organizations"
	} else {
		owner := false
		for _, org := range data.organizations {
			if org.ID == orgID && org.Type == 0 {
				owner = true
			}
		}
		if !owner {
			return OrganizationProfile{}, ErrPermission
		}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return OrganizationProfile{}, ErrProtocol
	}
	status, response, err := s.authenticatedGuardedLocked(ctx, method, path, "application/json", string(encoded), persist, guard)
	if err != nil {
		return OrganizationProfile{}, err
	}
	if status != http.StatusOK {
		return OrganizationProfile{}, &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	var result OrganizationProfile
	if json.Unmarshal(response, &result) != nil || !validObjectID(result.ID) || (orgID != "" && result.ID != orgID) {
		return OrganizationProfile{}, &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return OrganizationProfile{}, &MutationUncertainError{Cause: ErrCancelled}
	}
	return result, nil
}

func clearAccountPrivateKey(private *rsa.PrivateKey) {
	private.D.SetInt64(0)
	for _, prime := range private.Primes {
		prime.SetInt64(0)
	}
	private.Precomputed = rsa.PrecomputedValues{}
}

// LeaveOrganization relies on the server's live last-owner check; an offline
// member count cannot authorize leaving. All outcomes are reconciled by sync.
func (s *Session) LeaveOrganization(ctx context.Context, vault *VaultData, orgID string, isolate, persist func(SessionCheckpoint) error) error {
	return s.removeOrganization(ctx, vault, orgID, nil, isolate, persist)
}

// DeleteOrganization verifies with the current account KDF. Password bytes are
// borrowed only for this call; callers must clear their input when it completes.
func (s *Session) DeleteOrganization(ctx context.Context, vault *VaultData, orgID string, password []byte, isolate, persist func(SessionCheckpoint) error) error {
	if len(password) == 0 || len(password) > 4096 {
		return ErrValidation
	}
	return s.removeOrganization(ctx, vault, orgID, password, isolate, persist)
}

func (s *Session) removeOrganization(ctx context.Context, vault *VaultData, orgID string, password []byte, isolate, persist func(SessionCheckpoint) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if err := s.organizationManagementLocked(vault, orgID, password != nil); err != nil {
		return err
	}
	guard := s.organizationManagementGuardLocked(s.authorizationRevision)
	method, path, body := http.MethodPost, "/api/organizations/"+orgID+"/leave", ""
	if password != nil {
		if s.passwordUnlock == nil {
			return ErrPermission
		}
		config := s.passwordUnlock.Config
		master, err := vaultcrypto.DeriveMaster(password, config.Email, config.KDF)
		if err != nil {
			return err
		}
		defer clear(master)
		encoded, err := json.Marshal(map[string]string{"masterPasswordHash": vaultcrypto.AuthorizationHash(master, password)})
		if err != nil {
			return ErrProtocol
		}
		method, path, body = http.MethodDelete, "/api/organizations/"+orgID, string(encoded)
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	// No destructive request may escape before local isolation is durable.
	if isolate == nil {
		return ErrCheckpoint
	}
	if err := s.checkpointLocked(isolate); err != nil {
		return ErrCheckpoint
	}
	status, response, err := s.authenticatedGuardedLocked(ctx, method, path, "application/json", body, persist, guard)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
