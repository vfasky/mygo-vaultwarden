// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type AccountRotationFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type AccountRotationEmergency struct {
	ID           string `json:"id"`
	KeyEncrypted string `json:"keyEncrypted"`
}
type AccountRotationRecovery struct {
	OrganizationID   string `json:"organizationId"`
	ResetPasswordKey string `json:"resetPasswordKey"`
}
type AccountRotationData struct {
	Ciphers []json.RawMessage       `json:"ciphers"`
	Folders []AccountRotationFolder `json:"folders"`
	Sends   []json.RawMessage       `json:"sends"`
}
type AccountRotationMasterUnlock struct {
	KDFType        int    `json:"kdfType"`
	KDFIterations  int    `json:"kdfIterations"`
	KDFMemory      *int   `json:"kdfMemory"`
	KDFParallelism *int   `json:"kdfParallelism"`
	Email          string `json:"email"`
	Hash           string `json:"masterKeyAuthenticationHash"`
	Key            string `json:"masterKeyEncryptedUserKey"`
}
type AccountRotationUnlock struct {
	Emergency []AccountRotationEmergency  `json:"emergencyAccessUnlockData"`
	Master    AccountRotationMasterUnlock `json:"masterPasswordUnlockData"`
	Recovery  []AccountRotationRecovery   `json:"organizationAccountRecoveryUnlockData"`
}
type AccountRotationKeys struct {
	PrivateKey string `json:"userKeyEncryptedAccountPrivateKey"`
	PublicKey  string `json:"accountPublicKey"`
}

// AccountRotationRequest mirrors 1.37.4 KeyData, including all five resource sets.
type AccountRotationRequest struct {
	Unlock  AccountRotationUnlock `json:"accountUnlockData"`
	Keys    AccountRotationKeys   `json:"accountKeys"`
	Data    AccountRotationData   `json:"accountData"`
	OldHash string                `json:"oldMasterKeyAuthenticationHash"`
}

// AccountRotationInput is borrowed during Convert. It must not be retained or
// modified. Read is a scoped authenticated GET transport; do NOT call public
// Session methods from an adapter, since the session mutex is held.
type AccountRotationInput struct {
	Scope                  Scope
	Revision               string
	Epoch                  uint64
	SnapshotHash           [32]byte
	Sync                   json.RawMessage
	OldUserKey, NewUserKey []byte
	Read                   func(context.Context, string) (json.RawMessage, error)
}

// Coverage is the trusted recovery adapter's attestation of actual server
// enumeration and identity/public-key verification, never a UI-provided switch.
// Empty lists are valid only after both enumerations succeeded. An adapter must
// reject pagination, unknown schema, identity/state or public key mismatch.
type AccountRotationCoverage struct {
	Scope                                 Scope
	Revision                              string
	Epoch                                 uint64
	SnapshotHash                          [32]byte
	EmergencyComplete, RecoveryComplete   bool
	EmergencyIDs, RecoveryOrganizationIDs []string
}
type AccountRotationConversion struct {
	Data      AccountRotationData
	Emergency []AccountRotationEmergency
	Recovery  []AccountRotationRecovery
	Coverage  AccountRotationCoverage
	// Revalidate must re-read recipient/recovery identities and public keys before
	// POST and reject changes since Convert. Capture only nonsecret metadata;
	// borrowed Sync/keys are already cleared when this callback runs.
	Revalidate func(context.Context, func(context.Context, string) (json.RawMessage, error)) error
}

// Implemented by trusted schema owners, wired by the app integration. Convert
// must re-encrypt every field still using the old user key, validate all returned
// encrypted objects, and preserve unknown fields/large JSON integers or fail.
// Account code does not infer that a raw cipher/Send with matching ID is valid.
type AccountRotationAdapter interface {
	Convert(context.Context, AccountRotationInput) (AccountRotationConversion, error)
}

func accountExactIDs(want, got []string) error {
	if len(want) != len(got) {
		return ErrValidation
	}
	set := map[string]bool{}
	for _, id := range want {
		if !validObjectID(id) || set[id] {
			return ErrProtocol
		}
		set[id] = true
	}
	for _, id := range got {
		if !set[id] {
			return ErrValidation
		}
		delete(set, id)
	}
	if len(set) != 0 {
		return ErrValidation
	}
	return nil
}
func accountRawIDs(rows []json.RawMessage, personal bool) ([]string, error) {
	if rows == nil || len(rows) > 100000 {
		return nil, ErrProtocol
	}
	out := []string{}
	for _, row := range rows {
		var v struct {
			ID             string  `json:"id"`
			OrganizationID *string `json:"organizationId"`
		}
		if strictJSON(row) != nil || json.Unmarshal(row, &v) != nil || !validObjectID(v.ID) {
			return nil, ErrProtocol
		}
		if personal && v.OrganizationID != nil {
			continue
		}
		out = append(out, v.ID)
	}
	return out, nil
}
func validateAccountRotation(sync []byte, c AccountRotationConversion, input AccountRotationInput) error {
	if c.Revalidate == nil {
		return ErrValidation
	}
	if c.Coverage.Scope != input.Scope || c.Coverage.Revision != input.Revision || c.Coverage.Epoch != input.Epoch || c.Coverage.SnapshotHash != input.SnapshotHash || !c.Coverage.EmergencyComplete || !c.Coverage.RecoveryComplete {
		return ErrIdentity
	}
	var original struct{ Ciphers, Folders, Sends []json.RawMessage }
	if json.Unmarshal(sync, &original) != nil {
		return ErrProtocol
	}
	for _, pair := range []struct {
		old, new []json.RawMessage
		personal bool
	}{{original.Ciphers, c.Data.Ciphers, true}, {original.Sends, c.Data.Sends, false}} {
		want, err := accountRawIDs(pair.old, pair.personal)
		if err != nil {
			return err
		}
		got, err := accountRawIDs(pair.new, false)
		if err != nil {
			return err
		}
		if err = accountExactIDs(want, got); err != nil {
			return err
		}
		if pair.personal {
			for _, row := range pair.new {
				var v struct {
					OrganizationID *string `json:"organizationId"`
				}
				_ = json.Unmarshal(row, &v)
				if v.OrganizationID != nil {
					return ErrIdentity
				}
			}
		}
	}
	want, err := accountRawIDs(original.Folders, false)
	if err != nil {
		return err
	}
	got := []string{}
	if c.Data.Folders == nil || c.Emergency == nil || c.Recovery == nil {
		return ErrProtocol
	}
	for _, v := range c.Data.Folders {
		if !strings.HasPrefix(v.Name, "2.") {
			return ErrEncryption
		}
		got = append(got, v.ID)
	}
	if err = accountExactIDs(want, got); err != nil {
		return err
	}
	got = nil
	for _, v := range c.Emergency {
		if !strings.HasPrefix(v.KeyEncrypted, "3.") && !strings.HasPrefix(v.KeyEncrypted, "4.") {
			return ErrEncryption
		}
		got = append(got, v.ID)
	}
	if err = accountExactIDs(c.Coverage.EmergencyIDs, got); err != nil {
		return err
	}
	got = nil
	for _, v := range c.Recovery {
		if !strings.HasPrefix(v.ResetPasswordKey, "3.") && !strings.HasPrefix(v.ResetPasswordKey, "4.") {
			return ErrEncryption
		}
		got = append(got, v.OrganizationID)
	}
	return accountExactIDs(c.Coverage.RecoveryOrganizationIDs, got)
}

// AccountRewrapRotationObject is for independent cipher keys (64B) and Send
// seeds (16B). It preserves every other raw field. Legacy keyless ciphers MUST
// use the legacy schema adapter; this helper refuses them.
func AccountRewrapRotationObject(raw json.RawMessage, oldKey, newKey []byte, keyBytes int) (json.RawMessage, error) {
	if keyBytes != 16 && keyBytes != 64 {
		return nil, ErrValidation
	}
	if strictJSON(raw) != nil {
		return nil, ErrProtocol
	}
	var fields map[string]json.RawMessage
	var wrapped string
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(fields["key"], &wrapped) != nil || wrapped == "" {
		return nil, ErrEncryption
	}
	key, err := DecryptString(wrapped, oldKey)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if len(key) != keyBytes {
		return nil, ErrEncryption
	}
	encrypted, err := EncryptString(key, newKey)
	if err != nil {
		return nil, err
	}
	fields["key"], _ = json.Marshal(encrypted)
	return json.Marshal(fields)
}
func AccountRewrapRotationFolder(folder AccountRotationFolder, oldKey, newKey []byte) (AccountRotationFolder, error) {
	if !validObjectID(folder.ID) {
		return AccountRotationFolder{}, ErrValidation
	}
	name, err := DecryptString(folder.Name, oldKey)
	if err != nil {
		return AccountRotationFolder{}, err
	}
	defer clear(name)
	folder.Name, err = EncryptString(name, newKey)
	return folder, err
}
func (s *Session) PrepareAccountRotation(ctx context.Context, vault *VaultData, password []byte, adapter AccountRotationAdapter, persist func(SessionCheckpoint) error) (*AccountChangePlan, error) {
	if adapter == nil {
		return nil, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err = s.snapshotPoliciesLocked(vault); err != nil {
		return nil, err
	}
	if _, err = s.accountPolicyLocked(ctx, password, persist); err != nil {
		return nil, err
	}
	// Fresh server inventory must exactly match the reviewed complete snapshot.
	status, fresh, err := s.authenticatedLocked(ctx, "GET", "/api/sync", "", "", persist)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, statusError(status)
	}
	if _, err = parseOperationPolicies(fresh, vault.Scope, s.email, s.wrapped); err != nil {
		return nil, err
	}
	var a, b map[string]json.RawMessage
	if json.Unmarshal(fresh, &a) != nil || json.Unmarshal(vault.Sync, &b) != nil {
		return nil, ErrProtocol
	}
	for _, name := range []string{"profile", "ciphers", "folders", "sends"} {
		if len(a[name]) == 0 || (name == "ciphers" && !AccountRotationCipherInventoryEqual(a[name], b[name])) || (name != "ciphers" && !rawJSONEqual(a[name], b[name])) {
			return nil, ErrConflict
		}
	}
	if _, err = s.snapshotPoliciesLocked(vault); err != nil {
		return nil, err
	}
	newKey := make([]byte, 64)
	if _, err = rand.Read(newKey); err != nil {
		return nil, ErrEncryption
	}
	defer clear(newKey)
	digest, _ := snapshotDigest(vault)
	input := AccountRotationInput{Scope: vault.Scope, Revision: s.authorizationRevision, Epoch: s.authorizationEpoch, SnapshotHash: digest, Sync: append([]byte(nil), fresh...), OldUserKey: append([]byte(nil), s.key...), NewUserKey: append([]byte(nil), newKey...)}
	defer clear(input.Sync)
	defer clear(input.OldUserKey)
	defer clear(input.NewUserKey)
	input.Read = func(ctx context.Context, path string) (json.RawMessage, error) {
		if !strings.HasPrefix(path, "/api/emergency-access/") && !strings.HasPrefix(path, "/api/organizations/") && !strings.HasPrefix(path, "/api/users/") {
			return nil, ErrPermission
		}
		status, body, err := s.authenticatedLocked(ctx, "GET", path, "", "", persist)
		if err != nil {
			return nil, err
		}
		if path == emergencyAvailabilityPath {
			return recoveryAvailabilityResponse(status, body)
		}
		if status != 200 {
			return nil, statusError(status)
		}
		if strictJSON(body) != nil {
			return nil, ErrProtocol
		}
		return body, nil
	}
	originalHash := sha256.Sum256(input.Sync)
	converted, err := adapter.Convert(ctx, input)
	if err != nil {
		return nil, err
	}
	if originalHash != sha256.Sum256(input.Sync) || !bytes.Equal(input.OldUserKey, s.key) || !bytes.Equal(input.NewUserKey, newKey) {
		return nil, ErrIdentity
	}
	if err = validateAccountRotation(fresh, converted, input); err != nil {
		return nil, err
	}
	if input.Epoch != s.authorizationEpoch || input.Revision != s.authorizationRevision {
		return nil, ErrExpired
	}
	status, keyBody, err := s.authenticatedLocked(ctx, "GET", "/api/accounts/keys", "", "", persist)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, statusError(status)
	}
	var profile struct {
		PrivateKey string `json:"privateKey"`
		PublicKey  string `json:"publicKey"`
		Key        string `json:"key"`
	}
	var syncProfile struct {
		PrivateKey string `json:"privateKey"`
	}
	if strictJSON(keyBody) != nil || json.Unmarshal(keyBody, &profile) != nil || json.Unmarshal(a["profile"], &syncProfile) != nil || profile.PublicKey == "" || profile.Key != s.wrapped || profile.PrivateKey != syncProfile.PrivateKey {
		return nil, ErrIdentity
	}
	// Validate that the unchanged public and private RSA material are the same pair.
	private, err := accountPrivateKey(a["profile"], s.key)
	if err != nil {
		return nil, err
	}
	publicDER, keyErr := x509.MarshalPKIXPublicKey(&private.PublicKey)
	clearAccountPrivateKey(private)
	expectedDER, decodeErr := base64.StdEncoding.Strict().DecodeString(profile.PublicKey)
	if keyErr != nil || decodeErr != nil || !bytes.Equal(publicDER, expectedDER) {
		return nil, ErrIdentity
	}
	der, err := DecryptString(profile.PrivateKey, s.key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	privateWrapped, err := EncryptString(der, newKey)
	if err != nil {
		return nil, err
	}
	kdf := s.passwordUnlock.Config.KDF
	master, err := DeriveMaster(password, s.email, kdf)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	stretched, err := StretchMaster(master)
	if err != nil {
		return nil, err
	}
	defer clear(stretched)
	wrapped, err := EncryptString(newKey, stretched)
	if err != nil {
		return nil, err
	}
	hash := AuthorizationHash(master, password)
	unlock := AccountRotationMasterUnlock{KDFType: kdf.Type, KDFIterations: kdf.Iterations, Email: s.email, Hash: hash, Key: wrapped}
	if kdf.Type == 1 {
		unlock.KDFMemory = &kdf.Memory
		unlock.KDFParallelism = &kdf.Parallelism
	}
	request := AccountRotationRequest{Unlock: AccountRotationUnlock{Emergency: converted.Emergency, Master: unlock, Recovery: converted.Recovery}, Keys: AccountRotationKeys{PrivateKey: privateWrapped, PublicKey: profile.PublicKey}, Data: converted.Data, OldHash: hash}
	body, err := json.Marshal(request)
	if err != nil || len(body) > maxResponse {
		return nil, ErrProtocol
	}
	defer clear(body)
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	plan, err := s.accountPlanLocked(vault, AccountRotateKey, "/api/accounts/key-management/rotate-user-account-keys", body)
	if err != nil {
		return nil, err
	}
	plan.recovery.NewUserKey = append([]byte(nil), newKey...)
	plan.recovery.NewWrappedKey = wrapped
	// Retain only ciphertext server inventory and trusted metadata guard. The
	// adapter's borrowed key/sync copies are cleared at the end of prepare.
	read := input.Read
	plan.preflight = func(ctx context.Context) error {
		status, current, err := s.authenticatedLocked(ctx, "GET", "/api/sync", "", "", persist)
		if err != nil {
			return err
		}
		if status != 200 {
			return statusError(status)
		}
		var actual map[string]json.RawMessage
		if strictJSON(current) != nil || json.Unmarshal(current, &actual) != nil {
			return ErrProtocol
		}
		for _, name := range []string{"profile", "ciphers", "folders", "sends"} {
			if (name == "ciphers" && !AccountRotationCipherInventoryEqual(actual[name], a[name])) || (name != "ciphers" && !rawJSONEqual(actual[name], a[name])) {
				return ErrConflict
			}
		}
		return converted.Revalidate(ctx, read)
	}
	return plan, nil
}
func (c AccountRotationCoverage) String() string {
	return fmt.Sprintf("rotation coverage (%d emergency, %d recovery)", len(c.EmergencyIDs), len(c.RecoveryOrganizationIDs))
}
