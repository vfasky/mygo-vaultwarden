// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
)

type accountRecoveryDetails struct {
	Object              string `json:"object"`
	OrganizationUserID  string `json:"organizationUserId"`
	KDF                 int    `json:"kdf"`
	Iterations          int    `json:"kdfIterations"`
	Memory              int    `json:"kdfMemory"`
	Parallelism         int    `json:"kdfParallelism"`
	ResetPasswordKey    string `json:"resetPasswordKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
}

func (d accountRecoveryDetails) kdf() KDF {
	return KDF{Type: d.KDF, Iterations: d.Iterations, Memory: d.Memory, Parallelism: d.Parallelism}
}
func (s *Session) adminRecoveryDetailsLocked(ctx context.Context, org Organization, memberID string, persist func(SessionCheckpoint) error, guard func() error) (OrganizationMember, accountRecoveryDetails, error) {
	var details accountRecoveryDetails
	if err := guard(); err != nil {
		return OrganizationMember{}, details, err
	}
	rows, err := s.membersLocked(ctx, org, persist)
	if err != nil {
		return OrganizationMember{}, details, err
	}
	target, ok := memberIn(rows, memberID)
	if !ok || target.Status != 2 || target.UserID == s.account || (org.Type == 1 && target.Type == 0) {
		return target, details, ErrPermission
	}
	body, err := s.recoveryReadLocked(ctx, "/api/organizations/"+org.ID+"/users/"+memberID+"/reset-password-details", persist, guard)
	if err != nil {
		return target, details, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &details) != nil || json.Unmarshal(body, &fields) != nil || fields["kdf"] == nil || fields["kdfIterations"] == nil || details.OrganizationUserID != memberID || details.Object != "organizationUserResetPasswordDetails" || details.ResetPasswordKey == "" || details.EncryptedPrivateKey == "" {
		return target, details, ErrIdentity
	}
	return target, details, nil
}
func recoveryPasswordPayload(ctx context.Context, password []byte, email string, kdf KDF, userKey []byte, policy AccountPasswordPolicy) (string, string, error) {
	normalized, err := accountEmail(email)
	if err != nil || normalized != email {
		return "", "", ErrIdentity
	}
	// Keep the target's actual KDF, including supported legacy iteration counts.
	if policy.MinLength < 12 {
		policy.MinLength = 12
	}
	if err = policy.Check(ctx, password, email, false); err != nil {
		return "", "", err
	}
	master, err := DeriveMaster(password, email, kdf)
	if err != nil {
		return "", "", err
	}
	defer clear(master)
	stretched, err := StretchMaster(master)
	if err != nil {
		return "", "", err
	}
	defer clear(stretched)
	wrapped, err := EncryptString(userKey, stretched)
	if err != nil {
		return "", "", err
	}
	return AuthorizationHash(master, password), wrapped, nil
}
func decodeRecoveryPasswordPolicy(body []byte, orgID string) (AccountPasswordPolicy, error) {
	var row struct {
		OrganizationID string
		Type           *int
		Enabled        *bool
		Data           json.RawMessage
	}
	if json.Unmarshal(body, &row) != nil || row.OrganizationID != orgID || row.Type == nil || *row.Type != 1 || row.Enabled == nil {
		return AccountPasswordPolicy{}, ErrProtocol
	}
	if !*row.Enabled {
		return AccountPasswordPolicy{}, nil
	}
	var policy AccountPasswordPolicy
	decoder := json.NewDecoder(bytes.NewReader(row.Data))
	decoder.DisallowUnknownFields()
	if len(row.Data) == 0 || string(row.Data) == "null" || decoder.Decode(&policy) != nil {
		return policy, ErrProtocol
	}
	if policy.MinComplexity < 0 || policy.MinComplexity > 4 || policy.MinLength < 0 || policy.MinLength > 8192 {
		return policy, ErrProtocol
	}
	return policy, nil
}

// PrepareAdministratorRecovery never fetches a target /sync or interprets JWT
// roles. The server's details endpoint checks applicable policy/role. Other
// organizations, MFA providers and fallback email state remain server-owned.
func (s *Session) PrepareAdministratorRecovery(ctx context.Context, vault *VaultData, orgID, memberID, trustedOrgPublicKey string, newPassword []byte, resetPassword, resetTwoFactor bool, persist func(SessionCheckpoint) error) (*RecoveryPlan, error) {
	if !validObjectID(orgID) || !validObjectID(memberID) || (!resetPassword && !resetTwoFactor) {
		return nil, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	org, err := s.memberAdministratorLocked(vault, orgID)
	if err != nil {
		return nil, err
	}
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	epoch, revision := s.authorizationEpoch, s.authorizationRevision
	guard := s.recoveryGuardLocked(epoch, revision)
	if err = s.client.requireRecoveryCompatibility(ctx); err != nil {
		return nil, err
	}
	target, details, err := s.adminRecoveryDetailsLocked(ctx, org, memberID, persist, guard)
	if err != nil {
		return nil, err
	}
	payload := struct {
		NewMasterPasswordHash string `json:"newMasterPasswordHash,omitempty"`
		Key                   string `json:"key,omitempty"`
		ResetMasterPassword   bool   `json:"resetMasterPassword"`
		ResetTwoFactor        bool   `json:"resetTwoFactor"`
	}{ResetMasterPassword: resetPassword, ResetTwoFactor: resetTwoFactor}
	policyPath := "/api/organizations/" + orgID + "/policies/master-password"
	policyBody, err := s.recoveryReadLocked(ctx, policyPath, persist, guard)
	if err != nil {
		return nil, err
	}
	policy, err := decodeRecoveryPasswordPolicy(policyBody, orgID)
	if err != nil {
		return nil, err
	}
	// Prove that the encrypted organization private key matches independently
	// trusted SPKI, before decrypting any member recovery key.
	pubBody, err := s.recoveryReadLocked(ctx, "/api/organizations/"+orgID+"/public-key", persist, guard)
	if err != nil {
		return nil, err
	}
	var pub struct{ PublicKey string }
	if json.Unmarshal(pubBody, &pub) != nil || pub.PublicKey != trustedOrgPublicKey {
		return nil, ErrIdentity
	}
	profile, _ := json.Marshal(map[string]any{"privateKey": details.EncryptedPrivateKey, "accountKeys": map[string]any{"publicKeyEncryptionKeyPair": map[string]any{"wrappedPrivateKey": details.EncryptedPrivateKey, "publicKey": trustedOrgPublicKey}}})
	private, err := accountPrivateKey(profile, data.keys[orgID])
	if err != nil {
		return nil, err
	}
	defer clearAccountPrivateKey(private)
	key, err := unwrapOrganizationKey(details.ResetPasswordKey, private)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if resetPassword {
		payload.NewMasterPasswordHash, payload.Key, err = recoveryPasswordPayload(ctx, newPassword, target.Email, details.kdf(), key, policy)
		if err != nil {
			return nil, err
		}
	}
	impact := "管理员恢复会通知目标用户，并使旧授权失效；重置密码后必须重新登录、完整同步和核验。重置 MFA 可能启用邮件回退或触发组织策略，最终由服务器校验。HTTP 失败也可能部分成功，不能重试。"
	p, err := s.recoveryPlanLocked("administrator-recovery", "PUT", "/api/organizations/"+orgID+"/users/"+memberID+"/recover-account", memberID, target.UserID, impact, payload)
	if err != nil {
		return nil, err
	}
	p.epoch = epoch
	p.record.PreviousRevision = revision
	p.record.RequireTargetLogin = true
	p.record.OrganizationID = orgID
	p.record.MembershipID = memberID
	p.record.TargetEmail = target.Email
	p.record.Verification, err = recoveryExpectation(p.record.Kind, key, payload.Key, resetPassword, resetTwoFactor)
	if err != nil {
		p.Close()
		return nil, err
	}
	p.revalidate = func(ctx context.Context, persist func(SessionCheckpoint) error, guard func() error) error {
		if err := s.client.requireRecoveryCompatibility(ctx); err != nil {
			return err
		}
		fresh, freshDetails, e := s.adminRecoveryDetailsLocked(ctx, org, memberID, persist, guard)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(fresh, target) || !reflect.DeepEqual(freshDetails, details) {
			return ErrConflict
		}
		body, e := s.recoveryReadLocked(ctx, policyPath, persist, guard)
		if e != nil {
			return e
		}
		current, e := decodeRecoveryPasswordPolicy(body, orgID)
		if e != nil {
			return e
		}
		if current != policy {
			return ErrConflict
		}
		body, e = s.recoveryReadLocked(ctx, "/api/organizations/"+orgID+"/public-key", persist, guard)
		if e != nil {
			return e
		}
		var currentPub struct{ PublicKey string }
		if json.Unmarshal(body, &currentPub) != nil || currentPub.PublicKey != trustedOrgPublicKey {
			return ErrConflict
		}
		return nil
	}
	return p, nil
}
