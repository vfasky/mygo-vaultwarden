// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"reflect"
)

func (s *Session) emergencyActionReadLocked(ctx context.Context, id, action string, persist func(SessionCheckpoint) error, guard func() error) ([]byte, error) {
	status, body, err := s.authenticatedGuardedLocked(ctx, "POST", "/api/emergency-access/"+id+"/"+action, "application/json", "{}", persist, guard)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, statusError(status)
	}
	return body, nil
}
func (s *Session) emergencyUnwrapLocked(vault *VaultData, wrapped string) ([]byte, error) {
	var doc struct{ Profile json.RawMessage }
	if json.Unmarshal(vault.Sync, &doc) != nil {
		return nil, ErrProtocol
	}
	private, err := accountPrivateKey(doc.Profile, s.key)
	if err != nil {
		return nil, err
	}
	defer clearAccountPrivateKey(private)
	return unwrapOrganizationKey(wrapped, private)
}

// WithEmergencyView lends decrypted personal items only to an explicitly
// authorized read-only viewer. It never installs another user's sync/session,
// enables export/AutoFill/edit, or treats waitTimeDays as permission.
// The callback runs under the Session lock and must not reenter Session.
func (s *Session) WithEmergencyView(ctx context.Context, vault *VaultData, id string, consent bool, persist func(SessionCheckpoint) error, view func([]CipherFields) error) error {
	if !consent || view == nil || !validObjectID(id) {
		return ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer done()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return err
	}
	defer data.close()
	guard := s.recoveryGuardLocked(s.authorizationEpoch, s.authorizationRevision)
	rows, err := s.emergencyContactsLocked(ctx, false, persist, guard)
	if err != nil {
		return err
	}
	contact, err := emergencyFind(rows, id)
	if err != nil {
		return err
	}
	if !EmergencyActionAllowed(contact, false, "view") {
		return ErrPermission
	}
	body, err := s.emergencyActionReadLocked(ctx, id, "view", persist, guard)
	if err != nil {
		return err
	}
	defer clear(body)
	var reply struct {
		Ciphers              []json.RawMessage
		KeyEncrypted, Object string
	}
	if json.Unmarshal(body, &reply) != nil || reply.Object != "emergencyAccessView" || reply.Ciphers == nil {
		return ErrProtocol
	}
	key, err := s.emergencyUnwrapLocked(vault, reply.KeyEncrypted)
	if err != nil {
		return err
	}
	defer clear(key)
	fields := make([]CipherFields, 0, len(reply.Ciphers))
	defer clear(fields)
	seen := map[string]bool{}
	for _, raw := range reply.Ciphers {
		f, e := DecryptCipherDocument(CipherDocument{JSON: raw}, key)
		if e != nil {
			return e
		}
		if f.OrganizationID != nil || !validObjectID(f.ID) || seen[f.ID] {
			return ErrIdentity
		}
		seen[f.ID] = true
		f.Edit = false
		fields = append(fields, f)
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if err = guard(); err != nil {
		return err
	}
	return view(fields)
}

type emergencyTakeoverDetails struct {
	vaultcrypto.KDF
	KeyEncrypted, Object string
}

func (s *Session) emergencyTakeoverLocked(ctx context.Context, id string, persist func(SessionCheckpoint) error, guard func() error) (EmergencyContact, emergencyTakeoverDetails, []AccountPasswordPolicy, error) {
	var details emergencyTakeoverDetails
	rows, err := s.emergencyContactsLocked(ctx, false, persist, guard)
	if err != nil {
		return EmergencyContact{}, details, nil, err
	}
	contact, err := emergencyFind(rows, id)
	if err != nil {
		return contact, details, nil, err
	}
	if !EmergencyActionAllowed(contact, false, "takeover") {
		return contact, details, nil, ErrPermission
	}
	body, err := s.emergencyActionReadLocked(ctx, id, "takeover", persist, guard)
	if err != nil {
		return contact, details, nil, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &details) != nil || json.Unmarshal(body, &fields) != nil || fields["kdf"] == nil || fields["kdfIterations"] == nil || details.Object != "emergencyAccessTakeover" || details.KeyEncrypted == "" {
		return contact, details, nil, ErrProtocol
	}
	body, err = s.recoveryReadLocked(ctx, "/api/emergency-access/"+id+"/policies", persist, guard)
	if err != nil {
		return contact, details, nil, err
	}
	var list struct {
		Data              []json.RawMessage
		ContinuationToken json.RawMessage
		Object            string
	}
	if json.Unmarshal(body, &list) != nil || list.Data == nil || string(list.ContinuationToken) != "null" || list.Object != "list" {
		return contact, details, nil, ErrProtocol
	}
	policies := []AccountPasswordPolicy{}
	seen := map[string]bool{}
	for _, raw := range list.Data {
		var row struct {
			OrganizationID string
			Type           *int
		}
		if json.Unmarshal(raw, &row) != nil || row.Type == nil || !validObjectID(row.OrganizationID) {
			return contact, details, nil, ErrProtocol
		}
		if *row.Type != 1 {
			continue
		}
		if seen[row.OrganizationID] {
			return contact, details, nil, ErrIdentity
		}
		seen[row.OrganizationID] = true
		p, e := decodeRecoveryPasswordPolicy(raw, row.OrganizationID)
		if e != nil {
			return contact, details, nil, e
		}
		policies = append(policies, p)
	}
	return contact, details, policies, nil
}

// PrepareEmergencyTakeover changes only the target password wrapper, retaining
// its exact current KDF and user key. Explicit confirmation must disclose that
// 1.37.4 also removes all MFA and non-owner organization memberships.
func (s *Session) PrepareEmergencyTakeover(ctx context.Context, vault *VaultData, id string, newPassword []byte, persist func(SessionCheckpoint) error) (*RecoveryPlan, error) {
	if !validObjectID(id) {
		return nil, ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
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
	target, details, policies, err := s.emergencyTakeoverLocked(ctx, id, persist, guard)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		if err = p.Check(ctx, newPassword, target.Email, false); err != nil {
			return nil, err
		}
	}
	key, err := s.emergencyUnwrapLocked(vault, details.KeyEncrypted)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	hash, wrapped, err := recoveryPasswordPayload(ctx, newPassword, target.Email, details.KDF, key, AccountPasswordPolicy{})
	if err != nil {
		return nil, err
	}
	payload := struct {
		NewMasterPasswordHash string `json:"newMasterPasswordHash"`
		Key                   string `json:"key"`
	}{hash, wrapped}
	impact := "接管将更改目标账号主密码，删除全部 MFA，并移除其所有非所有者组织成员关系。旧会话和 AutoFill 必须失效；重新登录和完整同步核验前不能恢复。失败可能部分执行，不能重复提交。"
	p, err := s.recoveryPlanLocked("emergency-takeover", "POST", "/api/emergency-access/"+id+"/password", id, target.GrantorID, impact, payload)
	if err != nil {
		return nil, err
	}
	p.epoch = epoch
	p.record.PreviousRevision = revision
	p.record.RequireTargetLogin = true
	p.record.TargetEmail = target.Email
	p.record.Verification, err = recoveryExpectation(p.record.Kind, key, wrapped, true, true)
	if err != nil {
		p.Close()
		return nil, err
	}
	p.record.CounterpartyID, p.record.CounterpartyEmail = target.GrantorID, target.Email
	p.record.EmergencyType, p.record.WaitTimeDays = target.Type, target.WaitTimeDays
	p.revalidate = func(ctx context.Context, persist func(SessionCheckpoint) error, guard func() error) error {
		if err := s.client.requireRecoveryCompatibility(ctx); err != nil {
			return err
		}
		current, currentDetails, currentPolicies, e := s.emergencyTakeoverLocked(ctx, id, persist, guard)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(current, target) || !reflect.DeepEqual(currentDetails, details) || !reflect.DeepEqual(currentPolicies, policies) {
			return ErrConflict
		}
		return nil
	}
	return p, nil
}
