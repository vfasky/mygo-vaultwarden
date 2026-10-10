// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"reflect"
)

type recoveryEnrollmentState struct {
	Organization, Membership, User, PublicKey string
	Enrolled, AutoEnroll                      bool
	Policy                                    json.RawMessage
}

func (s *Session) recoveryEnrollmentLocked(ctx context.Context, orgID string, persist func(SessionCheckpoint) error, guard func() error) (recoveryEnrollmentState, error) {
	var state recoveryEnrollmentState
	body, err := s.recoveryReadLocked(ctx, "/api/sync", persist, guard)
	if err != nil {
		return state, err
	}
	var response struct {
		Profile struct {
			ID, Email, Key string
			Organizations  []struct {
				Organization
				ResetPasswordEnrolled *bool
			}
		}
		Policies []struct {
			OrganizationID string
			Type           int
			Enabled        bool
			Data           json.RawMessage
		}
	}
	if json.Unmarshal(body, &response) != nil || response.Profile.ID != s.account || response.Profile.Email != s.email || response.Profile.Key != s.wrapped || response.Profile.Organizations == nil || response.Policies == nil {
		return state, ErrIdentity
	}
	found := false
	for _, org := range response.Profile.Organizations {
		if org.ID != orgID {
			continue
		}
		if found || org.Status != 2 || !org.Enabled || org.UserID != s.account || !validObjectID(org.OrganizationUserID) || org.ResetPasswordEnrolled == nil {
			return state, ErrPermission
		}
		found = true
		state.Organization = orgID
		state.Membership = org.OrganizationUserID
		state.User = org.UserID
		state.Enrolled = *org.ResetPasswordEnrolled
	}
	if !found {
		return state, ErrPermission
	}
	found = false
	for _, policy := range response.Policies {
		if policy.OrganizationID != orgID || policy.Type != 8 {
			continue
		}
		if found || !policy.Enabled {
			return state, ErrPermission
		}
		found = true
		var options struct {
			AutoEnrollEnabled bool `json:"autoEnrollEnabled"`
		}
		if json.Unmarshal(policy.Data, &options) != nil {
			return state, ErrProtocol
		}
		state.AutoEnroll = options.AutoEnrollEnabled
		state.Policy = append([]byte(nil), policy.Data...)
	}
	if !found {
		return state, ErrPermission
	}
	body, err = s.recoveryReadLocked(ctx, "/api/organizations/"+orgID+"/public-key", persist, guard)
	if err != nil {
		return state, err
	}
	var public struct{ PublicKey string }
	if json.Unmarshal(body, &public) != nil {
		return state, ErrProtocol
	}
	if _, err = decodeRecoveryPublicKey(public.PublicKey); err != nil {
		return state, err
	}
	state.PublicKey = public.PublicKey
	return state, nil
}

// PrepareRecoveryEnrollment uses GLOBAL user ID in the enrollment route (not
// membership ID). Enrollment authorizes organization recovery-key holders to
// recover the personal user key. Withdrawal cannot revoke already learned keys.
func (s *Session) PrepareRecoveryEnrollment(ctx context.Context, vault *VaultData, orgID string, enroll bool, trustedPublicKey string, proof AccountSensitiveInput, persist func(SessionCheckpoint) error) (*RecoveryPlan, error) {
	if !validObjectID(orgID) {
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
	state, err := s.recoveryEnrollmentLocked(ctx, orgID, persist, guard)
	if err != nil {
		return nil, err
	}
	if state.Enrolled == enroll {
		return nil, ErrConflict
	}
	if !enroll && state.AutoEnroll {
		return nil, ErrPermission
	}
	payload := struct {
		ResetPasswordKey *string `json:"resetPasswordKey"`
		accountProof
	}{}
	kind := "recovery-withdraw"
	impact := i18n.T("server.recovery.withdraw_impact")
	if enroll {
		if trustedPublicKey != state.PublicKey {
			return nil, ErrIdentity
		}
		payload.accountProof, err = s.accountProofLocked(proof)
		if err != nil {
			return nil, err
		}
		wrapped, e := recoveryWrapUserKey(state.PublicKey, s.key)
		if e != nil {
			return nil, e
		}
		payload.ResetPasswordKey = &wrapped
		kind = "recovery-enroll"
		impact = i18n.T("server.recovery.enroll_impact")
	}
	p, err := s.recoveryPlanLocked(kind, "PUT", "/api/organizations/"+orgID+"/users/"+s.account+"/reset-password-enrollment", state.Membership, s.account, impact, payload)
	if err != nil {
		return nil, err
	}
	p.epoch = epoch
	p.record.PreviousRevision = revision
	p.record.OrganizationID = orgID
	p.record.MembershipID = state.Membership
	p.record.TargetEmail = s.email
	p.revalidate = func(ctx context.Context, persist func(SessionCheckpoint) error, guard func() error) error {
		current, e := s.recoveryEnrollmentLocked(ctx, orgID, persist, guard)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(current, state) {
			return ErrConflict
		}
		return nil
	}
	return p, nil
}
