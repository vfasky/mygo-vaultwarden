// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// prepareRecoveryForm is the concrete adapter for #14's scheduler. The caller
// supplies its authenticated Session/VaultData, current checkpoint implementation
// and UI scope/epoch lease. Commit separately supplies durable BeforeDispatch.
// It must never be invoked on the UI thread or reuse a vault after lock/switch.
func prepareRecoveryForm(ctx context.Context, s *vaultwarden.Session, v *vaultwarden.VaultData, r RecoveryFormRequest, persist func(vaultwarden.SessionCheckpoint) error) (*vaultwarden.RecoveryPlan, error) {
	if s == nil || v == nil {
		return nil, vaultwarden.ErrExpired
	}
	switch r.Action {
	case "enroll", "withdraw":
		return s.PrepareRecoveryEnrollment(ctx, v, r.OrganizationID, r.Action == "enroll", r.TrustedPublicKey, vaultwarden.AccountSensitiveInput{Password: r.Password, OTP: r.OTP}, persist)
	case "administrator":
		return s.PrepareAdministratorRecovery(ctx, v, r.OrganizationID, r.MemberID, r.TrustedPublicKey, r.NewPassword, r.ResetPassword, r.ResetTwoFactor, persist)
	case "takeover":
		return s.PrepareEmergencyTakeover(ctx, v, r.Emergency.ID, r.NewPassword, persist)
	default:
		if r.Action != r.Emergency.Action {
			return nil, vaultwarden.ErrValidation
		}
		return s.PrepareEmergencyOperation(ctx, v, r.Emergency, persist)
	}
}
