// SPDX-License-Identifier: GPL-3.0-only
package account

import "github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"

// Called only on the UI thread after the scheduler checks the request's scope,
// epoch and sequence. Secrets are masked until a separate reveal action.
func (f *Form) APIKeyCompleted(scope vaultwarden.Scope, epoch, sequence uint64, key vaultwarden.AccountAPIKey, err error) bool {
	if !f.Completed(scope, epoch, sequence, vaultwarden.AccountChangeResult{}, err) {
		return false
	}
	if err == nil {
		f.apiKey = key.APIKey
		f.apiKeyVisible = false
		f.Status = "个人 API key 已读取，请妥善保管"
	}
	return true
}
