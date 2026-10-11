// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
)

// BindPassword explicitly equips a successful device login with a real password
// wrapper. No password/hash is transmitted. Publish only after a new Sync and the
// existing authenticated storage transaction. KDF runs outside the Session lock.
func (f *DeviceLogin) BindPassword(ctx context.Context, password []byte) error {
	if err := f.guard(); err != nil {
		return err
	}
	f.mu.Lock()
	s := f.session
	policy := f.policy
	ready := f.ready
	f.mu.Unlock()
	if s == nil || !ready {
		return ErrPermission
	}
	ctx, cancel := context.WithCancel(ctx)
	detach := context.AfterFunc(f.ctx, cancel)
	defer func() { detach(); cancel() }()
	s.mu.Lock()
	if !s.itemSessionActiveLocked() || s.account != f.scope.Account {
		s.mu.Unlock()
		return ErrExpired
	}
	epoch, revision, wrapped := s.authorizationEpoch, s.authorizationRevision, s.wrapped
	key := append([]byte(nil), s.key...)
	s.mu.Unlock()
	defer clear(key)
	body, _ := json.Marshal(map[string]string{"email": f.email})
	status, data, err := f.client.request(ctx, "POST", "/identity/accounts/prelogin", "application/json", string(body), "")
	if err != nil {
		return err
	}
	if status != 200 {
		return statusError(status)
	}
	var kdf vaultcrypto.KDF
	if strictJSON(data) != nil || json.Unmarshal(data, &kdf) != nil {
		return ErrProtocol
	}
	master, err := vaultcrypto.DeriveOnlineMaster(password, f.email, kdf)
	if err != nil {
		return err
	}
	defer clear(master)
	stretched, err := vaultcrypto.StretchMaster(master)
	if err != nil {
		return err
	}
	defer clear(stretched)
	unwrapped, err := vaultcrypto.DecryptString(wrapped, stretched)
	if err != nil {
		return err
	}
	defer clear(unwrapped)
	if subtle.ConstantTimeCompare(unwrapped, key) != 1 {
		return ErrCredentials
	}
	unlock, err := snapshotUnlockKey(master)
	if err != nil {
		return err
	}
	defer clear(unlock)
	if policy != nil {
		if err = policy.Check(ctx, password, f.email, true); err != nil {
			return err
		}
	}
	if err = f.guard(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || !s.itemSessionActiveLocked() || s.authorizationEpoch != epoch || s.authorizationRevision != revision || s.wrapped != wrapped || s.account != f.scope.Account || subtle.ConstantTimeCompare(s.key, key) != 1 {
		return ErrExpired
	}
	if s.passwordUnlock != nil {
		clear(s.passwordUnlock.Key)
	}
	s.passwordUnlock = &PasswordUnlock{Config: PasswordUnlockConfig{Email: f.email, KDF: kdf}, Key: append([]byte(nil), unlock...)}
	return nil
}
