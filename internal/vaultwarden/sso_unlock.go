// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"time"
)

// UnlockSSOVault is deliberately separate from browser authentication. Pass only
// the token response returned by this client's SSOFlow.Exchange. Integration must
// sync and verify account identity before publishing this session. SSO accounts
// requiring key connector/trusted-device enrollment remain explicitly unsupported.
func (c *Client) UnlockSSOVault(ctx context.Context, raw json.RawMessage, email string, password []byte) (*Session, error) {
	var token tokenReply
	if len(raw) > maxResponse || json.Unmarshal(raw, &token) != nil || !validToken(token) {
		return nil, ErrProtocol
	}
	if token.wrappedKey() == "" {
		return nil, ErrEncryption
	}
	email = vaultcrypto.NormalizeEmail(email)
	prelogin, _ := json.Marshal(map[string]string{"email": email})
	status, data, err := c.request(ctx, "POST", "/identity/accounts/prelogin", "application/json", string(prelogin), "")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, statusError(status)
	}
	var kdf vaultcrypto.KDF
	if json.Unmarshal(data, &kdf) != nil {
		return nil, ErrProtocol
	}
	master, err := vaultcrypto.DeriveOnlineMaster(password, email, kdf)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	stretched, err := vaultcrypto.StretchMaster(master)
	if err != nil {
		return nil, err
	}
	defer clear(stretched)
	key, err := vaultcrypto.DecryptString(token.wrappedKey(), stretched)
	if err != nil {
		return nil, err
	}
	if len(key) != 64 {
		clear(key)
		return nil, ErrEncryption
	}
	unlock, err := snapshotUnlockKey(master)
	if err != nil {
		clear(key)
		return nil, err
	}
	if ctx.Err() != nil {
		clear(key)
		clear(unlock)
		return nil, ErrCancelled
	}
	return &Session{client: c, email: email, key: key, wrapped: token.wrappedKey(), access: token.AccessToken, refresh: token.RefreshToken, expires: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second), passwordUnlock: &PasswordUnlock{Config: PasswordUnlockConfig{Email: email, KDF: kdf}, Key: unlock}}, nil
}
