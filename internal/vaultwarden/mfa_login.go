// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"net/url"
	"strconv"
	"time"
)

type MFAChallenge struct {
	Providers map[string]json.RawMessage
	Attempt   int
	SendEmail func(context.Context) error
}
type MFAResponse struct {
	Provider            int
	Token               []byte
	Remember            bool
	ConfirmRemoveAllMFA bool
}
type MFALoginResult struct {
	Session       *Session
	RememberToken string
	RemovedAllMFA bool
}

// LoginMFA borrows password only for this call. Prompt must honor ctx and must
// never retain credentials. The result requires normal sync/identity validation.
func (c *Client) LoginMFA(ctx context.Context, email string, password []byte, remembered string, prompt func(context.Context, MFAChallenge) (MFAResponse, error)) (MFALoginResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	email = vaultcrypto.NormalizeEmail(email)
	body, _ := json.Marshal(map[string]string{"email": email})
	status, data, err := c.request(ctx, "POST", "/identity/accounts/prelogin", "application/json", string(body), "")
	if err != nil {
		return MFALoginResult{}, err
	}
	if status != 200 {
		return MFALoginResult{}, statusError(status)
	}
	var kdf vaultcrypto.KDF
	if json.Unmarshal(data, &kdf) != nil {
		return MFALoginResult{}, ErrProtocol
	}
	master, err := vaultcrypto.DeriveOnlineMaster(password, email, kdf)
	if err != nil {
		return MFALoginResult{}, err
	}
	defer clear(master)
	stretched, err := vaultcrypto.StretchMaster(master)
	if err != nil {
		return MFALoginResult{}, err
	}
	defer clear(stretched)
	form := url.Values{"grant_type": {"password"}, "username": {email}, "password": {vaultcrypto.AuthorizationHash(master, password)}, "scope": {"api offline_access"}, "client_id": {"desktop"}, "deviceType": {"7"}, "deviceIdentifier": {c.deviceID}, "deviceName": {"MyGo Vaultwarden"}}
	defer clear(form)
	if remembered != "" {
		form.Set("twoFactorProvider", "5")
		form.Set("twoFactorToken", remembered)
	}
	var providers map[string]json.RawMessage
	recovery := false
	for attempt := 0; attempt < 4; attempt++ {
		status, data, err = c.request(ctx, "POST", "/identity/connect/token", "application/x-www-form-urlencoded", form.Encode(), "")
		if err != nil {
			return MFALoginResult{}, err
		}
		if status == 200 {
			var t struct {
				tokenReply
				Remember string                 `json:"twoFactorToken"`
				Policy   *AccountPasswordPolicy `json:"MasterPasswordPolicy"`
			}
			if json.Unmarshal(data, &t) != nil || !validToken(t.tokenReply) {
				return MFALoginResult{}, ErrProtocol
			}
			if t.Policy != nil {
				if err := t.Policy.Check(ctx, password, email, true); err != nil {
					return MFALoginResult{}, err
				}
			}
			key, err := vaultcrypto.DecryptString(t.wrappedKey(), stretched)
			if err != nil {
				return MFALoginResult{}, err
			}
			if len(key) != 64 {
				clear(key)
				return MFALoginResult{}, ErrEncryption
			}
			unlock, err := snapshotUnlockKey(master)
			if err != nil {
				clear(key)
				return MFALoginResult{}, err
			}
			if ctx.Err() != nil {
				clear(key)
				clear(unlock)
				return MFALoginResult{}, ErrCancelled
			}
			s := &Session{client: c, email: email, key: key, wrapped: t.wrappedKey(), access: t.AccessToken, refresh: t.RefreshToken, expires: time.Now().Add(time.Duration(t.ExpiresIn) * time.Second), passwordUnlock: &PasswordUnlock{Config: PasswordUnlockConfig{Email: email, KDF: kdf}, Key: unlock}}
			if remembered == "" && form.Get("twoFactorProvider") != "5" {
				s.freshRecoveryDeadline = time.Now().Add(5 * time.Minute)
			}
			return MFALoginResult{Session: s, RememberToken: t.Remember, RemovedAllMFA: recovery}, nil
		}
		if status != 400 && status != 401 {
			return MFALoginResult{}, statusError(status)
		}
		var challenge struct {
			Details   map[string]json.RawMessage `json:"twoFactorProviders2"`
			Providers []json.RawMessage          `json:"twoFactorProviders"`
		}
		if json.Unmarshal(data, &challenge) != nil {
			return MFALoginResult{}, ErrProtocol
		}
		if len(challenge.Details) > 0 {
			providers = challenge.Details
		}
		if providers == nil && len(challenge.Providers) > 0 {
			providers = map[string]json.RawMessage{}
			for _, p := range challenge.Providers {
				var id string
				if json.Unmarshal(p, &id) != nil {
					id = string(p)
				}
				providers[id] = json.RawMessage(`{}`)
			}
		}
		if len(providers) == 0 || attempt == 3 {
			return MFALoginResult{}, ErrCredentials
		}
		if prompt == nil {
			return MFALoginResult{}, ErrMFA
		}
		// Copy public metadata; SendEmail is scoped to the active login context.
		metadata := map[string]json.RawMessage{}
		for k, v := range providers {
			metadata[k] = append(json.RawMessage(nil), v...)
		}
		_, emailSupported := providers["1"]
		emailHash := form.Get("password")
		response, err := prompt(ctx, MFAChallenge{Providers: metadata, Attempt: attempt, SendEmail: func(callCtx context.Context) error {
			if ctx.Err() != nil {
				return ErrCancelled
			}
			if !emailSupported {
				return ErrUnsupportedMFA
			}
			sendCtx, stop := context.WithCancel(callCtx)
			defer stop()
			detach := context.AfterFunc(ctx, stop)
			defer detach()
			b, _ := json.Marshal(map[string]string{"email": email, "masterPasswordHash": emailHash, "deviceIdentifier": c.deviceID})
			defer clear(b)
			code, _, e := c.request(sendCtx, "POST", "/api/two-factor/send-email-login", "application/json", string(b), "")
			if e != nil {
				return e
			}
			if code != 200 && code != 204 {
				return statusError(code)
			}
			return nil
		}})
		if err != nil || ctx.Err() != nil {
			clear(response.Token)
			return MFALoginResult{}, ErrCancelled
		}
		valid := false
		switch response.Provider {
		case 0, 1, 2, 3, 7:
			_, valid = providers[strconv.Itoa(response.Provider)]
		case 8:
			valid = response.ConfirmRemoveAllMFA
		}
		if !valid || len(response.Token) == 0 || len(response.Token) > 65536 {
			clear(response.Token)
			return MFALoginResult{}, ErrValidation
		}
		recovery = response.Provider == 8
		form.Set("twoFactorProvider", strconv.Itoa(response.Provider))
		form.Set("twoFactorToken", string(response.Token))
		clear(response.Token)
		form.Set("twoFactorRemember", "0")
		if response.Remember && !recovery {
			form.Set("twoFactorRemember", "1")
		}
	}
	return MFALoginResult{}, ErrCredentials
}
