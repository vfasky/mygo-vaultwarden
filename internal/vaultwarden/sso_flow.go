// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// SSOFlow authenticates to Vaultwarden, not directly to the upstream IdP.
// VW owns the upstream OIDC nonce/ID-token verification. Never decode a JWT to
// claim a vault is unlocked. Exchange returns encrypted token data only.
type SSOFlow struct {
	mu                        sync.Mutex
	client                    *Client
	redirect, state, verifier string
	epoch                     uint64
	expires                   time.Time
	used                      bool
	lifetime                  context.Context
	cancel                    context.CancelFunc
}

func randomSSO() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (c *Client) BeginSSO(ctx context.Context, redirect string, epoch uint64) (*SSOFlow, string, error) {
	valid := redirect == "bitwarden://sso-callback"
	for _, port := range []string{"8065", "8066", "8067", "8068", "8069", "8070"} {
		if redirect == "http://localhost:"+port {
			valid = true
		}
	}
	if !valid {
		return nil, "", ErrValidation
	}
	status, data, err := c.request(ctx, "GET", "/identity/sso/prevalidate", "", "", "")
	if err != nil {
		return nil, "", err
	}
	if status != 200 {
		return nil, "", statusError(status)
	}
	var config struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data, &config) != nil || config.Token == "" {
		return nil, "", ErrProtocol
	}
	state, err := randomSSO()
	if err != nil {
		return nil, "", err
	}
	verifier, err := randomSSO()
	if err != nil {
		return nil, "", err
	}
	hash := sha256.Sum256([]byte(verifier))
	lifetime, cancel := context.WithTimeout(ctx, 5*time.Minute)
	f := &SSOFlow{lifetime: lifetime, cancel: cancel, client: c, redirect: redirect, state: state, verifier: verifier, epoch: epoch, expires: time.Now().Add(5 * time.Minute)}
	u := *c.base
	u.Path += "/identity/connect/authorize"
	u.RawQuery = url.Values{"client_id": {"desktop"}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"api offline_access"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"}, "ssoToken": {config.Token}}.Encode()
	return f, u.String(), nil
}
func (f *SSOFlow) Close() {
	f.cancel()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.used = true
	f.verifier = ""
	f.state = ""
}

// Exchange accepts only a callback delivered by the platform browser session
// initiated for this flow. Epoch comes from the current UI/account lease.
func (f *SSOFlow) Exchange(ctx context.Context, callback string, epoch uint64, prompt ...func(context.Context, MFAChallenge) (MFAResponse, error)) (json.RawMessage, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(f.lifetime, cancel)
	defer stop()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used || epoch != f.epoch || time.Now().After(f.expires) || ctx.Err() != nil || f.lifetime.Err() != nil {
		return nil, ErrExpired
	}
	u, err := url.Parse(callback)
	expected, _ := url.Parse(f.redirect)
	if err != nil || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawPath != "" || u.Scheme != expected.Scheme || u.Host != expected.Host || u.Path != expected.Path {
		return nil, ErrValidation
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrValidation
	}
	for k, v := range q {
		if len(v) != 1 {
			return nil, ErrValidation
		}
		switch k {
		case "state", "code", "iss", "scope", "error", "error_description":
		default:
			return nil, ErrValidation
		}
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.state)) != 1 || q.Get("iss") != f.client.base.String() {
		return nil, ErrValidation
	}
	f.used = true
	defer func() { f.verifier = ""; f.state = "" }()
	if q.Get("error") != "" {
		return nil, ErrCredentials
	}
	if q.Get("code") == "" {
		return nil, ErrValidation
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "code_verifier": {f.verifier}, "redirect_uri": {f.redirect}, "client_id": {"desktop"}, "scope": {"api offline_access"}, "deviceType": {"7"}, "deviceIdentifier": {f.client.deviceID}, "deviceName": {"MyGo Vaultwarden"}}
	defer clear(form)
	for attempt := 0; attempt < 4; attempt++ {
		status, data, err := f.client.request(ctx, "POST", "/identity/connect/token", "application/x-www-form-urlencoded", form.Encode(), "")
		if err != nil {
			return nil, err
		}
		if status == 200 {
			var token tokenReply
			if json.Unmarshal(data, &token) != nil || !validToken(token) {
				return nil, ErrProtocol
			}
			return data, nil
		}
		if status != 400 || attempt == 3 || len(prompt) != 1 || prompt[0] == nil {
			return nil, statusError(status)
		}
		var challenge struct {
			Providers map[string]json.RawMessage `json:"twoFactorProviders2"`
		}
		if json.Unmarshal(data, &challenge) != nil || len(challenge.Providers) == 0 {
			return nil, ErrCredentials
		}
		response, err := prompt[0](ctx, MFAChallenge{Providers: challenge.Providers, Attempt: attempt})
		if err != nil || ctx.Err() != nil {
			clear(response.Token)
			return nil, ErrCancelled
		}
		valid := false
		switch response.Provider {
		case 0, 1, 2, 3, 7:
			_, valid = challenge.Providers[strconv.Itoa(response.Provider)]
		case 8:
			valid = response.ConfirmRemoveAllMFA
		}
		if !valid || len(response.Token) == 0 || len(response.Token) > 65536 {
			clear(response.Token)
			return nil, ErrValidation
		}
		form.Set("twoFactorProvider", strconv.Itoa(response.Provider))
		form.Set("twoFactorToken", string(response.Token))
		clear(response.Token)
		form.Set("twoFactorRemember", "0")
		if response.Remember && response.Provider != 8 {
			form.Set("twoFactorRemember", "1")
		}
	}
	return nil, ErrCredentials
}
