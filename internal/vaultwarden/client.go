// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const maxResponse = 32 * 1024 * 1024

type Client struct {
	base     *url.URL
	http     *http.Client
	deviceID string
}

func CanonicalServer(raw string) (string, error) {
	if len(raw) > 2048 {
		return "", ErrServer
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.Contains(u.Path, "\\") {
		return "", ErrServer
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return "", ErrServer
	}
	cleaned := path.Clean("/" + strings.Trim(u.Path, "/"))
	if cleaned != "/"+strings.Trim(u.Path, "/") {
		return "", ErrServer
	}
	u.Path = strings.TrimRight(cleaned, "/")
	return u.String(), nil
}

func NewClient(server, deviceID string) (*Client, error) {
	canonical, err := CanonicalServer(server)
	if err != nil {
		return nil, err
	}
	if len(deviceID) < 16 || len(deviceID) > 128 {
		return nil, ErrProtocol
	}
	u, _ := url.Parse(canonical)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = 15 * time.Second
	return &Client{base: u, deviceID: deviceID, http: &http.Client{
		Transport: transport, Timeout: 45 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *Client) request(ctx context.Context, method, endpoint, contentType, body, token string) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, ErrCancelled
	}
	u := *c.base
	u.Path += endpoint
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(body))
	if err != nil {
		return 0, nil, ErrProtocol
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "MyGoVaultwarden/0.1.0")
	// This is a tested protocol compatibility baseline, not the product version.
	req.Header.Set("Bitwarden-Client-Name", "desktop")
	req.Header.Set("Bitwarden-Client-Version", "2025.12.0")
	req.Header.Set("Device-Type", "7")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ErrCancelled
		}
		return 0, nil, ErrNetwork
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, nil, ErrServer
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if ctx.Err() != nil {
		return 0, nil, ErrCancelled
	}
	if err != nil || len(data) > maxResponse {
		return 0, nil, ErrProtocol
	}
	return resp.StatusCode, data, nil
}

type tokenReply struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	ExpiresIn             int    `json:"expires_in"`
	TokenType             string `json:"token_type"`
	Key                   string `json:"key"`
	UserDecryptionOptions struct {
		MasterPasswordUnlock *struct {
			Encrypted string `json:"masterKeyEncryptedUserKey"`
			Wrapped   string `json:"masterKeyWrappedUserKey"`
		} `json:"masterPasswordUnlock"`
	} `json:"userDecryptionOptions"`
}

func (t tokenReply) wrappedKey() string {
	if t.Key != "" {
		return t.Key
	}
	if t.UserDecryptionOptions.MasterPasswordUnlock != nil {
		if v := t.UserDecryptionOptions.MasterPasswordUnlock.Wrapped; v != "" {
			return v
		}
		return t.UserDecryptionOptions.MasterPasswordUnlock.Encrypted
	}
	return ""
}
func validToken(t tokenReply) bool {
	return t.AccessToken != "" && t.RefreshToken != "" && t.ExpiresIn > 0 && t.ExpiresIn <= 86400 && strings.EqualFold(t.TokenType, "bearer")
}

// Login owns KDF/master-key material until the challenge finishes. The caller
// owns password and should clear it immediately when Login returns.
func (c *Client) Login(ctx context.Context, email string, password []byte, promptTOTP func() ([]byte, error)) (*Session, error) {
	email = NormalizeEmail(email)
	prelogin, _ := json.Marshal(map[string]string{"email": email})
	status, data, err := c.request(ctx, "POST", "/identity/accounts/prelogin", "application/json", string(prelogin), "")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, ErrProtocol
	}
	var kdf KDF
	if json.Unmarshal(data, &kdf) != nil {
		return nil, ErrProtocol
	}
	master, err := DeriveMaster(password, email, kdf)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	stretched, err := StretchMaster(master)
	if err != nil {
		return nil, err
	}
	defer clear(stretched)
	form := url.Values{
		"grant_type": {"password"}, "username": {email}, "password": {AuthorizationHash(master, password)},
		"scope": {"api offline_access"}, "client_id": {"desktop"}, "deviceType": {"7"},
		"deviceIdentifier": {c.deviceID}, "deviceName": {"MyGo Vaultwarden"},
	}
	defer func() {
		for key := range form {
			delete(form, key)
		}
	}()
	for attempt := 0; attempt < 3; attempt++ {
		status, data, err = c.request(ctx, "POST", "/identity/connect/token", "application/x-www-form-urlencoded", form.Encode(), "")
		if err != nil {
			return nil, err
		}
		if status == 200 {
			var token tokenReply
			if json.Unmarshal(data, &token) != nil || !validToken(token) {
				return nil, ErrProtocol
			}
			key, err := DecryptString(token.wrappedKey(), stretched)
			if err != nil {
				return nil, err
			}
			if len(key) != 64 {
				clear(key)
				return nil, ErrEncryption
			}
			unlockKey, err := snapshotUnlockKey(master)
			if err != nil {
				clear(key)
				return nil, err
			}
			return &Session{client: c, email: email, key: key, wrapped: token.wrappedKey(), access: token.AccessToken, refresh: token.RefreshToken, expires: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
				passwordUnlock: &PasswordUnlock{Config: PasswordUnlockConfig{Email: email, KDF: kdf}, Key: unlockKey}}, nil
		}
		if status != 400 && status != 401 {
			return nil, ErrNetwork
		}
		var challenge struct {
			Providers []json.RawMessage          `json:"twoFactorProviders"`
			Details   map[string]json.RawMessage `json:"twoFactorProviders2"`
		}
		if json.Unmarshal(data, &challenge) != nil {
			return nil, ErrProtocol
		}
		totp := false
		for _, p := range challenge.Providers {
			if string(p) == `"0"` || string(p) == "0" {
				totp = true
			}
		}
		if _, exists := challenge.Details["0"]; exists {
			totp = true
		}
		// After a confirmed TOTP challenge, Vaultwarden can report a bad
		// code with only invalid_grant (without repeating provider metadata).
		// Keep the same bounded challenge instead of requesting the password again.
		if !totp && len(challenge.Providers) == 0 && len(challenge.Details) == 0 && form.Get("twoFactorProvider") == "0" {
			totp = true
		}
		if !totp {
			if len(challenge.Providers) > 0 || len(challenge.Details) > 0 {
				return nil, ErrUnsupportedMFA
			}
			return nil, ErrCredentials
		}
		if attempt == 2 {
			return nil, ErrCredentials
		}
		if promptTOTP == nil {
			return nil, ErrMFA
		}
		if ctx.Err() != nil {
			return nil, ErrCancelled
		}
		code, err := promptTOTP()
		if err != nil {
			clear(code)
			return nil, ErrCancelled
		}
		valid := len(code) == 6
		for _, ch := range code {
			if ch < '0' || ch > '9' {
				valid = false
			}
		}
		if !valid {
			clear(code)
			return nil, ErrCredentials
		}
		form.Set("twoFactorProvider", "0")
		form.Set("twoFactorToken", string(code))
		form.Set("twoFactorRemember", "0")
		clear(code)
	}
	return nil, ErrCredentials
}

type Session struct {
	mu                                       sync.Mutex
	client                                   *Client
	email, account, wrapped, access, refresh string
	key                                      []byte
	passwordUnlock                           *PasswordUnlock
	expires                                  time.Time
	closed                                   bool
	checkpointPending                        bool
	operationMu                              sync.Mutex
	cancelOperation                          context.CancelFunc
	stopping                                 bool
	authorizationRevision                    string
	authorizationEpoch                       uint64
}

func (s *Session) Close() {
	s.operationMu.Lock()
	s.stopping = true
	if s.cancelOperation != nil {
		s.cancelOperation()
	}
	s.operationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.key = nil
	if s.passwordUnlock != nil {
		clear(s.passwordUnlock.Key)
		s.passwordUnlock = nil
	}
	s.access = ""
	s.refresh = ""
	s.closed = true
	s.authorizationEpoch++
	s.authorizationRevision = ""
	s.client.http.CloseIdleConnections()
}
func (s *Session) refreshLocked(ctx context.Context) error {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.refresh}, "client_id": {"desktop"}}
	status, data, err := s.client.request(ctx, "POST", "/identity/connect/token", "application/x-www-form-urlencoded", form.Encode(), "")
	if err != nil {
		return err
	}
	if status == 400 || status == 401 {
		return ErrExpired
	}
	if status != 200 {
		return statusError(status)
	}
	var token tokenReply
	if json.Unmarshal(data, &token) != nil || !validToken(token) {
		return ErrProtocol
	}
	if token.wrappedKey() != "" && token.wrappedKey() != s.wrapped {
		return ErrExpired
	}
	s.access = token.AccessToken
	s.refresh = token.RefreshToken
	s.expires = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	return nil
}
func (s *Session) Sync(ctx context.Context) (SyncResult, error) {
	return s.SyncWithCheckpoint(ctx, nil)
}

func (s *Session) SyncWithCheckpoint(ctx context.Context, persist func(SessionCheckpoint) error) (SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	defer finish()
	status, data, err := s.authenticatedLocked(ctx, http.MethodGet, "/api/sync", "", "", persist)
	if err != nil {
		return SyncResult{}, err
	}
	if status != http.StatusOK {
		return SyncResult{}, statusError(status)
	}
	var syncData syncReply
	if json.Unmarshal(data, &syncData) != nil || syncData.Ciphers == nil {
		return SyncResult{}, ErrProtocol
	}
	if syncData.Profile.ID == "" || NormalizeEmail(syncData.Profile.Email) != s.email || (s.account != "" && s.account != syncData.Profile.ID) {
		return SyncResult{}, ErrIdentity
	}
	if syncData.Profile.Key != s.wrapped {
		return SyncResult{}, ErrExpired
	}
	result, err := decryptSync(syncData, s.key)
	if err != nil {
		return SyncResult{}, err
	}
	if ctx.Err() != nil {
		return SyncResult{}, ErrCancelled
	}
	s.account = syncData.Profile.ID
	result.Scope = Scope{Server: s.client.base.String(), Account: s.account}
	result.Vault = &VaultData{Version: 1, Scope: result.Scope, Sync: append([]byte(nil), data...)}
	if _, err := result.Vault.Documents(result.Scope); err != nil {
		return SyncResult{}, err
	}
	if err := s.appendOrganizationCredentialsLocked(&result); err != nil {
		return SyncResult{}, err
	}
	if ctx.Err() != nil {
		return SyncResult{}, ErrCancelled
	}
	if s.passwordUnlock != nil {
		result.PasswordUnlock = &PasswordUnlock{Config: s.passwordUnlock.Config, Key: append([]byte(nil), s.passwordUnlock.Key...)}
		result.Session, err = s.savedLocked()
		if err != nil {
			clear(result.PasswordUnlock.Key)
			return SyncResult{}, err
		}
	}
	return result, nil
}
