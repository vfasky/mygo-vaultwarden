// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
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
	relative, err := url.Parse(endpoint)
	if err != nil || !strings.HasPrefix(endpoint, "/") || relative.IsAbs() || relative.Host != "" || relative.User != nil || relative.Fragment != "" || relative.RawPath != "" || strings.Contains(relative.Path, "\\") {
		return 0, nil, ErrProtocol
	}
	for _, segment := range strings.Split(relative.Path, "/") {
		if segment == "." || segment == ".." {
			return 0, nil, ErrProtocol
		}
	}
	if _, err := url.ParseQuery(relative.RawQuery); err != nil {
		return 0, nil, ErrProtocol
	}
	u.Path += relative.Path
	u.RawQuery = relative.RawQuery
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
	form := url.Values{
		"grant_type": {"password"}, "username": {email}, "password": {vaultcrypto.AuthorizationHash(master, password)},
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
			key, err := vaultcrypto.DecryptString(token.wrappedKey(), stretched)
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
			return nil, statusError(status)
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
	// mu deliberately serializes network I/O with token refresh, key changes,
	// authorization epochs and checkpoint publication. Releasing it around I/O
	// would allow responses to commit against stale security state. The cost is
	// serialized session operations; operationMu lets Close cancel an in-flight
	// request before waiting for mu, without weakening this ordering.
	// The one exception is the GET of SyncWithWindow: it is read-only, and its
	// response is discarded unless the authorization epoch, access token and
	// lifecycle are unchanged when mu is reacquired.
	mu                                       sync.Mutex
	client                                   *Client
	email, account, wrapped, access, refresh string
	key                                      []byte
	passwordUnlock                           *PasswordUnlock
	expires                                  time.Time
	runtimeOnly                              bool
	freshRecoveryDeadline                    time.Time
	runtimeSyncDigest                        [32]byte
	runtimeCurrent                           atomic.Pointer[RuntimeAuthority]
	closed                                   bool
	checkpointPending                        bool
	operationMu                              sync.Mutex
	operations                               map[uint64]context.CancelFunc // by operationMu
	operationSeq                             uint64
	stopping                                 bool
	authorizationRevision                    string
	authorizationEpoch                       uint64
	writePolicies                            *operationPolicies
	pendingPolicyMutations                   []PendingPolicyMutation
	offlinePolicies                          *snapshotPolicies
	checkpointPolicies                       *snapshotPolicies
}

func (s *Session) Close() {
	if current := s.runtimeCurrent.Swap(nil); current != nil {
		current.Close()
	}
	s.operationMu.Lock()
	s.stopping = true
	for _, cancel := range s.operations {
		cancel()
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
	s.advanceAuthorizationLocked()
	s.authorizationRevision = ""
	s.writePolicies = nil
	s.offlinePolicies = nil
	s.checkpointPolicies = nil
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
	// Preserve only a currently valid policy context for a same-content durable
	// checkpoint receipt. Reads and item grants are revoked during rotation.
	s.checkpointPolicies = nil
	if p := s.offlinePolicies; p != nil && p.epoch == s.authorizationEpoch && p.revision == s.authorizationRevision {
		s.checkpointPolicies = p
	}
	s.offlinePolicies = nil
	s.advanceAuthorizationLocked()
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
	return s.syncLocked(ctx, persist)
}

// SyncWindow brackets the download of SyncWithWindow, during which the Session
// lock is released. Both hooks run on the sync goroutine without the lock.
type SyncWindow struct {
	// Open runs once the request is prepared, after any token checkpoint was
	// persisted. Reads of the installed snapshot may proceed from then on.
	Open func()
	// Close runs after the download and before the response is applied. It
	// must return only once the caller has stopped those reads, or when ctx is
	// done.
	Close func(ctx context.Context)
}

// SyncWithWindow is SyncWithCheckpoint for a sync that must not block the
// caller's reads of the installed snapshot while /api/sync downloads. Only the
// GET runs without s.mu; refresh, checkpoint, revocation and all parsing,
// decryption and authority changes stay serialized under it.
func (s *Session) SyncWithWindow(ctx context.Context, persist func(SessionCheckpoint) error, window SyncWindow) (SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	defer finish()
	status, data, err := s.downloadSyncReleasingLocked(ctx, persist, window)
	return s.applySyncLocked(ctx, status, data, err)
}

// downloadSyncReleasingLocked revokes the previous offline authority like
// syncLocked, but only once the download has returned, so the installed
// snapshot stays readable meanwhile. It revokes on every outcome. A response
// is used only when no authorization, token or lifecycle change happened while
// s.mu was released; otherwise it is fetched again with the lock held.
func (s *Session) downloadSyncReleasingLocked(ctx context.Context, persist func(SessionCheckpoint) error, window SyncWindow) (int, []byte, error) {
	if err := s.prepareAuthenticatedDispatchLocked(ctx, false, persist, nil); err != nil {
		s.revokeForSyncLocked()
		return 0, nil, err
	}
	epoch, access := s.authorizationEpoch, s.access
	s.mu.Unlock()
	if window.Open != nil {
		window.Open()
	}
	status, data, err := s.client.request(ctx, http.MethodGet, "/api/sync", "", "", access)
	if window.Close != nil {
		window.Close(ctx)
	}
	s.mu.Lock()
	changed := s.authorizationEpoch != epoch || s.access != access
	s.revokeForSyncLocked()
	if ctx.Err() != nil || s.closingLocked() {
		// Closing is the owner abandoning this sync, not a server-side expiry.
		clear(data)
		return 0, nil, ErrCancelled
	}
	if changed {
		clear(data)
		return s.authenticatedLocked(ctx, http.MethodGet, "/api/sync", "", "", persist)
	}
	if err != nil {
		return status, nil, err
	}
	if status == http.StatusUnauthorized {
		clear(data)
		if err := s.refreshAndCheckpointLocked(ctx, persist); err != nil {
			return status, nil, err
		}
		if err := s.prepareAuthenticatedDispatchLocked(ctx, false, persist, nil); err != nil {
			return status, nil, err
		}
		return s.client.request(ctx, http.MethodGet, "/api/sync", "", "", s.access)
	}
	return status, data, nil
}

func (s *Session) revokeForSyncLocked() {
	s.offlinePolicies = nil
	s.checkpointPolicies = nil
	s.advanceAuthorizationLocked()
}

func (s *Session) syncLocked(ctx context.Context, persist func(SessionCheckpoint) error) (SyncResult, error) {
	// Starting a replacement sync revokes the previous offline authority even
	// when download, identity validation or policy migration subsequently fails.
	s.revokeForSyncLocked()
	status, data, err := s.authenticatedLocked(ctx, http.MethodGet, "/api/sync", "", "", persist)
	return s.applySyncLocked(ctx, status, data, err)
}

func (s *Session) applySyncLocked(ctx context.Context, status int, data []byte, err error) (SyncResult, error) {
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
	if syncData.Profile.ID == "" || vaultcrypto.NormalizeEmail(syncData.Profile.Email) != s.email || (s.account != "" && s.account != syncData.Profile.ID) {
		return SyncResult{}, ErrIdentity
	}
	if syncData.Profile.Key != s.wrapped {
		return SyncResult{}, ErrExpired
	}
	policies, err := parseOperationPolicies(data, Scope{Server: s.client.base.String(), Account: syncData.Profile.ID}, s.email, s.wrapped)
	if err != nil {
		return SyncResult{}, err
	}
	if err := validateSnapshotOrganizationIdentity(data, syncData.Profile.ID); err != nil {
		return SyncResult{}, err
	}
	applyPendingPolicies(policies, s.pendingPolicyMutations)
	// Parsing and filtering must precede every credential decryption.
	result, err := decryptSyncWithPolicies(syncData, s.key, policies)
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
	if err := s.appendOrganizationCredentialsLocked(&result, policies); err != nil {
		// Close can start after the cancellation check above, while mu is
		// still held. Its stopping flag makes organization reads expire;
		// report the owner's cancellation instead of a server-side expiry.
		if ctx.Err() != nil || s.closingLocked() {
			return SyncResult{}, ErrCancelled
		}
		return SyncResult{}, err
	}
	if ctx.Err() != nil {
		return SyncResult{}, ErrCancelled
	}
	if err := s.recoveryCandidateLocked(&result); err != nil {
		return SyncResult{}, err
	}
	if s.passwordUnlock != nil {
		result.PasswordUnlock = &PasswordUnlock{Config: s.passwordUnlock.Config, Key: append([]byte(nil), s.passwordUnlock.Key...)}
		result.Session, err = s.savedLocked()
		if err != nil {
			clear(result.PasswordUnlock.Key)
			return SyncResult{}, err
		}
	}
	if s.runtimeOnly {
		s.runtimeSyncDigest, err = snapshotDigest(result.Vault)
		if err != nil {
			return SyncResult{}, err
		}
	}
	return result, nil
}
