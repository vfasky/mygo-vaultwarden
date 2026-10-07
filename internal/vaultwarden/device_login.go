// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

var ErrDeviceUnknown = errors.New("device login requires a previously registered device")
var ErrDeviceRejected = errors.New("device login request rejected, removed, or request source no longer valid")

// DeviceLogin binds one request to a known account, device, epoch and deadline.
// Check must be worker-safe and reject a changed account/epoch or locked host.
// Close revokes even a returned Session; keep this handle for that login lifecycle.
type DeviceLogin struct {
	mu       sync.Mutex
	client   *Client
	pending  *PendingAuthRequest
	scope    Scope
	email    string
	epoch    uint64
	check    func(Scope, uint64) error
	ctx      context.Context
	cancel   context.CancelFunc
	timer    *time.Timer
	started  bool
	ready    bool
	session  *Session
	policy   *AccountPasswordPolicy
	metadata AuthRequest
}

func (*DeviceLogin) String() string   { return "[device login]" }
func (*DeviceLogin) GoString() string { return "[device login]" }
func (f *DeviceLogin) Close() {
	f.timer.Stop()
	f.cancel()
	f.pending.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.session != nil {
		f.session.Close()
	}
}
func (f *DeviceLogin) Metadata() AuthRequest { return f.metadata }
func (f *DeviceLogin) guard() error {
	if f.ctx.Err() != nil {
		if errors.Is(f.ctx.Err(), context.DeadlineExceeded) {
			return ErrExpired
		}
		return ErrCancelled
	}
	return f.check(f.scope, f.epoch)
}

// KnownDevice uses the 1.37.4 header contract. No credentials are placed in URLs.
func (c *Client) KnownDevice(ctx context.Context, email string) (bool, error) {
	email = NormalizeEmail(email)
	if email == "" || len(email) > 1024 {
		return false, ErrValidation
	}
	u := *c.base
	u.Path += "/api/devices/knowndevice"
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return false, ErrProtocol
	}
	req.Header.Set("X-Request-Email", base64.RawURLEncoding.EncodeToString([]byte(email)))
	req.Header.Set("X-Device-Identifier", c.deviceID)
	req.Header.Set("Device-Type", "7")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ErrCancelled
		}
		return false, ErrNetwork
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, statusError(resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32))
	if err != nil {
		return false, ErrProtocol
	}
	var known bool
	if json.Unmarshal(data, &known) != nil {
		return false, ErrProtocol
	}
	return known, nil
}

func (c *Client) BeginDeviceLogin(ctx context.Context, email string, scope Scope, epoch uint64, check func(Scope, uint64) error) (*DeviceLogin, error) {
	if scope.Server != c.base.String() || scope.Account == "" || check == nil {
		return nil, ErrIdentity
	}
	if err := check(scope, epoch); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(5*time.Minute, cancel)
	known, err := c.KnownDevice(ctx, email)
	if err != nil || !known {
		timer.Stop()
		cancel()
		if err != nil {
			return nil, err
		}
		return nil, ErrDeviceUnknown
	}
	p, row, err := c.BeginAuthRequest(ctx, email)
	if err != nil {
		timer.Stop()
		cancel()
		return nil, err
	}
	f := &DeviceLogin{client: c, pending: p, scope: scope, email: NormalizeEmail(email), epoch: epoch, check: check, ctx: ctx, cancel: cancel, timer: timer, metadata: row}
	context.AfterFunc(ctx, func() { f.Close() })
	if err = f.guard(); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

type DeviceLoginResult struct {
	Session       *Session
	Sync          SyncResult
	RememberToken string
	RemovedAllMFA bool
	// No password wrapper is fabricated. Session persistence requires BindPassword.
	RequiresPasswordForSessionPersistence bool
}

// Run polls even when notifications are unavailable. Notifications are hints only.
// A second call is refused, including after an unknown token exchange result.
func (f *DeviceLogin) Run(prompt func(context.Context, MFAChallenge) (MFAResponse, error)) (DeviceLoginResult, error) {
	f.mu.Lock()
	if f.started {
		f.mu.Unlock()
		return DeviceLoginResult{}, ErrConflict
	}
	f.started = true
	f.mu.Unlock()
	failed := true
	defer func() {
		if failed {
			f.Close()
		}
	}()
	hints := make(chan struct{}, 1)
	stream, err := f.pending.StartNotifications(f.ctx, f.scope, func(_ context.Context, _ NotificationEvent) error {
		select {
		case hints <- struct{}{}:
		default:
		}
		return nil
	})
	if err == nil {
		defer func() { stream.Stop(); stream.Wait() }()
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err = f.guard(); err != nil {
			return DeviceLoginResult{}, err
		}
		row, e := f.pending.Poll(f.ctx)
		if e != nil {
			if errors.Is(e, ErrNotFound) || errors.Is(e, ErrValidation) {
				return DeviceLoginResult{}, ErrDeviceRejected
			}
			if !errors.Is(e, ErrNetwork) {
				return DeviceLoginResult{}, e
			}
		} else if row.RequestApproved != nil {
			if !*row.RequestApproved && row.ResponseDate != nil {
				return DeviceLoginResult{}, ErrDeviceRejected
			}
			if *row.RequestApproved {
				break
			}
		}
		select {
		case <-f.ctx.Done():
			return DeviceLoginResult{}, f.guard()
		case <-hints:
		case <-ticker.C:
		}
	}
	// TakeUserKey erases the code, so capture it only for this one grant sequence.
	f.pending.mu.Lock()
	code := f.pending.code
	id := f.pending.id
	f.pending.mu.Unlock()
	key, err := f.pending.TakeUserKey(f.ctx)
	if err != nil {
		return DeviceLoginResult{}, err
	}
	defer clear(key)
	if err = f.guard(); err != nil {
		return DeviceLoginResult{}, err
	}
	token, remember, recovery, err := f.exchange(code, id, prompt)
	code = ""
	if err != nil {
		return DeviceLoginResult{}, err
	}
	s := &Session{client: f.client, email: f.email, account: f.scope.Account, key: append([]byte(nil), key...), wrapped: token.wrappedKey(), access: token.AccessToken, refresh: token.RefreshToken, expires: time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)}
	f.mu.Lock()
	f.session = s
	f.mu.Unlock()
	if err = f.guard(); err != nil {
		return DeviceLoginResult{}, err
	}
	result, err := s.Sync(f.ctx)
	if err != nil {
		return DeviceLoginResult{}, err
	}
	// Authenticate the supplied user key against this account even for an empty vault.
	var document struct{ Profile json.RawMessage }
	if json.Unmarshal(result.Vault.Sync, &document) != nil {
		return DeviceLoginResult{}, ErrProtocol
	}
	private, err := accountPrivateKey(document.Profile, key)
	if err != nil {
		return DeviceLoginResult{}, err
	}
	clearAccountPrivateKey(private)
	if result.Scope != f.scope {
		return DeviceLoginResult{}, ErrIdentity
	}
	if err = f.guard(); err != nil {
		return DeviceLoginResult{}, err
	}
	f.mu.Lock()
	f.ready = true
	f.mu.Unlock()
	f.timer.Stop()
	failed = false
	return DeviceLoginResult{Session: s, Sync: result, RememberToken: remember, RemovedAllMFA: recovery, RequiresPasswordForSessionPersistence: true}, nil
}

func (f *DeviceLogin) exchange(code, id string, prompt func(context.Context, MFAChallenge) (MFAResponse, error)) (tokenReply, string, bool, error) {
	form := url.Values{"grant_type": {"password"}, "username": {f.email}, "password": {code}, "authrequest": {id}, "scope": {"api offline_access"}, "client_id": {"desktop"}, "deviceType": {"7"}, "deviceIdentifier": {f.client.deviceID}, "deviceName": {"MyGo Vaultwarden"}}
	defer clear(form)
	recovery := false
	for attempt := 0; attempt < 4; attempt++ {
		if err := f.guard(); err != nil {
			return tokenReply{}, "", recovery, err
		}
		status, data, err := f.client.request(f.ctx, "POST", "/identity/connect/token", "application/x-www-form-urlencoded", form.Encode(), "")
		if err != nil {
			return tokenReply{}, "", recovery, &MutationUncertainError{Cause: err}
		}
		if len(data) > maxResponse || strictJSON(data) != nil {
			clear(data)
			return tokenReply{}, "", recovery, &MutationUncertainError{Cause: ErrProtocol}
		}
		if status == 200 {
			var reply struct {
				tokenReply
				Remember string                 `json:"twoFactorToken"`
				Policy   *AccountPasswordPolicy `json:"MasterPasswordPolicy"`
			}
			err = json.Unmarshal(data, &reply)
			clear(data)
			if err != nil || !validToken(reply.tokenReply) {
				return tokenReply{}, "", recovery, &MutationUncertainError{Cause: ErrProtocol}
			}
			f.mu.Lock()
			f.policy = reply.Policy
			f.mu.Unlock()
			return reply.tokenReply, reply.Remember, recovery, nil
		}
		if status != 400 && status != 401 {
			clear(data)
			return tokenReply{}, "", recovery, &MutationUncertainError{Cause: statusError(status)}
		}
		var challenge struct {
			Providers map[string]json.RawMessage `json:"twoFactorProviders2"`
		}
		err = json.Unmarshal(data, &challenge)
		clear(data)
		if err != nil || len(challenge.Providers) == 0 || attempt == 3 {
			return tokenReply{}, "", recovery, ErrCredentials
		}
		if prompt == nil {
			return tokenReply{}, "", recovery, ErrMFA
		}
		// send-email-login requires a password hash, not the auth request access code.
		response, e := prompt(f.ctx, MFAChallenge{Providers: challenge.Providers, Attempt: attempt})
		if e != nil {
			clear(response.Token)
			return tokenReply{}, "", recovery, e
		}
		_, supported := challenge.Providers[strconv.Itoa(response.Provider)]
		switch response.Provider {
		case 0, 1, 2, 3, 7:
		case 8:
			supported = response.ConfirmRemoveAllMFA
		default:
			supported = false
		}
		if !supported || len(response.Token) == 0 || len(response.Token) > 65536 {
			clear(response.Token)
			return tokenReply{}, "", recovery, ErrValidation
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
	return tokenReply{}, "", recovery, ErrCredentials
}
