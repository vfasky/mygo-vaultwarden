// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sync"
	"time"
)

// AuthRequest contains review metadata only, never the access code or user key.
type AuthRequest struct {
	ID                string  `json:"id"`
	PublicKey         string  `json:"publicKey"`
	RequestDeviceType string  `json:"requestDeviceType"`
	RequestIPAddress  string  `json:"requestIpAddress"`
	CreationDate      string  `json:"creationDate"`
	ResponseDate      *string `json:"responseDate"`
	RequestApproved   *bool   `json:"requestApproved"`
	Origin            string  `json:"origin"`
}
type authRequestWire struct {
	AuthRequest
	Key *string `json:"key"`
}

// PendingAuthRequest owns temporary login secrets. Close on lock, cancellation,
// account switch or completion; do not persist or log it. Poll does not log in.
type PendingAuthRequest struct {
	mu               sync.Mutex
	client           *Client
	id, code, public string
	private          *rsa.PrivateKey
	expires          time.Time
	ctx              context.Context
	cancel           context.CancelFunc
}

func (*PendingAuthRequest) String() string   { return "[pending auth request]" }
func (*PendingAuthRequest) GoString() string { return "[pending auth request]" }
func (p *PendingAuthRequest) Close() {
	p.cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.private = nil
	p.code = ""
	p.public = ""
}
func (p *PendingAuthRequest) ID() string { p.mu.Lock(); defer p.mu.Unlock(); return p.id }
func validAuthID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// BeginAuthRequest requires a previously registered device; 1.37.4 rejects new
// unknown device identifiers. The generated public key must be verified out of
// band by the approving user, not merely trusted because the server returns it.
func (c *Client) BeginAuthRequest(ctx context.Context, email string) (*PendingAuthRequest, AuthRequest, error) {
	var empty AuthRequest
	if email = NormalizeEmail(email); email == "" || len(email) > 1024 {
		return nil, empty, ErrValidation
	}
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, empty, ErrEncryption
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, empty, ErrEncryption
	}
	seed := make([]byte, 32)
	if _, err = rand.Read(seed); err != nil {
		return nil, empty, ErrEncryption
	}
	defer clear(seed)
	p := &PendingAuthRequest{client: c, code: base64.RawURLEncoding.EncodeToString(seed), public: base64.StdEncoding.EncodeToString(der), private: private, expires: time.Now().Add(5 * time.Minute)}
	p.ctx, p.cancel = context.WithDeadline(ctx, p.expires)
	body, _ := json.Marshal(map[string]any{"email": email, "deviceIdentifier": c.deviceID, "publicKey": p.public, "accessCode": p.code, "type": 0})
	defer clear(body)
	status, data, err := c.request(ctx, "POST", "/api/auth-requests", "application/json", string(body), "")
	defer clear(data)
	if err != nil {
		p.Close()
		return nil, empty, &MutationUncertainError{Cause: err}
	}
	if status != 200 {
		p.Close()
		return nil, empty, mutationStatusError(status)
	}
	var row AuthRequest
	if len(data) > 65536 || strictJSON(data) != nil || json.Unmarshal(data, &row) != nil || !validAuthID(row.ID) || row.PublicKey != p.public {
		p.Close()
		return nil, empty, &MutationUncertainError{Cause: ErrProtocol}
	}
	p.id = row.ID
	return p, row, nil
}

// Poll returns metadata only after matching the request's key and ID. It
// never installs a session or vault. The caller must authenticate via the normal
// login flow; notifications alone cannot establish authentication.
func (p *PendingAuthRequest) Poll(ctx context.Context) (AuthRequest, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	row, err := p.pollLocked(ctx)
	return row.AuthRequest, err
}
func (p *PendingAuthRequest) pollLocked(ctx context.Context) (authRequestWire, error) {
	var row authRequestWire
	if p.private == nil || time.Now().After(p.expires) || p.ctx.Err() != nil {
		return row, ErrExpired
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() { stop(); cancel() }()
	status, data, err := p.client.request(ctx, "GET", "/api/auth-requests/"+p.id+"/response?"+url.Values{"code": {p.code}}.Encode(), "", "", "")
	defer clear(data)
	if err != nil {
		return row, err
	}
	if status != 200 {
		return row, statusError(status)
	}
	if len(data) > 65536 || strictJSON(data) != nil || json.Unmarshal(data, &row) != nil || row.ID != p.id || row.PublicKey != p.public {
		return authRequestWire{}, ErrProtocol
	}
	return row, nil
}

// TakeUserKey decrypts an approved response once. The caller owns and must clear
// the returned key, and must not use it to bypass login or snapshot authentication.
func (p *PendingAuthRequest) TakeUserKey(ctx context.Context) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	row, err := p.pollLocked(ctx)
	if err != nil {
		return nil, err
	}
	if row.RequestApproved == nil || !*row.RequestApproved || row.ResponseDate == nil || row.Key == nil {
		return nil, ErrPermission
	}
	key, err := unwrapOrganizationKey(*row.Key, p.private)
	if err != nil {
		return nil, err
	}
	if len(key) != 64 {
		clear(key)
		return nil, ErrEncryption
	}
	if ctx.Err() != nil || p.ctx.Err() != nil {
		clear(key)
		return nil, ErrCancelled
	}
	p.cancel()
	p.private = nil
	p.code = ""
	return key, nil
}
func (s *Session) AuthRequests(ctx context.Context, scope Scope, pending bool, persist func(SessionCheckpoint) error) ([]AuthRequest, error) {
	endpoint := "/api/auth-requests"
	if pending {
		endpoint += "/pending"
	}
	var list struct {
		Data              []AuthRequest
		ContinuationToken *string
	}
	if err := s.deviceCall(ctx, scope, "GET", endpoint, nil, &list, persist); err != nil {
		return nil, err
	}
	if list.Data == nil || len(list.Data) > 10000 || list.ContinuationToken != nil {
		return nil, ErrProtocol
	}
	for _, r := range list.Data {
		if !validAuthID(r.ID) {
			return nil, ErrProtocol
		}
	}
	return list.Data, nil
}
func (s *Session) GetAuthRequest(ctx context.Context, scope Scope, id string, persist func(SessionCheckpoint) error) (AuthRequest, error) {
	var row AuthRequest
	if !validAuthID(id) {
		return row, ErrValidation
	}
	err := s.deviceCall(ctx, scope, "GET", "/api/auth-requests/"+id, nil, &row, persist)
	if err == nil && row.ID != id {
		err = ErrProtocol
	}
	return row, err
}

// RespondAuthRequest must be invoked from an explicit user confirmation. For
// approval trustedPublicKey must have been verified with the requesting device
// out of band; passing the server's public key without verification is unsafe.
// The authenticated snapshot binds approval to its scope, revision and epoch.
func (s *Session) RespondAuthRequest(ctx context.Context, vault *VaultData, id, trustedPublicKey string, approve, confirmed bool, persist func(SessionCheckpoint) error) error {
	if !confirmed || !validAuthID(id) {
		return ErrPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if _, err = s.snapshotPoliciesLocked(vault); err != nil {
		return err
	}
	epoch, revision := s.authorizationEpoch, s.authorizationRevision
	guard := func() error {
		if ctx.Err() != nil || !s.itemSessionActiveLocked() || s.authorizationEpoch != epoch || s.authorizationRevision != revision {
			return ErrExpired
		}
		return nil
	}
	status, data, err := s.authenticatedGuardedLocked(ctx, "GET", "/api/auth-requests/"+id, "", "", persist, guard)
	if err != nil {
		return err
	}
	defer clear(data)
	if status != 200 {
		return statusError(status)
	}
	var row AuthRequest
	if len(data) > 65536 || strictJSON(data) != nil || json.Unmarshal(data, &row) != nil || row.ID != id {
		return ErrProtocol
	}
	if row.ResponseDate != nil || row.RequestApproved != nil && *row.RequestApproved {
		return ErrConflict
	}
	wrapped := ""
	if approve {
		if row.PublicKey != trustedPublicKey {
			return ErrIdentity
		}
		public, e := parseMemberPublicKey(trustedPublicKey)
		if e != nil {
			return e
		}
		encrypted, e := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, s.key, nil)
		if e != nil {
			return ErrEncryption
		}
		defer clear(encrypted)
		wrapped = "3." + base64.StdEncoding.EncodeToString(encrypted)
	}
	body, _ := json.Marshal(map[string]any{"deviceIdentifier": s.client.deviceID, "key": wrapped, "requestApproved": approve, "masterPasswordHash": nil})
	defer clear(body)
	status, data, err = s.authenticatedGuardedLocked(ctx, "PUT", "/api/auth-requests/"+id, "application/json", string(body), persist, guard)
	defer clear(data)
	if err != nil {
		return err
	}
	if status != 200 {
		return mutationStatusError(status)
	}
	if guard() != nil {
		return &MutationUncertainError{Cause: ErrExpired}
	}
	return nil
}
