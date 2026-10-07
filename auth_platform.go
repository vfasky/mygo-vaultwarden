// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

var errAuthUnavailable = errors.New("系统认证不可用；WebAuthn 需要受签名 associated domains 与服务器 AASA 支持，请保留服务器其它认证方法")
var errAuthFailed = errors.New("系统认证已取消或失败")

const authMaxBytes = 131072

var authSlots = make(chan struct{}, 16)

// AuthenticationPlatform belongs to one controller scope. The controller must
// cancel its context on lock/switch, and recheck scope before adopting results.
// Methods wait for authentication: call from workers, never the UI thread.
// No session, credentials, flow, or app is retained by the adapter.
type AuthenticationPlatform struct {
	call func(context.Context, []byte) ([]byte, error)
}

func NewAuthenticationPlatform(window *mygo.Window) *AuthenticationPlatform {
	return &AuthenticationPlatform{call: func(ctx context.Context, input []byte) ([]byte, error) {
		return nativeAuthentication(ctx, window, input)
	}}
}

// This is an internal ABI envelope, not a second server protocol DTO. All
// WebAuthn fields come from the existing parser and response binding.
type authNativeInput struct {
	Kind      string   `json:"kind"`
	URL       string   `json:"url,omitempty"`
	RP        string   `json:"rp,omitempty"`
	Challenge []byte   `json:"challenge,omitempty"`
	UserID    []byte   `json:"userID,omitempty"`
	UserName  string   `json:"userName,omitempty"`
	Allowed   [][]byte `json:"allowed,omitempty"`
	Excluded  [][]byte `json:"excluded,omitempty"`
}

func (p *AuthenticationPlatform) execute(ctx context.Context, request authNativeInput) ([]byte, error) {
	if p == nil || p.call == nil {
		return nil, errAuthUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case authSlots <- struct{}{}:
	default:
		return nil, errAuthUnavailable
	}
	defer func() { <-authSlots }()
	input, err := json.Marshal(request)
	if err != nil || len(input) > authMaxBytes {
		return nil, errAuthUnavailable
	}
	defer clear(input)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	result, err := p.call(ctx, input)
	if ctx.Err() != nil {
		clear(result)
		return nil, ctx.Err()
	}
	if len(result) > authMaxBytes {
		clear(result)
		return nil, errAuthFailed
	}
	return result, err
}

func (p *AuthenticationPlatform) WebAuthn(ctx context.Context, server string, raw json.RawMessage, register bool, epoch uint64) (json.RawMessage, error) {
	options, err := vaultwarden.ParseWebAuthnOptions(server, raw, register, epoch)
	if err != nil {
		return nil, err
	}
	defer options.Binding.Close()
	result, err := p.execute(ctx, authNativeInput{Kind: "webauthn", RP: options.RPID, Challenge: options.Challenge,
		UserID: options.UserID, UserName: options.UserName, Allowed: options.Allowed, Excluded: options.Excluded})
	if err != nil {
		clear(result)
		return nil, err
	}
	if err = options.Binding.Validate(result, epoch); err != nil {
		clear(result)
		return nil, err
	}
	return json.RawMessage(result), nil
}

func (p *AuthenticationPlatform) Duo(ctx context.Context, server, authURL string, epoch uint64) ([]byte, error) {
	flow, err := vaultwarden.NewDuoFlow(server, authURL, epoch)
	if err != nil {
		return nil, err
	}
	defer flow.Close()
	callback, err := p.execute(ctx, authNativeInput{Kind: "browser", URL: authURL})
	defer clear(callback)
	if err != nil {
		return nil, err
	}
	return flow.Complete(string(callback), epoch)
}

// SSO supports the existing bitwarden://sso-callback only. BeginSSO creates
// the state/PKCE flow here so an unrelated authorization URL cannot be supplied.
// Returned token bytes are secrets; #14 must unlock/sync/verify before adoption.
func (p *AuthenticationPlatform) SSO(ctx context.Context, client *vaultwarden.Client, epoch uint64, prompt ...func(context.Context, vaultwarden.MFAChallenge) (vaultwarden.MFAResponse, error)) (json.RawMessage, error) {
	flow, authURL, err := client.BeginSSO(ctx, "bitwarden://sso-callback", epoch)
	if err != nil {
		return nil, err
	}
	defer flow.Close()
	callback, err := p.execute(ctx, authNativeInput{Kind: "browser", URL: authURL})
	defer clear(callback)
	if err != nil {
		return nil, err
	}
	return flow.Exchange(ctx, string(callback), epoch, prompt...)
}

// MFA has the DeviceLoginHost.Platform signature after binding server/epoch.
func (p *AuthenticationPlatform) MFA(server string, epoch uint64) func(context.Context, vaultwarden.MFAChallenge, int) (vaultwarden.MFAResponse, error) {
	return func(ctx context.Context, challenge vaultwarden.MFAChallenge, provider int) (vaultwarden.MFAResponse, error) {
		var token []byte
		var err error
		switch provider {
		case 7:
			token, err = p.WebAuthn(ctx, server, challenge.Providers["7"], false, epoch)
		case 2:
			var metadata struct {
				AuthURL string `json:"AuthUrl"`
			}
			if json.Unmarshal(challenge.Providers["2"], &metadata) != nil {
				return vaultwarden.MFAResponse{}, vaultwarden.ErrProtocol
			}
			token, err = p.Duo(ctx, server, metadata.AuthURL, epoch)
		default:
			return vaultwarden.MFAResponse{}, errAuthUnavailable
		}
		return vaultwarden.MFAResponse{Provider: provider, Token: token}, err
	}
}

// authExchange is the testable single-owner request lifecycle. start/take/release
// are short dispatches; release is always called, even after take consumed an ID.
type authTransport interface {
	start([]byte) uint64
	take(uint64, []byte) int32
	release(uint64)
}

func authExchange(ctx context.Context, input []byte, transport authTransport) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := transport.start(input)
	if id == 0 {
		return nil, errAuthUnavailable
	}
	defer transport.release(id)
	result := make([]byte, authMaxBytes)
	defer clear(result)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := transport.take(id, result)
		if n > 0 && int(n) <= len(result) {
			return append([]byte(nil), result[:n]...), nil
		}
		if n == -5 {
			return nil, errAuthUnavailable
		}
		if n != 0 {
			return nil, errAuthFailed
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
