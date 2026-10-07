// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

type authTestTransport struct {
	startID  uint64
	status   int32
	takes    int
	releases int
	cancel   context.CancelFunc
}

func (f *authTestTransport) start([]byte) uint64 { return f.startID }
func (f *authTestTransport) take(_ uint64, output []byte) int32 {
	f.takes++
	if f.cancel != nil {
		f.cancel()
	}
	copy(output, "ok")
	return f.status
}
func (f *authTestTransport) release(uint64) { f.releases++ }
func TestAuthExchangeOwnership(t *testing.T) {
	for _, status := range []int32{2, -2, -3, -4, -5, authMaxBytes + 1} {
		f := &authTestTransport{startID: 1, status: status}
		out, err := authExchange(context.Background(), nil, f)
		if f.releases != 1 || f.takes != 1 {
			t.Fatalf("status %d: lifecycle %+v", status, f)
		}
		if status == 2 {
			if err != nil || string(out) != "ok" {
				t.Fatal("result copy lost")
			}
		} else if err == nil || out != nil {
			t.Fatal("error leaked result")
		}
	}
	f := &authTestTransport{}
	if _, err := authExchange(context.Background(), nil, f); err == nil || f.releases != 0 {
		t.Fatal("invalid handle accepted")
	}
}
func TestAuthExchangeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &authTestTransport{startID: 1, cancel: cancel}
	if _, err := authExchange(ctx, nil, f); !errors.Is(err, context.Canceled) || f.releases != 1 {
		t.Fatal("cancel not released")
	}
	f = &authTestTransport{startID: 1}
	if _, err := authExchange(ctx, nil, f); !errors.Is(err, context.Canceled) || f.releases != 0 {
		t.Fatal("started canceled request")
	}
}
func TestAuthPlatformCancellationWinsAndBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	bytes := []byte("late secret")
	p := &AuthenticationPlatform{call: func(context.Context, []byte) ([]byte, error) { cancel(); return bytes, nil }}
	if out, err := p.execute(ctx, authNativeInput{Kind: "browser"}); !errors.Is(err, context.Canceled) || out != nil {
		t.Fatal("late success adopted")
	}
	for _, v := range bytes {
		if v != 0 {
			t.Fatal("late bytes not cleared")
		}
	}
	active := make(chan struct{}, 16)
	release := make(chan struct{})
	p = &AuthenticationPlatform{call: func(context.Context, []byte) ([]byte, error) {
		active <- struct{}{}
		<-release
		return nil, errAuthFailed
	}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = p.execute(context.Background(), authNativeInput{}) }()
	}
	for i := 0; i < 16; i++ {
		<-active
	}
	if _, err := p.execute(context.Background(), authNativeInput{}); !errors.Is(err, errAuthUnavailable) {
		t.Fatal("unbounded requests")
	}
	close(release)
	wg.Wait()
}
func TestAuthPlatformBindingRejectsUntrustedResponse(t *testing.T) {
	calls := 0
	p := &AuthenticationPlatform{call: func(_ context.Context, input []byte) ([]byte, error) {
		calls++
		var envelope authNativeInput
		if json.Unmarshal(input, &envelope) != nil || envelope.RP != "vault.example" {
			t.Fatal("parser not used")
		}
		return []byte(`{"id":"wrong"}`), nil
	}}
	raw := json.RawMessage(`{"rpId":"vault.example","challenge":"MDEyMzQ1Njc4OWFiY2RlZg"}`)
	if out, err := p.WebAuthn(context.Background(), "https://vault.example", raw, false, 8); err == nil || out != nil || calls != 1 {
		t.Fatal("binding bypassed")
	}
	if _, err := p.WebAuthn(context.Background(), "https://other.example", raw, false, 8); err == nil || calls != 1 {
		t.Fatal("invalid RP dispatched")
	}
	if _, err := p.Duo(context.Background(), "https://vault.example", "https://evil.example", 8); err == nil || calls != 1 {
		t.Fatal("invalid Duo dispatched")
	}
}
