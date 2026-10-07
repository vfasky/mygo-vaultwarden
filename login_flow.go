// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"strings"
	"sync"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// One server challenge belongs to one login epoch. The channel transfers
// ownership of a code to the login worker; cancellation clears queued bytes.
// No UI state is accessed by the worker except through window.Update.
type loginChallenge struct {
	ctx       context.Context
	cancel    context.CancelFunc
	epoch     uint64
	response  chan []byte
	mu        sync.Mutex
	closed    bool
	submitted bool
}

func newLoginChallenge(ctx context.Context, epoch uint64) *loginChallenge {
	ctx, cancel := context.WithCancel(ctx)
	return &loginChallenge{ctx: ctx, cancel: cancel, epoch: epoch, response: make(chan []byte, 1)}
}

// submit takes ownership even when it rejects the code.
func (challenge *loginChallenge) submit(code []byte) bool {
	challenge.mu.Lock()
	defer challenge.mu.Unlock()
	if challenge.closed || challenge.submitted || challenge.ctx.Err() != nil {
		clear(code)
		return false
	}
	challenge.submitted = true
	challenge.response <- code
	return true
}

func (challenge *loginChallenge) wait() ([]byte, error) {
	defer challenge.cancel()
	var code []byte
	select {
	case code = <-challenge.response:
	case <-challenge.ctx.Done():
	}
	challenge.mu.Lock()
	challenge.closed = true
	select {
	case unused := <-challenge.response:
		clear(unused)
	default:
	}
	cancelled := challenge.ctx.Err() != nil
	challenge.mu.Unlock()
	if cancelled {
		clear(code)
		return nil, vaultwarden.ErrCancelled
	}
	return code, nil
}

func (a *app) clearLoginInputs() {
	a.masterPassword, a.verificationCode = "", ""
	// A new subtree gives the next input fresh editor/undo state. Merely
	// assigning an empty string lets a text editor undo the application's edit.
	a.secretInputVersion++
}

func (a *app) resetLoginForm() {
	if a.loginChallenge != nil {
		a.loginChallenge.cancel()
		a.loginChallenge = nil
	}
	a.clearLoginInputs()
	a.showVerification = false
}

func (a *app) presentLoginChallenge(challenge *loginChallenge, attempt int) {
	if challenge.epoch != a.epoch || challenge.ctx.Err() != nil || !a.showLogin {
		challenge.cancel()
		return
	}
	a.clearLoginInputs()
	a.loginChallenge = challenge
	a.showVerification = true
	a.status = ""
	if attempt > 1 {
		a.status = "验证码错误或已过期，请重新输入。"
	}
}

func (a *app) requestLoginCode(ctx context.Context, epoch uint64, attempt int, update func(func())) ([]byte, error) {
	challenge := newLoginChallenge(ctx, epoch)
	update(func() { a.presentLoginChallenge(challenge, attempt) })
	return challenge.wait()
}

func (a *app) submitLoginCode() {
	challenge := a.loginChallenge
	if challenge == nil || challenge.epoch != a.epoch || challenge.ctx.Err() != nil {
		a.clearLoginInputs()
		a.status = "本次验证已失效，请重新登录。"
		return
	}
	code := strings.ReplaceAll(strings.TrimSpace(a.verificationCode), " ", "")
	valid := len(code) == 6
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			valid = false
		}
	}
	if !valid {
		a.status = "请输入 6 位数字验证码。"
		return
	}
	accepted := challenge.submit([]byte(code))
	a.clearLoginInputs()
	a.loginChallenge = nil
	if accepted {
		a.status = "正在验证并同步…"
	} else {
		a.status = "本次验证已失效，请重新登录。"
	}
}
