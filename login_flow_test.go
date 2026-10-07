// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type codeResult struct {
	code []byte
	err  error
}

func awaitCode[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("login challenge did not settle")
		var zero T
		return zero
	}
}

func TestLoginChallengeOwnershipAndCancellation(t *testing.T) {
	challenge := newLoginChallenge(context.Background(), 1)
	code := []byte("123456")
	if !challenge.submit(code) {
		t.Fatal("first code rejected")
	}
	duplicate := []byte("654321")
	if challenge.submit(duplicate) || !bytes.Equal(duplicate, make([]byte, 6)) {
		t.Fatal("duplicate submission was not rejected and cleared")
	}
	got, err := challenge.wait()
	if err != nil || string(got) != "123456" {
		t.Fatal("code not delivered")
	}
	clear(got)
	late := []byte("123456")
	if challenge.submit(late) || !bytes.Equal(late, make([]byte, 6)) {
		t.Fatal("closed challenge accepted or retained a code")
	}

	ctx, cancel := context.WithCancel(context.Background())
	challenge = newLoginChallenge(ctx, 2)
	queued := []byte("123456")
	challenge.submit(queued)
	cancel()
	got, err = challenge.wait()
	if !errors.Is(err, vaultwarden.ErrCancelled) || len(got) != 0 || !bytes.Equal(queued, make([]byte, 6)) {
		t.Fatal("cancelled challenge retained queued code")
	}
}

func TestLoginChallengeCancelSubmitRace(t *testing.T) {
	for range 32 {
		ctx, cancel := context.WithCancel(context.Background())
		challenge := newLoginChallenge(ctx, 1)
		code := []byte("123456")
		var tasks sync.WaitGroup
		tasks.Add(2)
		go func() { defer tasks.Done(); challenge.submit(code) }()
		go func() { defer tasks.Done(); cancel() }()
		got, _ := challenge.wait()
		clear(got)
		tasks.Wait()
		if len(challenge.response) != 0 || !bytes.Equal(code, make([]byte, 6)) {
			t.Fatal("cancel/submit race left an unowned code")
		}
	}
}

func TestInlineVerificationSubmissionAndRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &app{snapshot: &snapshotStatus{Revision: "signed-out"}, showLogin: true, pending: 1,
		epoch: 7, cancel: cancel, masterPassword: "fixture-password",
		serverURL: "https://vault.example.com", email: "person@example.invalid"}
	updates := make(chan func(), 1)
	result := make(chan codeResult, 1)
	go func() {
		code, err := a.requestLoginCode(ctx, 7, 1, func(fn func()) { updates <- fn })
		result <- codeResult{code, err}
	}()
	awaitCode(t, (<-chan func())(updates))()
	tt := ui.NewTester(a.view, 1060, 700)
	if !tt.HasText("两步验证") || tt.HasText("主密码") || a.masterPassword != "" {
		t.Fatal("challenge did not replace password form")
	}
	clickUI(t, tt, "验证码")
	tt.Type("12a")
	clickUI(t, tt, "验证并登录")
	if !tt.HasText("请输入 6 位数字验证码。") || a.loginChallenge == nil {
		t.Fatal("invalid code advanced the challenge")
	}
	clickUI(t, tt, "验证码")
	tt.Key(ui.Cmd, ui.KeyA)
	tt.Type("123 456")
	tt.Key(0, ui.KeyEnter)
	got := awaitCode(t, (<-chan codeResult)(result))
	if got.err != nil || string(got.code) != "123456" {
		t.Fatal("inline submission did not resume login worker")
	}
	clear(got.code)
	if a.verificationCode != "" || a.loginChallenge != nil || !tt.HasText("正在验证…") {
		t.Fatal("submitted code was retained or duplicate submission stayed enabled")
	}

	go func() {
		code, err := a.requestLoginCode(ctx, 7, 2, func(fn func()) { updates <- fn })
		result <- codeResult{code, err}
	}()
	awaitCode(t, (<-chan func())(updates))()
	tt.Frame()
	if !tt.HasText("验证码错误或已过期") {
		t.Fatal("retry message missing")
	}
	clickUI(t, tt, "验证码")
	tt.Key(ui.Cmd, ui.KeyZ)
	if a.verificationCode != "" {
		t.Fatal("undo restored the previous code in a new challenge")
	}
	// The same method is used by cancel, lock and logout before native storage work.
	a.stopNetwork()
	tt.Frame()
	got = awaitCode(t, (<-chan codeResult)(result))
	if !errors.Is(got.err, vaultwarden.ErrCancelled) || a.showVerification || a.loginChallenge != nil {
		t.Fatal("cancellation left a challenge active")
	}
}

func TestStaleLoginChallengeCannotReplaceNewForm(t *testing.T) {
	a := &app{epoch: 2, showLogin: true, masterPassword: "new-password"}
	challenge := newLoginChallenge(context.Background(), 1)
	a.presentLoginChallenge(challenge, 1)
	_, err := challenge.wait()
	if !errors.Is(err, vaultwarden.ErrCancelled) || a.masterPassword != "new-password" || a.showVerification {
		t.Fatal("stale UI callback overwrote a newer login")
	}
}

func TestPasswordFieldMasksCopyAndResetsUndo(t *testing.T) {
	a := &app{snapshot: &snapshotStatus{Revision: "empty"}, deviceID: "fixture",
		serverURL: "https://vault.example.com", email: "invalid"}
	tt := ui.NewTester(a.view, 1060, 700)
	clickUI(t, tt, "主密码")
	tt.Type("fixture-secret")
	if a.masterPassword != "fixture-secret" || tt.HasText("fixture-secret") {
		t.Fatal("password input did not mask typed content")
	}
	tt.SetClipboard("unrelated")
	tt.Key(ui.Cmd, ui.KeyA)
	tt.Key(ui.Cmd, ui.KeyC)
	if tt.Clipboard() != "unrelated" {
		t.Fatal("password copied to clipboard")
	}
	a.resetLoginForm()
	tt.Frame()
	clickUI(t, tt, "主密码")
	tt.Key(ui.Cmd, ui.KeyZ)
	if a.masterPassword != "" {
		t.Fatal("undo restored a cleared password")
	}

	a.email = "person@example.invalid"
	tt.Frame()
	clickUI(t, tt, "登录并同步")
	if a.pending != 0 || a.status != "请输入主密码。" {
		t.Fatal("empty password reached native storage or network")
	}
}
