// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func passwordLockedApp() *app {
	a := previewApp()
	a.snapshot.Scope = &vaultwarden.Scope{Server: "https://vault.example.com", Account: "account-a"}
	a.snapshot.PasswordUnlock = &vaultwarden.PasswordUnlockConfig{Email: "fixture@example.invalid", KDF: vaultcrypto.KDF{Type: 0, Iterations: 5000}}
	a.lockInterface()
	return a
}

func TestLockImmediatelyHidesVaultAndClearsSecrets(t *testing.T) {
	a, session := onlineTestApp()
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.masterPassword, a.verificationCode, a.query = "fixture-password", "123456", "secret search"
	a.showLogin = true
	version := a.secretInputVersion
	a.lockInterface()
	assertSessionRevoked(t, a, session)
	if ctx.Err() == nil || a.masterPassword != "" || a.verificationCode != "" || a.query != "" || a.showLogin || a.secretInputVersion == version {
		t.Fatal("lock retained work, form secrets or navigation state")
	}
	tt := ui.NewTester(a.view, 1060, 700)
	assertVaultHidden(t, tt)
	if !tt.HasText("密码库已锁定") {
		t.Fatal("lock did not replace the vault with the authentication page")
	}
}

func TestPasswordUnlockFormAndValidation(t *testing.T) {
	a := passwordLockedApp()
	tt := ui.NewTester(a.view, 1060, 700)
	for _, label := range []string{"主密码", "解锁密码库", "使用 Touch ID 解锁"} {
		if !tt.HasText(label) {
			t.Fatalf("missing unlock control: %s", label)
		}
	}
	assertVaultHidden(t, tt)
	uitest.Click(t, tt, "解锁密码库")
	if a.status != "请输入主密码。" || a.pending != 0 {
		t.Fatal("empty password was not validated locally")
	}
	a.status = ""
	tt.Frame()
	uitest.Click(t, tt, "主密码")
	tt.Key(0, ui.KeyEnter)
	if a.status != "请输入主密码。" {
		t.Fatal("Enter did not submit the password form")
	}
	a.masterPassword = strings.Repeat("x", 8193)
	a.unlockWithPassword()
	if a.masterPassword != "" || a.pending != 0 || a.status != "主密码过长，请检查输入。" {
		t.Fatal("oversized password was retained or submitted")
	}
	// Pending authentication must disable both routes, including Enter.
	a.pending, a.status = 1, "pending"
	tt.Frame()
	uitest.Click(t, tt, "处理中…")
	uitest.Click(t, tt, "使用 Touch ID 解锁")
	tt.Key(0, ui.KeyEnter)
	if a.status != "pending" || a.pending != 1 {
		t.Fatal("duplicate authentication was started")
	}
}

func TestLegacySnapshotOffersMigrationAndRetainsTouchID(t *testing.T) {
	a := passwordLockedApp()
	a.snapshot.PasswordUnlock = nil
	tt := ui.NewTester(a.view, 1060, 700)
	if !tt.HasText("使用 Touch ID 解锁") || !tt.HasText("此密码库需重新登录一次") {
		t.Fatal("legacy snapshot has no supported unlock route or migration guidance")
	}
	uitest.Click(t, tt, "解锁密码库")
	if a.pending != 0 {
		t.Fatal("legacy snapshot started unsupported password unlock")
	}
	uitest.Click(t, tt, "重新登录")
	if !a.showLogin || a.serverURL != "https://vault.example.com" {
		t.Fatal("migration did not open login for the last server")
	}
	if !a.snapshot.Available {
		t.Fatal("navigation revoked the old snapshot before login")
	}
}

func TestUnlockReceiptsCannotRevealStaleOrWrongAccountMetadata(t *testing.T) {
	for _, operation := range []string{"listPassword", "list"} {
		for _, scenario := range []string{"success", "wrong-password", "cancelled", "late-lock", "late-logout", "wrong-revision", "wrong-account", "wrong-server", "nil-state", "unavailable"} {
			t.Run(operation+"/"+scenario, func(t *testing.T) {
				a := passwordLockedApp()
				a.epoch, a.pending = 2, 1
				request := localstore.Request{Operation: operation, ExpectedRevision: a.snapshot.Revision, Scope: a.snapshot.Scope}
				state := *a.snapshot
				reply := localstore.Reply{OK: true, State: &state, Items: []localstore.DisplayCredential{{ID: "secret", Title: "Secret title"}}}
				epoch := a.epoch
				switch scenario {
				case "wrong-password", "cancelled":
					reply.OK, reply.Message = false, "authentication failed"
				case "late-lock":
					a.lockInterface()
					a.epoch++
				case "late-logout":
					a.observeSnapshot(&localstore.SnapshotStatus{Revision: "signed-out"})
					a.epoch++
				case "wrong-revision":
					state.Revision = "replacement"
				case "wrong-account":
					state.Scope = &vaultwarden.Scope{Server: request.Scope.Server, Account: "account-b"}
				case "wrong-server":
					state.Scope = &vaultwarden.Scope{Server: "https://other.example.com", Account: request.Scope.Account}
				case "nil-state":
					reply.State = nil
				case "unavailable":
					state.Available = false
				}
				a.completeStorage(request, epoch, reply)
				if a.pending != 0 {
					t.Fatal("pending operation was not settled")
				}
				if scenario == "success" {
					if !a.unlocked() || len(a.items) != 0 || a.sessionOwnsSnapshot() {
						t.Fatal("legacy unlock exposed unfiltered candidates or granted online authority")
					}
				} else if a.unlocked() || len(a.items) != 0 {
					t.Fatal("failed or superseded authentication exposed metadata")
				}
			})
		}
	}
}
