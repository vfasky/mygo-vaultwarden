// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
)

// The details copy the username, the password and the current code; the
// password and the code go through the protected clipboard and never show.
func TestDetailCopiesUsernamePasswordAndCode(t *testing.T) {
	a := secretUIFixture(t)
	a.editor = nil
	if err := a.adoptVault(a.vault); err != nil {
		t.Fatal(err)
	}
	if len(a.items) != 1 || !a.items[0].HasPassword || !a.items[0].HasTOTP {
		t.Fatalf("metadata lacks the login's password and code flags: %+v", a.items)
	}
	a.items[0].Username = "alex@example.com"
	var copied []localstore.Request
	a.storageBackend = func(r localstore.Request) localstore.Reply {
		if r.Operation == localstore.OperationCopySecret {
			copied = append(copied, r)
		}
		return localstore.Reply{OK: true, State: a.snapshot}
	}
	tt := ui.NewTester(a.view, 1280, 820)
	if tt.HasText("fixture-secret") {
		t.Fatal("the details show the password")
	}
	uitest.Click(t, tt, i18n.T("app.detail.copy_username"))
	if got := tt.Clipboard(); got != a.items[0].Username {
		t.Fatalf("username copy wrote %q", got)
	}
	uitest.Click(t, tt, i18n.T("app.detail.copy_password"))
	uitest.Click(t, tt, i18n.T("app.detail.copy_code"))
	if len(copied) != 2 || copied[0].Secret != "fixture-secret" || copied[1].Secret == "" || copied[1].Secret == copied[0].Secret || !a.secretClipboardOwned {
		t.Fatalf("protected copies: %d", len(copied))
	}
	if tt.HasText("fixture-secret") || tt.HasText(copied[1].Secret) {
		t.Fatal("a copied secret showed on screen")
	}
}

// Without a code there is no code row; an item that needs the master
// password again copies only from its editor; a busy vault copies nothing.
func TestDetailCopyAvailability(t *testing.T) {
	a := secretUIFixture(t)
	a.editor = nil
	if err := a.adoptVault(a.vault); err != nil {
		t.Fatal(err)
	}
	a.storageBackend = func(r localstore.Request) localstore.Reply {
		if r.Operation == localstore.OperationCopySecret {
			t.Fatal("a disabled copy reached the native bridge")
		}
		return localstore.Reply{OK: true, State: a.snapshot}
	}
	a.items[0].HasTOTP = false
	tt := ui.NewTester(a.view, 1280, 820)
	if tt.HasText(i18n.T("app.detail.totp")) {
		t.Fatal("a login without a code shows a code row")
	}
	a.pending = 1
	tt.Frame()
	_ = tt.Click(i18n.T("app.detail.copy_password"))
	a.pending = 0
	a.items[0].RequiresPassword = true
	tt.Frame()
	if !tt.HasText(i18n.T("app.detail.reprompt_copy_hint")) {
		t.Fatal("no hint for an item that needs the master password")
	}
	_ = tt.Click(i18n.T("app.detail.copy_password"))
	a.copyDetailSecret(a.items[0], "password", a.storageBackend)
}

// Without a session the details cannot know whether a password is set.
func TestDetailWithoutSessionDoesNotClaimNoPassword(t *testing.T) {
	a := previewApp()
	tt := ui.NewTester(a.view, 1280, 820)
	if tt.HasText(i18n.T("app.detail.no_password")) {
		t.Fatal("offline details claimed the login has no password")
	}
}
