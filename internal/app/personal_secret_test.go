// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/egoist/mygo/ui"
	"strings"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func secretUIFixture(t *testing.T) *app {
	t.Helper()
	a := writableUIFixture(t)
	doc, err := vaultwarden.NewPersonalCipher(vaultwarden.CipherFields{Type: 1, Name: "fixture", Login: map[string]any{"password": "fixture-secret", "totp": "WQIQ25BRKZYCJVYP"}}, bytes.Repeat([]byte{4}, 64), a.liveScope.Account)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	_ = json.Unmarshal(doc.JSON, &object)
	object["id"], object["revisionDate"], object["edit"], object["viewPassword"] = "login-1", "2026-01-01T00:00:00Z", true, true
	a.vault.Sync, _ = json.Marshal(map[string]any{"profile": map[string]any{"id": a.liveScope.Account}, "ciphers": []any{object}})
	acceptUIReceipt(t, a, a.vault)
	a.openCipherEditor("login-1", 1)
	if a.editor == nil {
		t.Fatal("fixture editor")
	}
	t.Cleanup(func() { a.secretClipboardOwned = false; a.stopNetwork() }) // injected board only
	return a
}
func TestPersonalSecretCopyUsesAuthenticatedProtocolAndPersistedValue(t *testing.T) {
	a := secretUIFixture(t)
	for i := range a.editor.inputs {
		if a.editor.inputs[i].key == "password" {
			a.editor.inputs[i].value = "unsaved"
		}
	}
	calls := 0
	a.copyPersonalSecret("password", func(request localstore.Request) localstore.Reply {
		calls++
		if request.Operation != "copySecret" || request.Secret != "fixture-secret" || len(request.UnlockKey) != 32 || request.Scope == nil || *request.Scope != *a.liveScope || request.ExpectedRevision != a.sessionRevision || request.SecretProtocol != 1 {
			t.Fatal("copy missing secret/lease authentication")
		}
		if remaining := time.Until(time.UnixMilli(request.SecretNotAfter)); remaining <= 0 || remaining > 30*time.Second {
			t.Fatal("invalid expiry")
		}
		return localstore.Reply{OK: true}
	})
	if calls != 1 || !a.secretClipboardOwned || strings.Contains(a.status, "fixture-secret") {
		t.Fatal("copy state leaked secret or omitted ownership")
	}
}
func TestPersonalSecretCopyRejectsStaleLockedAndBusyUI(t *testing.T) {
	for _, scenario := range []string{"revision", "scope", "busy", "lock"} {
		t.Run(scenario, func(t *testing.T) {
			a := secretUIFixture(t)
			switch scenario {
			case "revision":
				a.editor.revision = "stale"
			case "scope":
				a.sessionRevision = "other"
			case "busy":
				a.pending = 1
			case "lock":
				a.lockInterface()
			}
			a.copyPersonalSecret("password", func(localstore.Request) localstore.Reply {
				t.Fatal("late/stale copy reached native bridge")
				return localstore.Reply{}
			})
		})
	}
}
func repromptUIFixture(t *testing.T) (*app, *vaultwarden.Session) {
	a := secretUIFixture(t)
	var raw map[string]any
	_ = json.Unmarshal(a.vault.Sync, &raw)
	raw["ciphers"].([]any)[0].(map[string]any)["reprompt"] = 1
	a.vault.Sync, _ = json.Marshal(raw)
	var saved map[string]any
	_ = json.Unmarshal(savedUIFixture(t, a), &saved)
	key, err := vaultwarden.DeriveSnapshotUnlockKey([]byte("fixture-master"), *a.snapshot.PasswordUnlock)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	saved["passwordUnlock"] = &vaultwarden.PasswordUnlock{Config: *a.snapshot.PasswordUnlock, Key: key}
	data, _ := json.Marshal(saved)
	defer clear(data)
	session, err := vaultwarden.RestoreSessionFromAuthenticatedSnapshot(data, *a.liveScope, a.snapshot.PasswordUnlock, a.vault, a.sessionRevision)
	if err != nil {
		t.Fatal(err)
	}
	a.session.Close()
	a.session = session
	return a, session
}

func TestRepromptEditorRequiresPasswordAndExpires(t *testing.T) {
	a, session := repromptUIFixture(t)
	a.openCipherEditor("login-1", 1)
	if a.editor == nil || a.editor.repromptID != "login-1" || a.editor.fields.Name != "" {
		t.Fatal("reauthentication bypass")
	}
	grant, err := session.AuthorizePersonalItem(context.Background(), a.vault, a.sessionRevision, "login-1", []byte("fixture-master"))
	if err != nil {
		t.Fatal(err)
	}
	a.openCipherEditorAuthorized("login-1", 1, grant)
	if a.editor.fields.Reprompt != 1 || a.editor.authorization != grant || a.editor.fields.Name != "fixture" {
		t.Fatal("reprompt flag or authorization lost")
	}
	a.editor.authorizationExpires = time.Now()
	tester := ui.NewTester(a.view, 1280, 820)
	tester.Frame()
	if a.editor != nil {
		t.Fatal("expired protected editor retained")
	}
}

func TestSecretDisplayFailureAndLockClear(t *testing.T) {
	a := secretUIFixture(t)
	a.showPersonalSecret("password", func(request localstore.Request) localstore.Reply {
		if request.Operation != "authorizeSecretDisplay" || request.Secret != "" || len(request.UnlockKey) != 32 {
			t.Fatal("display gate leaked secret")
		}
		return localstore.Reply{OK: true}
	})
	e := a.editor
	if e.shownSecret != "fixture-secret" || strings.Contains(a.status, "fixture-secret") {
		t.Fatal("display status leak")
	}
	a.lockInterface()
	if e.shownSecret != "" || a.editor != nil {
		t.Fatal("lock retained newly displayed secret")
	}
	b := secretUIFixture(t)
	b.showPersonalSecret("password", func(localstore.Request) localstore.Reply { return localstore.Reply{Code: "stale", Message: "expired"} })
	if b.editor.shownSecret != "" {
		t.Fatal("failed bridge auth exposed secret")
	}
}
