// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
)

func historyUIFixture(t *testing.T) *app {
	t.Helper()
	a := secretUIFixture(t)
	var sync map[string]any
	json.Unmarshal(a.vault.Sync, &sync)
	object := sync["ciphers"].([]any)[0].(map[string]any)
	key, err := vaultcrypto.DecryptString(object["key"].(string), bytes.Repeat([]byte{4}, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	password, err := vaultcrypto.EncryptString([]byte("saved-history-secret"), key)
	if err != nil {
		t.Fatal(err)
	}
	object["passwordHistory"] = []any{map[string]any{"password": password, "lastUsedDate": "2026-01-01T00:00:00Z"}}
	a.vault.Sync, _ = json.Marshal(sync)
	acceptUIReceipt(t, a, a.vault)
	a.openCipherEditor("login-1", 1)
	return a
}
func TestHistoryDisplayUsesSameNativeLeaseAndDeadline(t *testing.T) {
	a := historyUIFixture(t)
	e := a.editor
	calls := 0
	a.showCipherHistory(func(request localstore.Request) localstore.Reply {
		calls++
		if request.Operation != "authorizeSecretDisplay" || request.Secret != "" || len(request.UnlockKey) != 32 || request.SecretProtocol != 1 || request.ExpectedRevision != a.sessionRevision {
			t.Fatal("history bypassed native lease")
		}
		if left := time.Until(time.UnixMilli(request.SecretNotAfter)); left <= 0 || left > 30*time.Second {
			t.Fatal("history deadline")
		}
		return localstore.Reply{OK: true}
	})
	if calls != 1 || !e.showHistory || len(e.shownHistory) != 1 || e.shownHistory[0].Password != "saved-history-secret" || strings.Contains(a.status, "saved-history-secret") {
		t.Fatal("authorized history display")
	}
	tester := ui.NewTester(func(c *ui.Context) { a.passwordHistoryView(c, e) }, 650, 500)
	if !tester.HasText("saved-history-secret") {
		t.Fatal("authorized history not rendered")
	}
	e.historyExpires = time.Now().Add(-time.Second)
	tester.Frame()
	if tester.HasText("saved-history-secret") || len(e.shownHistory) != 0 {
		t.Fatal("expired history visible")
	}
	a.showCipherHistory(func(localstore.Request) localstore.Reply { return localstore.Reply{Code: "stale", Message: "expired"} })
	if e.showHistory || len(e.shownHistory) != 0 {
		t.Fatal("failed native receipt exposed history")
	}
	a.showCipherHistory(func(localstore.Request) localstore.Reply { return localstore.Reply{OK: true} })
	a.lockInterface()
	if a.editor != nil || len(e.shownHistory) != 0 {
		t.Fatal("lock retained displayed history")
	}
}
