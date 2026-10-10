// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestSendPanelReceivePasswordIsolationAndHiddenText(t *testing.T) {
	access := "ttmLCeaxQrCT8df3equVQw"
	var grantPassword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/connect/token":
			r.ParseForm()
			grantPassword = r.Form.Get("password_hash_b64")
			json.NewEncoder(w).Encode(map[string]any{"access_token": "receiver-token", "expires_in": 120, "token_type": "Bearer", "scope": "api.send.access"})
		case "/api/sends/access":
			json.NewEncoder(w).Encode(map[string]any{"id": access, "type": 0, "name": "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=", "text": map[string]any{"text": "2.2VPyLzk1tMLug0X3x7RkaQ==|mrMt9vbZsCJhJIj4eebKyg==|aZ7JeyndytEMR1+uEBupEvaZuUE69D/ejhfdJL8oKq0=", "hidden": true}, "creatorIdentifier": "sender@example.invalid"})
		default:
			t.Error("wrong receiver route")
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	p, queue := sendPanelFixture(t)
	c, e := vaultwarden.NewClient(srv.URL, "test-device-send-ui")
	if e != nil {
		t.Fatal(e)
	}
	p.Client = c
	p.Password = "owner-edit-password-must-not-leak"
	p.Link = srv.URL + "/#/send/" + access + "/Pgui0FK85cNhBGWHAlBHBw"
	p.Receive()
	select {
	case done := <-queue:
		done()
	case <-time.After(time.Second):
		t.Fatal("receiver callback")
	}
	if grantPassword != "" {
		t.Fatal("owner editor password leaked to receiver grant")
	}
	if p.Receiver == nil || p.Fields.Name != "Test" {
		t.Fatal("receiver view", p.Status)
	}
	tt := ui.NewTester(p.View, 1000, 1400)
	if tt.HasText("This is a test") || !tt.HasText("发送者：sender@example.invalid") {
		t.Fatal("hidden text/sender")
	}
	uitest.Click(t, tt, "显示分享文本")
	if !tt.HasText("This is a test") {
		t.Fatal("reveal")
	}
	p.Close()
	tt.Frame()
	if tt.HasText("This is a test") {
		t.Fatal("close retained text")
	}
}
func TestSendPanelCancelledFileSelectionRetainsDraft(t *testing.T) {
	p, queue := sendPanelFixture(t)
	p.New(1)
	p.Fields.Name = "retained name"
	p.Fields.Notes = "retained note"
	p.Password = "retained new password"
	p.Host.ChooseSource = func(context.Context) (io.ReadCloser, int64, string, error) {
		return nil, 0, "", vaultwarden.ErrCancelled
	}
	p.Save()
	select {
	case done := <-queue:
		done()
	case <-time.After(time.Second):
		t.Fatal("file callback")
	}
	if p.Draft == nil || p.Fields.Name != "retained name" || p.Password != "retained new password" || p.Busy || p.Uncertain {
		t.Fatal("cancelled chooser lost pre-dispatch draft")
	}
}
