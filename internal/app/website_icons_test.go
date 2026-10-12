// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/websiteicons"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func TestWebsiteIconsRenderAndStopWithVault(t *testing.T) {
	var requests atomic.Int32
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	img.SetNRGBA(4, 4, color.NRGBA{R: 255, A: 255})
	var data bytes.Buffer
	if err := png.Encode(&data, img); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write(data.Bytes()) }))
	defer server.Close()
	scope := vaultwarden.Scope{Server: server.URL, Account: "test-account"}
	cache := websiteicons.New(scope.Server, scope.Account, t.TempDir())
	defer cache.Close()
	item := localstore.DisplayCredential{ID: "github", Title: "GitHub", URL: "https://github.com/login", Type: 1}
	a := previewApp()
	a.items = []localstore.DisplayCredential{item}
	a.snapshot.Scope = &scope
	a.websiteIcons, a.websiteIconScope = cache, scope
	// The fallback still renders immediately while icons are unavailable.
	tt := ui.NewTester(a.view, 1100, 760)
	if !slices.Contains(tt.Texts(), "G") {
		t.Fatal("missing initial fallback")
	}
	done := make(chan struct{}, 1)
	cache.Lookup(item.URL, func() { done <- struct{}{} })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("icon load timed out")
	}
	a.websiteIconsEnabled = true
	tt.Frame()
	if slices.Contains(tt.Texts(), "G") || requests.Load() != 1 {
		t.Fatal("list/detail did not share the loaded icon")
	}
	// Reprompt and non-login items must not use a website image.
	for _, protected := range []localstore.DisplayCredential{
		{Title: "GitHub", URL: item.URL, Type: 1, RequiresPassword: true},
		{Title: "GitHub", URL: item.URL, Type: 2},
	} {
		fallback := ui.NewTester(func(c *ui.Context) { a.credentialAvatar(c, protected, 40) }, 100, 100)
		if !slices.Contains(fallback.Texts(), "G") {
			t.Fatal("protected/non-login item requested an icon")
		}
	}
	a.stopNetwork()
	if a.websiteIcons != nil || a.websiteIconScope != (vaultwarden.Scope{}) {
		t.Fatal("lock retained the icon controller")
	}
	if cache.Lookup(item.URL, nil) != nil {
		t.Fatal("lock retained an active icon cache")
	}
	tt.Frame()
	if slices.Contains(tt.Texts(), "GitHub") {
		t.Fatal("locked UI exposed entry")
	}
}
