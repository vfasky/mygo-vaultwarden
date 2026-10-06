// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDemoHandlerBoundaries(t *testing.T) {
	root, err := fs.Sub(demoFiles, "resources")
	if err != nil {
		t.Fatal(err)
	}
	handler := demoHandler(root)
	cases := []struct {
		name, method, host, path string
		status                   int
	}{
		{"page", "GET", "localhost:18472", "/", http.StatusOK},
		{"fixture", "GET", "127.0.0.1:18472", "/demo-credentials.json", http.StatusOK},
		{"rebound host", "GET", "attacker.test:18472", "/demo-credentials.json", http.StatusForbidden},
		{"hostname lookalike", "GET", "localhost.evil.test:18472", "/", http.StatusForbidden},
		{"never submit passwords", "POST", "localhost:18472", "/", http.StatusMethodNotAllowed},
		{"unlisted resource", "GET", "localhost:18472", "/demo-login.html", http.StatusNotFound},
		{"traversal", "GET", "localhost:18472", "/../LICENSE", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://"+tc.host+tc.path, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tc.status {
				t.Fatalf("got %d, want %d", recorder.Code, tc.status)
			}
			if tc.status == http.StatusOK {
				if recorder.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("demo response can be cached")
				}
				if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "form-action 'none'") {
					t.Fatal("form submission is not blocked")
				}
			}
		})
	}
}

func TestPublicFixtureAndPageStayConsistent(t *testing.T) {
	credential, err := loadDemoCredential()
	if err != nil {
		t.Fatal(err)
	}
	if credential.URL != "http://localhost:18472/" || !strings.HasSuffix(credential.Username, ".invalid") {
		t.Fatal("demo must remain a loopback-only public identity")
	}
	page, err := demoFiles.ReadFile("resources/demo-login.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), `autocomplete="current-password"`) ||
		!strings.Contains(string(page), `autocomplete="username"`) {
		t.Fatal("browser cannot identify login fields")
	}
}
