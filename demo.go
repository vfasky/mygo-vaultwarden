// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// These public fixtures are for localhost only. There is no vault or login yet.
//
//go:embed resources/demo-credentials.json resources/demo-login.html
var demoFiles embed.FS

type demoCredential = vaultwarden.Credential

func loadDemoCredential() (demoCredential, error) {
	data, err := demoFiles.ReadFile("resources/demo-credentials.json")
	if err != nil {
		return demoCredential{}, err
	}
	var credentials []demoCredential
	if err := json.Unmarshal(data, &credentials); err != nil {
		return demoCredential{}, err
	}
	if len(credentials) != 1 {
		return demoCredential{}, errors.New("expected one public demo credential")
	}
	return credentials[0], nil
}

type demoServer struct {
	mu     sync.Mutex
	server *http.Server
}

func (s *demoServer) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:18472")
	if err != nil {
		return fmt.Errorf("本机端口 18472 不可用：%w", err)
	}
	root, err := fs.Sub(demoFiles, "resources")
	if err != nil {
		_ = listener.Close()
		return err
	}
	server := &http.Server{
		Handler:           demoHandler(root),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	s.server = server
	go func() {
		_ = server.Serve(listener)
		s.mu.Lock()
		if s.server == server {
			s.server = nil
		}
		s.mu.Unlock()
	}()
	return nil
}

func demoHandler(root fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do not expose the fixture through DNS rebinding or a non-loopback host.
		if r.Host != "localhost:18472" && r.Host != "127.0.0.1:18472" {
			http.Error(w, "loopback hosts only", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "this demo never receives submitted credentials", http.StatusMethodNotAllowed)
			return
		}
		name := ""
		switch r.URL.Path {
		case "/":
			name = "demo-login.html"
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "/demo-credentials.json":
			name = "demo-credentials.json"
			w.Header().Set("Content-Type", "application/json")
		default:
			http.NotFound(w, r)
			return
		}
		data, err := fs.ReadFile(root, name)
		if err != nil {
			http.Error(w, "demo resource unavailable", http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	})
}

func (s *demoServer) close() {
	s.mu.Lock()
	server := s.server
	s.mu.Unlock()
	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
}
