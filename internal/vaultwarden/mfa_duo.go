// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DuoFlow binds a server-issued AuthUrl to the desktop callback. JWT payload
// parsing here extracts correlation metadata only; Duo/VW verify its signature.
type DuoFlow struct {
	mu      sync.Mutex
	state   string
	epoch   uint64
	expires time.Time
	used    bool
}

var duoHost = regexp.MustCompile(`^api-[a-zA-Z0-9]+\.(duosecurity|duofederal)\.com$`)

func NewDuoFlow(server, authURL string, epoch uint64) (*DuoFlow, error) {
	canonical, e := CanonicalServer(server)
	if e != nil {
		return nil, e
	}
	u, e := url.Parse(authURL)
	if e != nil || u.Scheme != "https" || u.User != nil || !duoHost.MatchString(u.Hostname()) || (u.Port() != "" && u.Port() != "443") || u.Path != "/oauth/v1/authorize" || u.RawPath != "" || u.Fragment != "" {
		return nil, ErrValidation
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(q["request"]) != 1 {
		return nil, ErrValidation
	}
	parts := strings.Split(q.Get("request"), ".")
	if len(parts) != 3 || len(parts[1]) > 16384 {
		return nil, ErrValidation
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || strictJSON(payload) != nil {
		return nil, ErrValidation
	}
	var claims struct {
		State    string `json:"state"`
		Redirect string `json:"redirect_uri"`
	}
	if json.Unmarshal(payload, &claims) != nil || len(claims.State) < 16 || strings.Contains(claims.State, "|") {
		return nil, ErrValidation
	}
	redirect, e := url.Parse(claims.Redirect)
	expected, _ := url.Parse(canonical + "/duo-redirect-connector.html")
	if e != nil || redirect.Scheme != expected.Scheme || redirect.Host != expected.Host || redirect.Path != expected.Path || redirect.User != nil || redirect.Fragment != "" || redirect.RawPath != "" || redirect.RawQuery != "client=desktop" {
		return nil, ErrValidation
	}
	return &DuoFlow{state: claims.State, epoch: epoch, expires: time.Now().Add(5 * time.Minute)}, nil
}
func (f *DuoFlow) Close() { f.mu.Lock(); defer f.mu.Unlock(); f.used = true; f.state = "" }
func (f *DuoFlow) Complete(callback string, epoch uint64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.used || epoch != f.epoch || time.Now().After(f.expires) {
		return nil, ErrExpired
	}
	u, e := url.Parse(callback)
	if e != nil || u.Scheme != "bitwarden" || u.Host != "duo-callback" || u.Path != "" || u.RawPath != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrValidation
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(q) != 2 || len(q["state"]) != 1 || len(q["code"]) != 1 || q.Get("code") == "" || strings.Contains(q.Get("code"), "|") || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.state)) != 1 {
		return nil, ErrValidation
	}
	f.used = true
	token := []byte(q.Get("code") + "|" + f.state)
	f.state = ""
	return token, nil
}
