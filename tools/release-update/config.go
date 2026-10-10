// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type updates struct {
	PublicKey  string `json:"publicKey"`
	URL        string `json:"url"`
	GitHub     string `json:"github"`
	TagPrefix  string `json:"tagPrefix"`
	PrivateKey string `json:"privateKey"`
}

func loadConfig(name string, lookup func(string) (string, bool)) (*updates, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var config struct {
		Updates *updates `json:"updates"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	u := config.Updates
	for _, item := range []struct {
		env   string
		field func(*updates) *string
	}{
		{"MYGO_UPDATE_PUBLIC_KEY", func(u *updates) *string { return &u.PublicKey }},
		{"MYGO_UPDATE_URL", func(u *updates) *string { return &u.URL }},
		{"MYGO_UPDATE_GITHUB", func(u *updates) *string { return &u.GitHub }},
		{"MYGO_UPDATE_TAG_PREFIX", func(u *updates) *string { return &u.TagPrefix }},
	} {
		if value, ok := lookup(item.env); ok {
			if u == nil {
				u = &updates{}
			}
			*item.field(u) = value
		}
	}
	if u == nil {
		return nil, nil
	}
	if err := u.validate(); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *updates) validate() error {
	u.PublicKey = strings.TrimSpace(u.PublicKey)
	key, err := base64.StdEncoding.DecodeString(u.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("updates.publicKey must be a base64 encoded 32-byte Ed25519 public key")
	}
	if (u.URL == "") == (u.GitHub == "") {
		return fmt.Errorf("updates requires exactly one of url or github")
	}
	if u.URL != "" {
		parsed, err := url.Parse(u.URL)
		// The manifest and archive names are appended to the URL, so even an
		// empty query or fragment would move them out of the path, and MyGo
		// reads {version} as the placeholder of a GitHub feed (ResolveFeed).
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
			strings.ContainsAny(u.URL, "\"'\r\n\t ?#{}") || strings.Contains(parsed.Path, "{version}") {
			return fmt.Errorf("updates.url must be an HTTPS base URL without credentials, query, fragment, braces, quotes or whitespace")
		}
	}
	if u.GitHub != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`).MatchString(u.GitHub) {
		return fmt.Errorf("updates.github must be owner/name")
	}
	if u.TagPrefix == "" {
		u.TagPrefix = "v"
	}
	if strings.Contains(u.TagPrefix, "{version}") {
		return fmt.Errorf("updates.tagPrefix must not contain {version}")
	}
	return nil
}

// URL and signature formats are independently implemented from MyGo v0.3.7's
// cmd/mygo/updates.go and internal/update/{update,github}.go contracts.
func (u *updates) fileURL(name, version string, latest bool) string {
	if u.GitHub == "" {
		return strings.TrimSuffix(u.URL, "/") + "/" + url.PathEscape(name)
	}
	base := "https://github.com/" + u.GitHub + "/releases/"
	if latest {
		if u.TagPrefix == "v" {
			return base + "latest/download/" + url.PathEscape(name)
		}
		return base + "download/" + url.PathEscape(u.TagPrefix) + "{version}/" + url.PathEscape(name)
	}
	return base + "download/" + url.PathEscape(u.TagPrefix+version) + "/" + url.PathEscape(name)
}

func (u *updates) signingKey(config string) (ed25519.PrivateKey, error) {
	text := os.Getenv("MYGO_UPDATER_PRIVATE_KEY")
	if text == "" && u.PrivateKey != "" {
		name := u.PrivateKey
		if strings.HasPrefix(name, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			name = filepath.Join(home, name[2:])
		} else if !filepath.IsAbs(name) {
			name = filepath.Join(filepath.Dir(config), name)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		text = string(data)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("set MYGO_UPDATER_PRIVATE_KEY or updates.privateKey to a base64 encoded 64-byte Ed25519 private key")
	}
	key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if !bytes.Equal(key, raw) || base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) != u.PublicKey {
		return nil, fmt.Errorf("update private key does not match updates.publicKey")
	}
	return key, nil
}

func releaseNotes(text, version string) (string, error) {
	var lines []string
	active := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if heading, ok := strings.CutPrefix(line, "## "); ok {
			if active {
				break
			}
			fields := strings.Fields(heading)
			if len(fields) == 0 {
				continue
			}
			candidate := fields[0]
			if strings.HasPrefix(candidate, "[") {
				candidate, _, _ = strings.Cut(candidate[1:], "]")
			}
			active = strings.TrimPrefix(candidate, "v") == strings.TrimPrefix(version, "v")
		} else if active {
			lines = append(lines, line)
		}
	}
	notes := strings.TrimSpace(strings.Join(lines, "\n"))
	if notes == "" {
		return "", fmt.Errorf("CHANGELOG.md has no notes for %s", version)
	}
	return notes, nil
}
