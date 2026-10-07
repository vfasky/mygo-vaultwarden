// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type encryptedURI struct {
	URI   *string `json:"uri"`
	Match *int    `json:"match"`
}
type encryptedCipher struct {
	ID             string  `json:"id"`
	Type           int     `json:"type"`
	OrganizationID *string `json:"organizationId"`
	DeletedDate    *string `json:"deletedDate"`
	ArchivedDate   *string `json:"archivedDate"`
	ViewPassword   *bool   `json:"viewPassword"`
	Reprompt       int     `json:"reprompt"`
	Name           *string `json:"name"`
	Key            *string `json:"key"`
	Login          *struct {
		Username *string        `json:"username"`
		Password *string        `json:"password"`
		URIs     []encryptedURI `json:"uris"`
	} `json:"login"`
}
type syncReply struct {
	Profile struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Key   string `json:"key"`
	} `json:"profile"`
	Ciphers []encryptedCipher `json:"ciphers"`
}

func NormalizeURI(value string, match int) (URI, string, error) {
	if match == 2 {
		// clients 5983f56c login-uri.view.ts:175 compares the original strings.
		// Prefixes may end within a host/path/escape, so do not URL-normalize them.
		// They never contribute a domain/host hint or a quick-fill identity.
		if value == "" || len(value) > 8192 || !utf8.ValidString(value) {
			return URI{}, "", ErrProtocol
		}
		for _, character := range value {
			if character <= 0x20 || character == 0x7f {
				return URI{}, "", ErrProtocol
			}
		}
		return URI{URI: value, Match: 2}, "", nil
	}
	if match != 0 && match != 1 && match != 3 {
		return URI{}, "", ErrProtocol
	}
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return URI{}, "", ErrProtocol
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if net.ParseIP(host) == nil {
		host, err = idna.Lookup.ToASCII(host)
	}
	if err != nil || host == "" {
		return URI{}, "", ErrProtocol
	}
	if u.Port() != "" {
		u.Host = net.JoinHostPort(host, u.Port())
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	base := host
	subdomains := false
	if match == 0 && net.ParseIP(host) == nil {
		if registrable, e := publicsuffix.EffectiveTLDPlusOne(host); e == nil {
			base = registrable
			subdomains = true
		}
	}
	return URI{URI: u.String(), Match: match, BaseDomain: base, IncludeSubdomains: subdomains}, host, nil
}

// Production sync always supplies policies parsed from the authenticated reply.
func decryptSyncWithPolicies(data syncReply, key []byte, policies *operationPolicies) (SyncResult, error) {
	result := SyncResult{Credentials: make([]Credential, 0)}
	if policies == nil {
		return result, ErrPermission
	}
	if len(data.Ciphers) > 100000 {
		return result, ErrProtocol
	}
	seen := make(map[string]bool)
	for _, item := range data.Ciphers {
		if policies.restricts(item.OrganizationID, item.Type) {
			result.Summary.Restricted++
			continue
		}
		if item.DeletedDate != nil {
			result.Summary.Deleted++
			continue
		}
		if item.ArchivedDate != nil {
			result.Summary.Archived++
			continue
		}
		if item.ViewPassword != nil && !*item.ViewPassword {
			result.Summary.Restricted++
			continue
		}
		if item.OrganizationID != nil && *item.OrganizationID != "" {
			result.Summary.Organizations++
			continue
		}
		if item.Type != 1 {
			result.Summary.OtherTypes++
			continue
		}
		if item.Reprompt != 0 {
			result.Summary.Reprompt++
			continue
		}
		if item.Login == nil || item.ID == "" || len(item.ID) > 256 || strings.Contains(item.ID, ":") || seen[item.ID] {
			return result, ErrProtocol
		}
		seen[item.ID] = true
		credential, skipped, err := decryptCipher(item, key, policies.defaultURIMatch)
		if err != nil {
			return SyncResult{}, err
		}
		result.Summary.UnsupportedURIs += skipped
		result.Credentials = append(result.Credentials, credential)
		result.Summary.Logins++
		if len(result.Credentials) > 10000 {
			return SyncResult{}, ErrProtocol
		}
	}
	return result, nil
}
func decryptCipher(item encryptedCipher, userKey []byte, defaultMatch ...int) (Credential, int, error) {
	key := userKey
	if item.Key != nil && *item.Key != "" {
		var err error
		key, err = DecryptString(*item.Key, userKey)
		if err != nil {
			return Credential{}, 0, err
		}
		defer clear(key)
		if len(key) != 64 {
			return Credential{}, 0, ErrEncryption
		}
	}
	name, err := decryptText(item.Name, key)
	if err != nil {
		return Credential{}, 0, err
	}
	username, err := decryptText(item.Login.Username, key)
	if err != nil {
		return Credential{}, 0, err
	}
	password, err := decryptText(item.Login.Password, key)
	if err != nil {
		return Credential{}, 0, err
	}
	credential := Credential{ID: item.ID, Title: name, Username: username, Password: password, Hosts: []string{}, URIs: []URI{}}
	if len(username) > 4096 || len(password) > 65536 || len(name) > 4096 {
		return Credential{}, 0, ErrProtocol
	}
	skipped := 0
	for index, entry := range item.Login.URIs {
		value, err := decryptText(entry.URI, key)
		if err != nil {
			return Credential{}, 0, err
		}
		match := 0
		if len(defaultMatch) == 1 {
			match = defaultMatch[0]
		}
		if entry.Match != nil {
			match = *entry.Match
		}
		rule, host, err := NormalizeURI(value, match)
		if value == "" || err != nil {
			skipped++
			continue
		}
		rule.SourceIndex = &index
		credential.URIs = append(credential.URIs, rule)
		credential.Hosts = append(credential.Hosts, host)
		if credential.URL == "" {
			credential.URL = rule.URI
		}
	}
	return credential, skipped, nil
}
