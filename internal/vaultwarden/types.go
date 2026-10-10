// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
)

// Error messages deliberately exclude response bodies, URLs, tokens and secrets.
var (
	ErrServer          = vaulterr.ErrServer
	ErrNetwork         = vaulterr.ErrNetwork
	ErrProtocol        = vaulterr.ErrProtocol
	ErrCredentials     = vaulterr.ErrCredentials
	ErrMFA             = vaulterr.ErrMFA
	ErrUnsupportedMFA  = vaulterr.ErrUnsupportedMFA
	ErrExpired         = vaulterr.ErrExpired
	ErrIdentity        = vaulterr.ErrIdentity
	ErrKDF             = vaulterr.ErrKDF
	ErrEncryption      = vaulterr.ErrEncryption
	ErrCancelled       = vaulterr.ErrCancelled
	ErrUnsupportedEdit = vaulterr.ErrUnsupportedEdit
	ErrCheckpoint      = vaulterr.ErrCheckpoint
	ErrValidation      = vaulterr.ErrValidation
	ErrPermission      = vaulterr.ErrPermission
	ErrNotFound        = vaulterr.ErrNotFound
	ErrConflict        = vaulterr.ErrConflict
	ErrRateLimited     = vaulterr.ErrRateLimited
)

// MutationUncertainError means a transport failure prevented confirmation of a
// write. It is never safe to automatically resubmit this operation.
type MutationUncertainError struct{ Cause error }

func (e *MutationUncertainError) Error() string {
	return i18n.T("server.err_save_unconfirmed")
}
func (e *MutationUncertainError) Unwrap() error { return e.Cause }

type Scope struct {
	Server  string `json:"server"`
	Account string `json:"account"`
}

type URI struct {
	// SourceIndex binds a derived rule to the original encrypted login URI.
	// Swift uses its explicit/default match when revalidating old candidates.
	SourceIndex       *int   `json:"sourceIndex,omitempty"`
	URI               string `json:"uri"`
	Match             int    `json:"match"`
	BaseDomain        string `json:"baseDomain,omitempty"`
	IncludeSubdomains bool   `json:"includeSubdomains"`
}

type Credential struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Hosts    []string `json:"hosts"`
	URL      string   `json:"url"`
	URIs     []URI    `json:"uris"`
}

type Summary struct {
	Logins          int
	Organizations   int
	OtherTypes      int
	Reprompt        int
	Deleted         int
	Archived        int
	Restricted      int
	UnsupportedURIs int
}

type SyncResult struct {
	Scope                  Scope
	Credentials            []Credential
	Summary                Summary
	PasswordUnlock         *PasswordUnlock
	Session                []byte
	Vault                  *VaultData
	confirmedOrganizations []string
	candidate              *syncCandidate
}
