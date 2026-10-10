// SPDX-License-Identifier: GPL-3.0-only
// Package vaulterr defines shared Vaultwarden sentinel errors.
package vaulterr

import (
	"context"
	"errors"

	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
)

// Sentinels contain stable identities only. Translate at the presentation boundary.
var (
	ErrServer          = errors.New("vaultwarden: server")
	ErrNetwork         = errors.New("vaultwarden: network")
	ErrProtocol        = errors.New("vaultwarden: protocol")
	ErrCredentials     = errors.New("vaultwarden: credentials")
	ErrMFA             = errors.New("vaultwarden: mfa")
	ErrUnsupportedMFA  = errors.New("vaultwarden: unsupported_mfa")
	ErrExpired         = errors.New("vaultwarden: expired")
	ErrIdentity        = errors.New("vaultwarden: identity")
	ErrKDF             = errors.New("vaultwarden: kdf")
	ErrWeakKDF         = errors.New("vaultwarden: weak_kdf")
	ErrEncryption      = errors.New("vaultwarden: encryption")
	ErrCancelled       = errors.New("vaultwarden: cancelled")
	ErrUnsupportedEdit = errors.New("vaultwarden: unsupported_edit")
	ErrCheckpoint      = errors.New("vaultwarden: checkpoint")
	ErrValidation      = errors.New("vaultwarden: validation")
	ErrPermission      = errors.New("vaultwarden: permission")
	ErrNotFound        = errors.New("vaultwarden: not_found")
	ErrConflict        = errors.New("vaultwarden: conflict")
	ErrRateLimited     = errors.New("vaultwarden: rate_limited")
)

// ErrorMessage translates known identities, including wrapped sentinels, using
// the current language. Unknown errors never expose response text or secrets.
// Callers with domain-specific error types must handle those before this fallback.
func ErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	for _, entry := range []struct {
		err     error
		message string
	}{
		{ErrServer, "error.server"},
		{ErrNetwork, "error.network"},
		{ErrProtocol, "error.protocol"},
		{ErrCredentials, "error.credentials"},
		{ErrMFA, "error.mfa"},
		{ErrUnsupportedMFA, "error.unsupported_mfa"},
		{ErrExpired, "error.expired"},
		{ErrIdentity, "error.identity"},
		{ErrWeakKDF, "error.weak_kdf"},
		{ErrKDF, "error.kdf"},
		{ErrEncryption, "error.encryption"},
		{ErrCancelled, "error.cancelled"},
		{context.Canceled, "error.cancelled"},
		{ErrUnsupportedEdit, "error.unsupported_edit"},
		{ErrCheckpoint, "error.checkpoint"},
		{ErrValidation, "error.validation"},
		{ErrPermission, "error.permission"},
		{ErrNotFound, "error.not_found"},
		{ErrConflict, "error.conflict"},
		{ErrRateLimited, "error.rate_limited"},
	} {
		if errors.Is(err, entry.err) {
			return i18n.T(entry.message)
		}
	}
	return i18n.T("error.unknown")
}
