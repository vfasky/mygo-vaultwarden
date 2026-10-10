// SPDX-License-Identifier: GPL-3.0-only
// Package vaulterr defines shared Vaultwarden sentinel errors.
package vaulterr

import "github.com/vfasky/mygo-vaultwarden/internal/i18n"

// Error messages deliberately exclude response bodies, URLs, tokens and secrets.
var (
	ErrServer          = i18n.Error("error.server")
	ErrNetwork         = i18n.Error("error.network")
	ErrProtocol        = i18n.Error("error.protocol")
	ErrCredentials     = i18n.Error("error.credentials")
	ErrMFA             = i18n.Error("error.mfa")
	ErrUnsupportedMFA  = i18n.Error("error.unsupported_mfa")
	ErrExpired         = i18n.Error("error.expired")
	ErrIdentity        = i18n.Error("error.identity")
	ErrKDF             = i18n.Error("error.kdf")
	ErrEncryption      = i18n.Error("error.encryption")
	ErrCancelled       = i18n.Error("error.cancelled")
	ErrUnsupportedEdit = i18n.Error("error.unsupported_edit")
	ErrCheckpoint      = i18n.Error("error.checkpoint")
	ErrValidation      = i18n.Error("error.validation")
	ErrPermission      = i18n.Error("error.permission")
	ErrNotFound        = i18n.Error("error.not_found")
	ErrConflict        = i18n.Error("error.conflict")
	ErrRateLimited     = i18n.Error("error.rate_limited")
)
