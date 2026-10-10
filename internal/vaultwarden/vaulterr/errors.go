// SPDX-License-Identifier: GPL-3.0-only
// Package vaulterr defines shared Vaultwarden sentinel errors.
package vaulterr

import (
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
)

// Error messages deliberately exclude response bodies, URLs, tokens and secrets.
var (
	ErrServer          = errors.New(i18n.T("error.server"))
	ErrNetwork         = errors.New(i18n.T("error.network"))
	ErrProtocol        = errors.New(i18n.T("error.protocol"))
	ErrCredentials     = errors.New(i18n.T("error.credentials"))
	ErrMFA             = errors.New(i18n.T("error.mfa"))
	ErrUnsupportedMFA  = errors.New(i18n.T("error.unsupported_mfa"))
	ErrExpired         = errors.New(i18n.T("error.expired"))
	ErrIdentity        = errors.New(i18n.T("error.identity"))
	ErrKDF             = errors.New(i18n.T("error.kdf"))
	ErrEncryption      = errors.New(i18n.T("error.encryption"))
	ErrCancelled       = errors.New(i18n.T("error.cancelled"))
	ErrUnsupportedEdit = errors.New(i18n.T("error.unsupported_edit"))
	ErrCheckpoint      = errors.New(i18n.T("error.checkpoint"))
	ErrValidation      = errors.New(i18n.T("error.validation"))
	ErrPermission      = errors.New(i18n.T("error.permission"))
	ErrNotFound        = errors.New(i18n.T("error.not_found"))
	ErrConflict        = errors.New(i18n.T("error.conflict"))
	ErrRateLimited     = errors.New(i18n.T("error.rate_limited"))
)
