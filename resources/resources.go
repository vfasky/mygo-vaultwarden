// SPDX-License-Identifier: GPL-3.0-only

// Package resources embeds image assets that the Go UI draws at runtime.
// Bundle icons in this directory are consumed by the build scripts instead.
package resources

import _ "embed"

// AppLogo is the PNG logo shown on the login and lock screens.
//
//go:embed app-logo.png
var AppLogo []byte
