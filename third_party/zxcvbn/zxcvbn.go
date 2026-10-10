// SPDX-License-Identifier: GPL-3.0-only
// Package zxcvbn embeds the original zxcvbn distribution and dictionaries.
package zxcvbn

import _ "embed"

// The original distribution and its dictionaries are embedded verbatim.
//
//go:embed zxcvbn.js
var Script string
