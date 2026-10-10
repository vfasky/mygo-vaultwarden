// SPDX-License-Identifier: GPL-3.0-only

// Package vaultwarden is the Vaultwarden protocol client. Session carries the
// authenticated account state and implements the account, vault, attachment,
// Send, organization, policy, recovery and notification operations. Key
// derivation and encryption live in vaultcrypto, TOTP in totp, and the shared
// sentinel errors in vaulterr.
package vaultwarden
