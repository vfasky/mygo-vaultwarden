// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "testing"

// Cryptographic fixtures explicitly supply no restrictions. This helper is
// test-only; production always parses policy from the authenticated sync.
func decryptSync(data syncReply, key []byte) (SyncResult, error) {
	return decryptSyncWithPolicies(data, key, &operationPolicies{})
}

func TestLastLoginExcludedProducesExplicitEmptyReplacement(t *testing.T) {
	deleted := "2026-10-07T00:00:00Z"
	denied := false
	for _, tc := range []struct {
		name    string
		ciphers []encryptedCipher
	}{
		{"empty account", []encryptedCipher{}},
		{"last login deleted", []encryptedCipher{{ID: "last", Type: 1, DeletedDate: &deleted}}},
		{"last login reprompt", []encryptedCipher{{ID: "last", Type: 1, Reprompt: 1}}},
		{"last login archived", []encryptedCipher{{ID: "last", Type: 1, ArchivedDate: &deleted}}},
		{"last login denied", []encryptedCipher{{ID: "last", Type: 1, ViewPassword: &denied}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := decryptSync(syncReply{Ciphers: tc.ciphers}, nil)
			if err != nil || result.Credentials == nil || len(result.Credentials) != 0 || result.Summary.Logins != 0 {
				t.Fatal("zero eligible records must produce an explicit empty replacement", err)
			}
		})
	}
}
