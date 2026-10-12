// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSyncCredentialTOTP(t *testing.T) {
	userKey := bytes.Repeat([]byte{8}, 64)
	for _, itemKey := range []bool{false, true} {
		for _, tc := range []struct {
			name    string
			value   string
			missing bool
			invalid bool
		}{
			{name: "base32", value: "JBSWY3DPEHPK3PXP"},
			{name: "otpauth", value: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=6"},
			{name: "steam", value: "steam://JBSWY3DPEHPK3PXP"},
			{name: "unvalidated whitespace", value: " arbitrary raw seed \n"},
			{name: "empty"},
			{name: "absent", missing: true},
			{name: "byte limit", value: strings.Repeat("é", 2048)},
			{name: "oversize", value: strings.Repeat("x", 4097), invalid: true},
			{name: "multibyte oversize", value: strings.Repeat("é", 2049), invalid: true},
		} {
			name := tc.name
			if itemKey {
				name += "/item key"
			}
			t.Run(name, func(t *testing.T) {
				key := userKey
				wire := map[string]any{"id": "login-1", "type": 1}
				if itemKey {
					key = bytes.Repeat([]byte{9}, 64)
					wire["key"] = encryptFixture(key, userKey)
				}
				login := map[string]any{}
				if !tc.missing {
					login["totp"] = encryptFixture([]byte(tc.value), key)
				}
				wire["login"] = login
				raw, err := json.Marshal(wire)
				if err != nil {
					t.Fatal(err)
				}
				var cipher encryptedCipher
				if err := json.Unmarshal(raw, &cipher); err != nil {
					t.Fatal(err)
				}
				result, err := decryptSync(syncReply{Ciphers: []encryptedCipher{cipher}}, userKey)
				if tc.invalid {
					if !errors.Is(err, ErrProtocol) || len(result.Credentials) != 0 {
						t.Fatal("oversize TOTP must reject projection", err)
					}
					return
				}
				if err != nil || len(result.Credentials) != 1 {
					t.Fatal("credential projection", err)
				}
				credential := result.Credentials[0]
				if credential.TOTP != tc.value {
					t.Fatal("TOTP was not preserved")
				}
				raw, err = json.Marshal(credential)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(raw, &fields); err != nil {
					t.Fatal(err)
				}
				if _, present := fields["totp"]; present != (tc.value != "") {
					t.Fatal("TOTP JSON presence")
				}
				var restored Credential
				if err := json.Unmarshal(raw, &restored); err != nil || restored.TOTP != tc.value {
					t.Fatal("TOTP JSON round trip", err)
				}
			})
		}
	}
}
