// SPDX-License-Identifier: GPL-3.0-only
package totp

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
)

func TestGenerateDisplayCompatibility(t *testing.T) {
	// Public RFC 6238 SHA256 vector, with padding to exercise both encodings.
	encoder := base32.StdEncoding
	secret := encoder.EncodeToString([]byte("12345678901234567890123456789012"))
	grouped := strings.ToLower(secret[:8] + " \t" + secret[8:16] + "\r\n" + secret[16:24] + "\u00a0" + secret[24:])
	for _, input := range []string{
		"otpauth://totp/test?secret=" + url.QueryEscape(grouped) + "&algorithm=sha256&digits=8&image=https%3A%2F%2Fexample.invalid%2Ficon.png",
		"otpauth://totp/test?secret=" + url.QueryEscape(strings.TrimRight(grouped, "=")) + "&algorithm=SHA256&digits=8&image=a&image=b&future=anything",
	} {
		code, err := Generate(input, time.Unix(59, 0))
		if err != nil || code.Code != "46119246" || code.ValidUntil.Unix() != 60 {
			t.Fatalf("compatible RFC vector failed: %+v, %v", code, err)
		}
	}
	for _, prefix := range []string{"", "steam://"} {
		want, err := Generate(prefix+secret, time.Unix(59, 0))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Generate(prefix+grouped, time.Unix(59, 0))
		if err != nil || got != want {
			t.Fatalf("grouped secret failed for %q: %+v, %v", prefix, got, err)
		}
	}
}

func TestGenerateRecognizedParametersRemainStrict(t *testing.T) {
	encoder := base32.StdEncoding
	secret := encoder.EncodeToString([]byte("public test vector"))
	base := "otpauth://totp/test?secret=" + url.QueryEscape(secret)
	for _, query := range []string{
		"&secret=" + secret,
		"&issuer=a&issuer=b", "&algorithm=SHA1&algorithm=SHA256",
		"&digits=6&digits=8", "&period=30&period=60",
		"&algorithm=MD5", "&algorithm=", "&digits=5", "&digits=9",
		"&period=0", "&period=301", "&period=not-a-number",
	} {
		if _, err := Generate(base+query+"&image=ignored", time.Unix(59, 0)); err != vaulterr.ErrValidation {
			t.Fatalf("recognized malformed parameter accepted: %q, %v", query, err)
		}
	}
	for _, secret := range []string{"MZ======", "MY=====", "MY=======", "MY=AAAAA", "M!Y======", " \t\n"} {
		if _, err := Generate(secret, time.Unix(59, 0)); err != vaulterr.ErrValidation {
			t.Fatalf("invalid base32 accepted: %q, %v", secret, err)
		}
	}
}
