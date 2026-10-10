// SPDX-License-Identifier: GPL-3.0-only
package totp

import (
	"encoding/base32"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
	"testing"
	"time"
)

func TestTOTPRFC6238(t *testing.T) {
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	for _, test := range []struct {
		algorithm, secret string
		codes             []string
	}{
		{"SHA1", "12345678901234567890", []string{"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"}},
		{"SHA256", "12345678901234567890123456789012", []string{"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"}},
		{"SHA512", "1234567890123456789012345678901234567890123456789012345678901234", []string{"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"}},
	} {
		for i, timestamp := range times {
			input := fmt.Sprintf("otpauth://totp/test?secret=%s&algorithm=%s&digits=8", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(test.secret)), test.algorithm)
			result, err := Generate(input, time.Unix(timestamp, 0))
			if err != nil || result.Code != test.codes[i] || result.ValidUntil.Unix() != (timestamp/30+1)*30 {
				t.Fatalf("%s vector %d failed: %v", test.algorithm, i, err)
			}
		}
	}
}
func TestTOTPSteamAndExpiry(t *testing.T) {
	now := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	code, err := Generate("StEam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", now)
	if err != nil || code.Code != "7W6CJ" {
		t.Fatal("fixed SDK Steam vector failed", err)
	}
	before, err := Generate("WQIQ25BRKZYCJVYP", now.Add(30*time.Second-time.Nanosecond))
	if err != nil || before.Code != "194506" || !before.ValidUntil.Equal(now.Add(30*time.Second)) {
		t.Fatal("period before boundary failed", err)
	}
	after, err := Generate("wqiq25brkzycjvyp", before.ValidUntil)
	if err != nil || after.Code == before.Code || !after.ValidUntil.Equal(now.Add(time.Minute)) {
		t.Fatal("exclusive expiry failed", err)
	}
}
func TestTOTPRejectsAmbiguousParameters(t *testing.T) {
	for _, input := range []string{"", "ABCD123", "PIUD1IS!EQYA=", "WQIQ\n25BRKZYCJVYP", "otpauth://hotp/a?secret=WQIQ25BRKZYCJVYP", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&algorithm=MD5", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&digits=10", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&period=0", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&period=301", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&secret=PIUDISEQYA", "otpauth://user@totp/a?secret=WQIQ25BRKZYCJVYP", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP#fragment", "otpauth://totp/a?secret=WQIQ25BRKZYCJVYP&counter=1"} {
		if _, err := Generate(input, time.Unix(100, 0)); err != vaulterr.ErrValidation {
			t.Fatal("malformed TOTP accepted")
		}
	}
	if _, err := Generate("WQIQ25BRKZYCJVYP", time.Unix(-1, 0)); err != vaulterr.ErrValidation {
		t.Fatal("negative time accepted")
	}
}
