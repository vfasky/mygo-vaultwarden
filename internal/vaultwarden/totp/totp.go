// SPDX-License-Identifier: GPL-3.0-only
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// TOTPCode is ephemeral secret material; it must never enter display metadata,
// status messages or logs. ValidUntil is exclusive, including at period edges.
type Code struct {
	Code       string
	ValidUntil time.Time
}

// Generate implements RFC 6238 and the Steam alphabet from Bitwarden SDK
// 39dbb510f5eae82f5cbfd527b0f70a01d5626ec1. It tolerates display/import metadata
// and whitespace grouping, but rejects malformed secrets and invalid known parameters.
// This is a code-generation parser, not a validator for persisted input.
// Supported resource limits: 6–8 decimal digits, 1–300 seconds, 1–1024 key bytes.
func Generate(input string, now time.Time) (Code, error) {
	if len(input) == 0 || len(input) > 4096 || now.Unix() < 0 || now.Unix() > 253402300499 {
		return Code{}, vaulterr.ErrValidation
	}
	secret := strings.TrimSpace(input)
	period, digits := int64(30), 6
	algorithm := "SHA1"
	steam := false
	lower := strings.ToLower(secret)
	if strings.HasPrefix(lower, "steam://") {
		steam, secret = true, secret[len("steam://"):]
	} else if strings.HasPrefix(lower, "otpauth://") {
		u, err := url.Parse(secret)
		if err != nil || !strings.EqualFold(u.Scheme, "otpauth") || !strings.EqualFold(u.Host, "totp") || u.User != nil || u.Fragment != "" || u.Path == "" {
			return Code{}, vaulterr.ErrValidation
		}
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return Code{}, vaulterr.ErrValidation
		}
		for key, values := range q {
			switch key {
			case "secret", "issuer", "algorithm", "digits", "period":
				if len(values) != 1 {
					return Code{}, vaulterr.ErrValidation
				}
			default:
				// Metadata such as image does not affect code generation.
				continue
			}
		}
		secret = q.Get("secret")
		if value, ok := q["algorithm"]; ok {
			algorithm = strings.ToUpper(value[0])
		}
		if value, ok := q["period"]; ok {
			period, err = strconv.ParseInt(value[0], 10, 64)
			if err != nil || period < 1 || period > 300 {
				return Code{}, vaulterr.ErrValidation
			}
		}
		if value, ok := q["digits"]; ok {
			digits, err = strconv.Atoi(value[0])
			if err != nil || digits < 6 || digits > 8 {
				return Code{}, vaulterr.ErrValidation
			}
		}
	}
	var makeHash func() hash.Hash
	switch algorithm {
	case "SHA1":
		makeHash = sha1.New
	case "SHA256":
		makeHash = sha256.New
	case "SHA512":
		makeHash = sha512.New
	default:
		return Code{}, vaulterr.ErrValidation
	}
	secret = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToUpper(r)
	}, secret)
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	if strings.Contains(secret, "=") {
		encoding = base32.StdEncoding
	}
	key, err := encoding.DecodeString(secret)
	if err != nil || len(key) == 0 || len(key) > 1024 {
		clear(key)
		return Code{}, vaulterr.ErrValidation
	}
	defer clear(key)
	// Reject non-canonical padding/trailing bits after normalizing whitespace.
	if encoding.EncodeToString(key) != secret {
		return Code{}, vaulterr.ErrValidation
	}
	counter := uint64(now.Unix() / period)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(makeHash, key)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	defer clear(digest)
	offset := int(digest[len(digest)-1] & 15)
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	result := Code{ValidUntil: time.Unix((int64(counter)+1)*period, 0)}
	if steam {
		const alphabet = "23456789BCDFGHJKMNPQRTVWXY"
		var code [5]byte
		for i := range code {
			code[i] = alphabet[value%uint32(len(alphabet))]
			value /= uint32(len(alphabet))
		}
		result.Code = string(code[:])
	} else {
		modulus := uint32(1)
		for i := 0; i < digits; i++ {
			modulus *= 10
		}
		result.Code = fmt.Sprintf("%0*d", digits, value%modulus)
	}
	return result, nil
}
