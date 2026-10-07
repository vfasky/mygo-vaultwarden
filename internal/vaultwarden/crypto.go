// SPDX-License-Identifier: GPL-3.0-only
// Protocol and test-vector references: bitwarden/sdk-internal bitwarden-crypto.
package vaultwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type KDF struct {
	Type        int     `json:"kdf"`
	Iterations  int     `json:"kdfIterations"`
	Memory      int     `json:"kdfMemory"`
	Parallelism int     `json:"kdfParallelism"`
	Salt        *string `json:"salt"`
}

func NormalizeEmail(email string) string {
	return cases.Lower(language.Und).String(strings.TrimSpace(email))
}

func DeriveMaster(password []byte, email string, kdf KDF) ([]byte, error) {
	email = NormalizeEmail(email)
	if len(password) == 0 || len(password) > 8192 || len(email) == 0 || len(email) > 1024 || !utf8.Valid(password) {
		return nil, ErrCredentials
	}
	if kdf.Salt != nil && *kdf.Salt != "" && *kdf.Salt != email {
		return nil, ErrKDF
	}
	switch kdf.Type {
	case 0:
		if kdf.Iterations < 5000 || kdf.Iterations > 2000000 {
			return nil, ErrKDF
		}
		return pbkdf2.Key(password, []byte(email), kdf.Iterations, 32, sha256.New), nil
	case 1:
		if kdf.Iterations < 2 || kdf.Iterations > 10 || kdf.Memory < 16 || kdf.Memory > 256 || kdf.Parallelism < 1 || kdf.Parallelism > 16 {
			return nil, ErrKDF
		}
		salt := sha256.Sum256([]byte(email))
		return argon2.IDKey(password, salt[:], uint32(kdf.Iterations), uint32(kdf.Memory)*1024, uint8(kdf.Parallelism), 32), nil
	default:
		return nil, ErrKDF
	}
}

func AuthorizationHash(master, password []byte) string {
	hash := pbkdf2.Key(master, password, 1, 32, sha256.New)
	defer clear(hash)
	return base64.StdEncoding.EncodeToString(hash)
}

func StretchMaster(master []byte) ([]byte, error) {
	if len(master) != 32 {
		return nil, ErrEncryption
	}
	enc, err := hkdf.Expand(sha256.New, master, "enc", 32)
	if err != nil {
		return nil, ErrEncryption
	}
	mac, err := hkdf.Expand(sha256.New, master, "mac", 32)
	if err != nil {
		clear(enc)
		return nil, ErrEncryption
	}
	defer clear(enc)
	defer clear(mac)
	return append(append(make([]byte, 0, 64), enc...), mac...), nil
}

// Only authenticated type-2 AES256-CBC/HMAC strings are accepted. Legacy type 0
// and newer COSE type 7 fail explicitly rather than being misinterpreted.
func DecryptString(encoded string, key []byte) ([]byte, error) {
	if len(key) != 64 || !strings.HasPrefix(encoded, "2.") || len(encoded) > 2*1024*1024 {
		return nil, ErrEncryption
	}
	parts := strings.Split(encoded[2:], "|")
	if len(parts) != 3 {
		return nil, ErrEncryption
	}
	iv, e1 := base64.StdEncoding.Strict().DecodeString(parts[0])
	data, e2 := base64.StdEncoding.Strict().DecodeString(parts[1])
	mac, e3 := base64.StdEncoding.Strict().DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil || len(iv) != aes.BlockSize || len(mac) != sha256.Size || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, ErrEncryption
	}
	expected := hmac.New(sha256.New, key[32:])
	expected.Write(iv)
	expected.Write(data)
	if !hmac.Equal(mac, expected.Sum(nil)) {
		return nil, ErrEncryption
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, ErrEncryption
	}
	plaintext := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, data)
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(plaintext) {
		clear(plaintext)
		return nil, ErrEncryption
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			clear(plaintext)
			return nil, ErrEncryption
		}
	}
	result := append([]byte(nil), plaintext[:len(plaintext)-padding]...)
	clear(plaintext)
	return result, nil
}

// EncryptString emits the authenticated type-2 format used by Vaultwarden
// 1.37.4 clients. Every invocation gets an independent cryptographic random IV.
func EncryptString(plaintext, key []byte) (string, error) {
	if len(key) != 64 || len(plaintext) > 1024*1024 {
		return "", ErrEncryption
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", ErrEncryption
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	data := make([]byte, len(plaintext)+padding)
	copy(data, plaintext)
	for i := len(plaintext); i < len(data); i++ {
		data[i] = byte(padding)
	}
	defer clear(data)
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", ErrEncryption
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	mac := hmac.New(sha256.New, key[32:])
	mac.Write(iv)
	mac.Write(data)
	return "2." + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(data) + "|" + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func decryptText(encoded *string, key []byte) (string, error) {
	if encoded == nil || *encoded == "" {
		return "", nil
	}
	plaintext, err := DecryptString(*encoded, key)
	if err != nil {
		return "", err
	}
	defer clear(plaintext)
	if !utf8.Valid(plaintext) {
		return "", ErrEncryption
	}
	return string(plaintext), nil
}
