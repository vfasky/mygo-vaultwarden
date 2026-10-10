// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
	"io"
	"os"
	"testing"
)

// Independent official SDK fixture, pinned to 39dbb510f5eae82f5cbfd527b0f70a01d5626ec1:
// crates/bitwarden-vault/src/cipher/attachment.rs::test_attachment_without_key.
func officialAttachmentVector(t *testing.T) (key, encrypted, plaintext []byte) {
	t.Helper()
	decode := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	key = decode("w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==")
	encrypted = decode("AsQLXOBHrJ8porroTUlPxeJOm9XID7LL9D2+KwYATXEpR1EFjLBpcCvMmnqcnYLXIEefe9TCeY4Us50ux43kRSpvdB7YkjxDKV0O1/y6tB7qC4vvv9J9+O/uDEnMx/9yXuEhAW/LA/TsU/WAgxkOM0uTvm8JdD9LUR1z9Ql7zOWycMVzkvGsk2KBNcqAdrotS5FlDftZOXyU8pWecNeyA/w=")
	// Full expected binary from the upstream test, not text/UTF-8.
	plaintext = decode("rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==")
	return
}
func TestAttachmentOfficialVector(t *testing.T) {
	key, encrypted, expected := officialAttachmentVector(t)
	spool, err := vaultcrypto.DecryptAttachment(context.Background(), bytes.NewReader(encrypted), int64(len(encrypted)), key)
	if err != nil {
		t.Fatal(err)
	}
	name := spool.File.Name()
	stat, err := spool.File.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v", stat.Mode())
	}
	actual, err := io.ReadAll(spool.File)
	if err != nil || !bytes.Equal(actual, expected) || spool.Size != int64(len(expected)) {
		t.Fatalf("official vector mismatch: %v", err)
	}
	spool.Close()
	spool.Close()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("spool not removed: %v", err)
	}
}
func TestAttachmentSizesAndStringInteroperability(t *testing.T) {
	key, _, _ := officialAttachmentVector(t)
	for _, size := range []int{0, 1, 15, 16, 17, 65535, 65536, 65537, 8*1024*1024 + 3} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			original := bytes.Repeat([]byte{0, 0xff, 2, 0x80, 3}, size/5+1)[:size]
			encrypted, err := vaultcrypto.EncryptAttachment(context.Background(), bytes.NewReader(original), int64(size), key)
			if err != nil {
				t.Fatal(err)
			}
			defer encrypted.Close()
			actual, err := io.ReadAll(encrypted.File)
			if err != nil {
				t.Fatal(err)
			}
			expectedSize, _ := vaultcrypto.AttachmentEncryptedSize(int64(size))
			if int64(len(actual)) != expectedSize || encrypted.Size != expectedSize {
				t.Fatal("wrong ciphertext size")
			}
			if size < 65537 {
				b64 := base64.StdEncoding.EncodeToString
				encoded := "2." + b64(actual[1:17]) + "|" + b64(actual[49:]) + "|" + b64(actual[17:49])
				decoded, err := vaultcrypto.DecryptString(encoded, key)
				if err != nil || !bytes.Equal(decoded, original) {
					t.Fatalf("string format interop: %v", err)
				}
			}
			// Read through a reader which deliberately fragments every read.
			plain, err := vaultcrypto.DecryptAttachment(context.Background(), &attachmentSmallReader{r: bytes.NewReader(actual)}, encrypted.Size, key)
			if err != nil {
				t.Fatal(err)
			}
			defer plain.Close()
			decoded, err := io.ReadAll(plain.File)
			if err != nil || !bytes.Equal(decoded, original) {
				t.Fatalf("roundtrip: %v", err)
			}
		})
	}
}

type attachmentSmallReader struct{ r io.Reader }

func (r *attachmentSmallReader) Read(p []byte) (int, error) { return r.r.Read(p[:min(len(p), 997)]) }

func TestAttachmentRejectsCorruptionAndCleansSpools(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	key, encrypted, _ := officialAttachmentVector(t)
	check := func(data []byte, size int64, k []byte) {
		t.Helper()
		result, err := vaultcrypto.DecryptAttachment(context.Background(), bytes.NewReader(data), size, k)
		if err == nil || result != nil {
			if result != nil {
				result.Close()
			}
			t.Fatal("accepted corrupt input")
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatalf("temporary file leak: %v %v", entries, err)
		}
	}
	for i := range encrypted {
		changed := bytes.Clone(encrypted)
		changed[i] ^= 1
		check(changed, int64(len(changed)), key)
	}
	for i := 0; i < len(encrypted); i++ {
		check(encrypted[:i], int64(len(encrypted)), key)
	}
	check(append(bytes.Clone(encrypted), 0), int64(len(encrypted)), key)
	check(encrypted, int64(len(encrypted))+16, key)
	check(encrypted, int64(len(encrypted))-16, key)
	check(encrypted, -1, key)
	check(encrypted, 1<<62, key)
	check(encrypted, int64(len(encrypted)), key[:32])
	wrongKey := bytes.Clone(key)
	wrongKey[32] ^= 1
	check(encrypted, int64(len(encrypted)), wrongKey)
	// Correctly authenticated ciphertext with invalid PKCS#7 padding.
	invalid := make([]byte, 65)
	invalid[0] = 2
	block, _ := aes.NewCipher(key[:32])
	cipher.NewCBCEncrypter(block, invalid[1:17]).CryptBlocks(invalid[49:], make([]byte, 16))
	mac := hmac.New(sha256.New, key[32:])
	mac.Write(invalid[1:17])
	mac.Write(invalid[49:])
	copy(invalid[17:49], mac.Sum(nil))
	check(invalid, int64(len(invalid)), key)
}

type attachmentCancelReader struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (r *attachmentCancelReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.cancel()
	return n, err
}
func TestAttachmentCancellationAndInputBounds(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	key, encrypted, _ := officialAttachmentVector(t)
	for _, decrypt := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		reader := &attachmentCancelReader{r: bytes.NewReader(encrypted), cancel: cancel}
		var spool *vaultcrypto.AttachmentSpool
		var err error
		if decrypt {
			spool, err = vaultcrypto.DecryptAttachment(ctx, reader, int64(len(encrypted)), key)
		} else {
			spool, err = vaultcrypto.EncryptAttachment(ctx, reader, int64(len(encrypted)), key)
		}
		cancel()
		if !errors.Is(err, vaulterr.ErrCancelled) || spool != nil {
			t.Fatalf("cancel: %v", err)
		}
	}
	for _, size := range []int64{-1, 0, 1, 17, vaultcrypto.AttachmentPlaintextLimit + 1, 1 << 62} {
		spool, err := vaultcrypto.EncryptAttachment(context.Background(), bytes.NewReader([]byte{1, 2}), size, key)
		if err == nil || spool != nil {
			t.Fatal("accepted mismatched or unbounded input")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("spool leak: %v %v", entries, err)
	}
}
