// SPDX-License-Identifier: GPL-3.0-only
package vaultcrypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaulterr"
	"io"
	"os"
)

// Attachments use the SDK octet-stream format, not a JSON/base64 EncString.
// This ceiling bounds disk consumption; working memory stays at 64 KiB.
const AttachmentPlaintextLimit int64 = 512 * 1024 * 1024
const AttachmentHeaderSize int64 = 1 + aes.BlockSize + sha256.Size
const AttachmentBufferSize = 64 * 1024

func AttachmentEncryptedSize(size int64) (int64, error) {
	if size < 0 || size > AttachmentPlaintextLimit {
		return 0, vaulterr.ErrValidation
	}
	return AttachmentHeaderSize + (size/aes.BlockSize+1)*aes.BlockSize, nil
}

// A transfer owns an unlinked private spool until explicitly consumed and closed.
// Publication requires the session and item authorization lease to be checked by
// the product layer. Unlinking prevents pathname access and crash leftovers; it
// does not protect against an attacker able to access this process's descriptors.
type AttachmentSpool struct {
	File *os.File
	Size int64
}

func newAttachmentSpool() (*AttachmentSpool, error) {
	f, err := os.CreateTemp("", "mygo-attachment-*")
	if err != nil {
		return nil, vaulterr.ErrEncryption
	}
	// Unlink before writing any data and retain this descriptor through MAC
	// verification and decryption. Platforms that cannot unlink an open file
	// fail closed; never fall back to a named plaintext spool.
	if err := os.Remove(f.Name()); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, vaulterr.ErrEncryption
	}
	return &AttachmentSpool{File: f}, nil // CreateTemp creates with mode 0600.
}
func (s *AttachmentSpool) Close() {
	if s == nil || s.File == nil {
		return
	}
	_ = s.File.Close()
	s.File = nil
}
func (s *AttachmentSpool) Rewind() error {
	if _, err := s.File.Seek(0, io.SeekStart); err != nil {
		return vaulterr.ErrEncryption
	}
	return nil
}
func AttachmentRead(ctx context.Context, r io.Reader, b []byte) error {
	if ctx.Err() != nil {
		return vaulterr.ErrCancelled
	}
	if _, err := io.ReadFull(r, b); err != nil {
		if ctx.Err() != nil {
			return vaulterr.ErrCancelled
		}
		return vaulterr.ErrEncryption
	}
	if ctx.Err() != nil {
		return vaulterr.ErrCancelled
	}
	return nil
}
func AttachmentEOF(ctx context.Context, r io.Reader) error {
	if ctx.Err() != nil {
		return vaulterr.ErrCancelled
	}
	var extra [1]byte
	n, err := io.ReadFull(r, extra[:])
	if ctx.Err() != nil {
		return vaulterr.ErrCancelled
	}
	if n != 0 || err != io.EOF {
		return vaulterr.ErrEncryption
	}
	return nil
}
func AttachmentWrite(ctx context.Context, w io.Writer, b []byte) error {
	if ctx.Err() != nil {
		return vaulterr.ErrCancelled
	}
	n, err := w.Write(b)
	if err != nil || n != len(b) {
		return vaulterr.ErrEncryption
	}
	if ctx.Err() != nil {
		return vaulterr.ErrCancelled
	}
	return nil
}

// encryptAttachment streams exactly size bytes, rejects short/long input and
// returns a rewound ciphertext spool. Cancellation/failure removes the spool.
// Blocking readers must themselves be bound to ctx (e.g. an HTTP request).
func EncryptAttachment(ctx context.Context, source io.Reader, size int64, key []byte) (result *AttachmentSpool, err error) {
	encryptedSize, err := AttachmentEncryptedSize(size)
	if err != nil {
		return nil, err
	}
	if len(key) != 64 {
		return nil, vaulterr.ErrEncryption
	}
	if ctx.Err() != nil {
		return nil, vaulterr.ErrCancelled
	}
	spool, err := newAttachmentSpool()
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil {
			spool.Close()
		}
	}()
	var header [AttachmentHeaderSize]byte
	header[0] = 2
	iv := header[1:17]
	if _, err = rand.Read(iv); err != nil {
		return nil, vaulterr.ErrEncryption
	}
	if err = AttachmentWrite(ctx, spool.File, header[:]); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key[:32])
	cbc := cipher.NewCBCEncrypter(block, iv)
	mac := hmac.New(sha256.New, key[32:])
	_, _ = mac.Write(iv)
	buffer := make([]byte, AttachmentBufferSize)
	defer clear(buffer)
	remaining := size
	for remaining >= aes.BlockSize {
		n := min(int64(len(buffer)), remaining/aes.BlockSize*aes.BlockSize)
		chunk := buffer[:int(n)]
		if err = AttachmentRead(ctx, source, chunk); err != nil {
			return nil, err
		}
		cbc.CryptBlocks(chunk, chunk)
		_, _ = mac.Write(chunk)
		if err = AttachmentWrite(ctx, spool.File, chunk); err != nil {
			return nil, err
		}
		remaining -= n
	}
	tail := buffer[:aes.BlockSize]
	if err = AttachmentRead(ctx, source, tail[:int(remaining)]); err != nil {
		return nil, err
	}
	if err = AttachmentEOF(ctx, source); err != nil {
		return nil, err
	}
	for i := int(remaining); i < len(tail); i++ {
		tail[i] = byte(aes.BlockSize - int(remaining))
	}
	cbc.CryptBlocks(tail, tail)
	_, _ = mac.Write(tail)
	if err = AttachmentWrite(ctx, spool.File, tail); err != nil {
		return nil, err
	}
	if _, err = spool.File.Seek(17, io.SeekStart); err != nil {
		return nil, vaulterr.ErrEncryption
	}
	if err = AttachmentWrite(ctx, spool.File, mac.Sum(nil)); err != nil {
		return nil, err
	}
	if err = spool.Rewind(); err != nil {
		return nil, err
	}
	spool.Size = encryptedSize
	if ctx.Err() != nil {
		return nil, vaulterr.ErrCancelled
	}
	return spool, nil
}

// decryptAttachment first authenticates the complete bounded ciphertext into a
// private spool. Only then is any plaintext written, to a second private spool.
// The caller cannot observe output on bad MAC, padding, size or cancellation.
func DecryptAttachment(ctx context.Context, source io.Reader, size int64, key []byte) (result *AttachmentSpool, err error) {
	maxSize, _ := AttachmentEncryptedSize(AttachmentPlaintextLimit)
	if len(key) != 64 || size < AttachmentHeaderSize+aes.BlockSize || size > maxSize || (size-AttachmentHeaderSize)%aes.BlockSize != 0 {
		return nil, vaulterr.ErrEncryption
	}
	var header [AttachmentHeaderSize]byte
	if err = AttachmentRead(ctx, source, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 2 {
		return nil, vaulterr.ErrEncryption
	}
	ciphertext, err := newAttachmentSpool()
	if err != nil {
		return nil, err
	}
	defer ciphertext.Close()
	mac := hmac.New(sha256.New, key[32:])
	_, _ = mac.Write(header[1:17])
	buffer := make([]byte, AttachmentBufferSize)
	defer clear(buffer)
	for remaining := size - AttachmentHeaderSize; remaining > 0; {
		n := min(int64(len(buffer)), remaining)
		chunk := buffer[:int(n)]
		if err = AttachmentRead(ctx, source, chunk); err != nil {
			return nil, err
		}
		_, _ = mac.Write(chunk)
		if err = AttachmentWrite(ctx, ciphertext.File, chunk); err != nil {
			return nil, err
		}
		remaining -= n
	}
	if err = AttachmentEOF(ctx, source); err != nil {
		return nil, err
	}
	if !hmac.Equal(header[17:], mac.Sum(nil)) {
		return nil, vaulterr.ErrEncryption
	}
	if err = ciphertext.Rewind(); err != nil {
		return nil, err
	}
	plaintext, err := newAttachmentSpool()
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil {
			plaintext.Close()
		}
	}()
	block, _ := aes.NewCipher(key[:32])
	cbc := cipher.NewCBCDecrypter(block, header[1:17])
	for remaining := size - AttachmentHeaderSize; remaining > 0; {
		n := min(int64(len(buffer)), remaining)
		chunk := buffer[:int(n)]
		if err = AttachmentRead(ctx, ciphertext.File, chunk); err != nil {
			return nil, err
		}
		cbc.CryptBlocks(chunk, chunk)
		remaining -= n
		if remaining == 0 {
			padding := int(chunk[len(chunk)-1])
			if padding < 1 || padding > aes.BlockSize {
				return nil, vaulterr.ErrEncryption
			}
			for _, value := range chunk[len(chunk)-padding:] {
				if int(value) != padding {
					return nil, vaulterr.ErrEncryption
				}
			}
			chunk = chunk[:len(chunk)-padding]
		}
		if err = AttachmentWrite(ctx, plaintext.File, chunk); err != nil {
			return nil, err
		}
		plaintext.Size += int64(len(chunk))
	}
	if plaintext.Size > AttachmentPlaintextLimit {
		return nil, vaulterr.ErrEncryption
	}
	if err = plaintext.Rewind(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, vaulterr.ErrCancelled
	}
	return plaintext, nil
}
