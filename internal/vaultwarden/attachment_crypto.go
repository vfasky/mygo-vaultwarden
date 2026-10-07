// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"
)

// Attachments use the SDK octet-stream format, not a JSON/base64 EncString.
// This ceiling bounds disk consumption; working memory stays at 64 KiB.
const attachmentPlaintextLimit int64 = 512 * 1024 * 1024
const attachmentHeaderSize int64 = 1 + aes.BlockSize + sha256.Size
const attachmentBufferSize = 64 * 1024

func attachmentEncryptedSize(size int64) (int64, error) {
	if size < 0 || size > attachmentPlaintextLimit {
		return 0, ErrValidation
	}
	return attachmentHeaderSize + (size/aes.BlockSize+1)*aes.BlockSize, nil
}

// A transfer owns its private spool until explicitly consumed and closed. Never
// expose this path as a download destination: publication requires the session
// and item authorization lease to be checked by the product layer.
type attachmentSpool struct {
	file *os.File
	size int64
}

func newAttachmentSpool() (*attachmentSpool, error) {
	f, err := os.CreateTemp("", "mygo-attachment-*")
	if err != nil {
		return nil, ErrEncryption
	}
	return &attachmentSpool{file: f}, nil // CreateTemp creates with mode 0600.
}
func (s *attachmentSpool) close() {
	if s == nil || s.file == nil {
		return
	}
	name := s.file.Name()
	_ = s.file.Close()
	_ = os.Remove(name)
	s.file = nil
}
func (s *attachmentSpool) rewind() error {
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return ErrEncryption
	}
	return nil
}
func attachmentRead(ctx context.Context, r io.Reader, b []byte) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if _, err := io.ReadFull(r, b); err != nil {
		if ctx.Err() != nil {
			return ErrCancelled
		}
		return ErrEncryption
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}
func attachmentEOF(ctx context.Context, r io.Reader) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	var extra [1]byte
	n, err := io.ReadFull(r, extra[:])
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if n != 0 || err != io.EOF {
		return ErrEncryption
	}
	return nil
}
func attachmentWrite(ctx context.Context, w io.Writer, b []byte) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	n, err := w.Write(b)
	if err != nil || n != len(b) {
		return ErrEncryption
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}

// encryptAttachment streams exactly size bytes, rejects short/long input and
// returns a rewound ciphertext spool. Cancellation/failure removes the spool.
// Blocking readers must themselves be bound to ctx (e.g. an HTTP request).
func encryptAttachment(ctx context.Context, source io.Reader, size int64, key []byte) (result *attachmentSpool, err error) {
	encryptedSize, err := attachmentEncryptedSize(size)
	if err != nil {
		return nil, err
	}
	if len(key) != 64 {
		return nil, ErrEncryption
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	spool, err := newAttachmentSpool()
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil {
			spool.close()
		}
	}()
	var header [attachmentHeaderSize]byte
	header[0] = 2
	iv := header[1:17]
	if _, err = rand.Read(iv); err != nil {
		return nil, ErrEncryption
	}
	if err = attachmentWrite(ctx, spool.file, header[:]); err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key[:32])
	cbc := cipher.NewCBCEncrypter(block, iv)
	mac := hmac.New(sha256.New, key[32:])
	_, _ = mac.Write(iv)
	buffer := make([]byte, attachmentBufferSize)
	defer clear(buffer)
	remaining := size
	for remaining >= aes.BlockSize {
		n := min(int64(len(buffer)), remaining/aes.BlockSize*aes.BlockSize)
		chunk := buffer[:int(n)]
		if err = attachmentRead(ctx, source, chunk); err != nil {
			return nil, err
		}
		cbc.CryptBlocks(chunk, chunk)
		_, _ = mac.Write(chunk)
		if err = attachmentWrite(ctx, spool.file, chunk); err != nil {
			return nil, err
		}
		remaining -= n
	}
	tail := buffer[:aes.BlockSize]
	if err = attachmentRead(ctx, source, tail[:int(remaining)]); err != nil {
		return nil, err
	}
	if err = attachmentEOF(ctx, source); err != nil {
		return nil, err
	}
	for i := int(remaining); i < len(tail); i++ {
		tail[i] = byte(aes.BlockSize - int(remaining))
	}
	cbc.CryptBlocks(tail, tail)
	_, _ = mac.Write(tail)
	if err = attachmentWrite(ctx, spool.file, tail); err != nil {
		return nil, err
	}
	if _, err = spool.file.Seek(17, io.SeekStart); err != nil {
		return nil, ErrEncryption
	}
	if err = attachmentWrite(ctx, spool.file, mac.Sum(nil)); err != nil {
		return nil, err
	}
	if err = spool.rewind(); err != nil {
		return nil, err
	}
	spool.size = encryptedSize
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return spool, nil
}

// decryptAttachment first authenticates the complete bounded ciphertext into a
// private spool. Only then is any plaintext written, to a second private spool.
// The caller cannot observe output on bad MAC, padding, size or cancellation.
func decryptAttachment(ctx context.Context, source io.Reader, size int64, key []byte) (result *attachmentSpool, err error) {
	maxSize, _ := attachmentEncryptedSize(attachmentPlaintextLimit)
	if len(key) != 64 || size < attachmentHeaderSize+aes.BlockSize || size > maxSize || (size-attachmentHeaderSize)%aes.BlockSize != 0 {
		return nil, ErrEncryption
	}
	var header [attachmentHeaderSize]byte
	if err = attachmentRead(ctx, source, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 2 {
		return nil, ErrEncryption
	}
	ciphertext, err := newAttachmentSpool()
	if err != nil {
		return nil, err
	}
	defer ciphertext.close()
	mac := hmac.New(sha256.New, key[32:])
	_, _ = mac.Write(header[1:17])
	buffer := make([]byte, attachmentBufferSize)
	defer clear(buffer)
	for remaining := size - attachmentHeaderSize; remaining > 0; {
		n := min(int64(len(buffer)), remaining)
		chunk := buffer[:int(n)]
		if err = attachmentRead(ctx, source, chunk); err != nil {
			return nil, err
		}
		_, _ = mac.Write(chunk)
		if err = attachmentWrite(ctx, ciphertext.file, chunk); err != nil {
			return nil, err
		}
		remaining -= n
	}
	if err = attachmentEOF(ctx, source); err != nil {
		return nil, err
	}
	if !hmac.Equal(header[17:], mac.Sum(nil)) {
		return nil, ErrEncryption
	}
	if err = ciphertext.rewind(); err != nil {
		return nil, err
	}
	plaintext, err := newAttachmentSpool()
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil {
			plaintext.close()
		}
	}()
	block, _ := aes.NewCipher(key[:32])
	cbc := cipher.NewCBCDecrypter(block, header[1:17])
	for remaining := size - attachmentHeaderSize; remaining > 0; {
		n := min(int64(len(buffer)), remaining)
		chunk := buffer[:int(n)]
		if err = attachmentRead(ctx, ciphertext.file, chunk); err != nil {
			return nil, err
		}
		cbc.CryptBlocks(chunk, chunk)
		remaining -= n
		if remaining == 0 {
			padding := int(chunk[len(chunk)-1])
			if padding < 1 || padding > aes.BlockSize {
				return nil, ErrEncryption
			}
			for _, value := range chunk[len(chunk)-padding:] {
				if int(value) != padding {
					return nil, ErrEncryption
				}
			}
			chunk = chunk[:len(chunk)-padding]
		}
		if err = attachmentWrite(ctx, plaintext.file, chunk); err != nil {
			return nil, err
		}
		plaintext.size += int64(len(chunk))
	}
	if plaintext.size > attachmentPlaintextLimit {
		return nil, ErrEncryption
	}
	if err = plaintext.rewind(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return plaintext, nil
}
