// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A signed download URL is a separate capability. Never attach the account
// bearer, device headers, a cookie jar or a Referer, even to the vault origin.
// Plain HTTP is allowed only at the explicitly configured loopback origin.
func (c *Client) attachmentDownloadURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 16384 || strings.TrimSpace(raw) != raw {
		return nil, ErrServer
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" {
		return nil, ErrServer
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && c.base.Scheme == "http" && u.Host == c.base.Host) {
		return nil, ErrServer
	}
	// Escaping is legitimate in signed URLs, but decoded path traversal and
	// alternate separators must not be handed to an intermediary for rewriting.
	if strings.ContainsAny(u.Path, "\\\r\n\x00") {
		return nil, ErrServer
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, ErrServer
		}
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return nil, ErrServer
	}
	return u, nil
}

func (c *Client) attachmentHTTPClient() *http.Client {
	// Copy only the transport. No ambient cookie jar, redirect policy or auth
	// headers can be inherited by the independently bounded file request.
	return &http.Client{Transport: c.http.Transport, Timeout: 5 * time.Minute,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *Client) downloadAttachment(ctx context.Context, rawURL string, size int64, key []byte) (*attachmentSpool, error) {
	maxSize, _ := attachmentEncryptedSize(attachmentPlaintextLimit)
	if size < attachmentHeaderSize+16 || size > maxSize || (size-attachmentHeaderSize)%16 != 0 || len(key) != 64 {
		return nil, ErrEncryption
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	u, err := c.attachmentDownloadURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrProtocol
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.attachmentHTTPClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrCancelled
		}
		return nil, ErrNetwork
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrServer
	}
	if (resp.ContentLength >= 0 && resp.ContentLength != size) || (resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity") {
		return nil, ErrProtocol
	}
	// The extra byte detects oversized chunked responses without consuming the
	// rest of an attacker-controlled stream. No error includes the signed URL.
	return decryptAttachment(ctx, io.LimitReader(resp.Body, size+1), size, key)
}

// uploadAttachment performs one direct v2 multipart request. The destination is
// reconstructed from validated IDs, never accepted from an untrusted upload URL.
// The session layer owns token refresh/checkpoint, policy/reprompt guards and
// handling unknown outcomes; this function never retries or deletes metadata.
func (c *Client) uploadAttachment(ctx context.Context, cipherID, attachmentID, token string, encrypted *attachmentSpool) (int, error) {
	if !validObjectID(cipherID) || !validObjectID(attachmentID) || token == "" || encrypted == nil || encrypted.file == nil {
		return 0, ErrValidation
	}
	maxSize, _ := attachmentEncryptedSize(attachmentPlaintextLimit)
	if encrypted.size < attachmentHeaderSize+16 || encrypted.size > maxSize || (encrypted.size-attachmentHeaderSize)%16 != 0 {
		return 0, ErrValidation
	}
	if ctx.Err() != nil {
		return 0, ErrCancelled
	}
	if err := encrypted.rewind(); err != nil {
		return 0, err
	}
	// Build only the small multipart envelope in memory, streaming the ciphertext
	// directly from disk. A fixed public filename avoids plaintext metadata leaks.
	var envelope bytes.Buffer
	writer := multipart.NewWriter(&envelope)
	if _, err := writer.CreateFormFile("data", "attachment.bin"); err != nil {
		return 0, ErrProtocol
	}
	prefix := bytes.Clone(envelope.Bytes())
	envelope.Reset()
	if err := writer.Close(); err != nil {
		return 0, ErrProtocol
	}
	suffix := bytes.Clone(envelope.Bytes())
	u := *c.base
	u.Path += "/api/ciphers/" + cipherID + "/attachment/" + attachmentID
	body := io.MultiReader(bytes.NewReader(prefix), io.LimitReader(encrypted.file, encrypted.size), bytes.NewReader(suffix))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return 0, ErrProtocol
	}
	req.ContentLength = int64(len(prefix)) + encrypted.size + int64(len(suffix))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.attachmentHTTPClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ErrCancelled
		}
		return 0, ErrNetwork
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, ErrServer
	}
	// No file response should be large; drain a bounded error/success response
	// without propagating its possibly sensitive contents into logs or UI.
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024+1))
	if ctx.Err() != nil {
		return resp.StatusCode, ErrCancelled
	}
	if err != nil || n > 64*1024 {
		return resp.StatusCode, ErrProtocol
	}
	return resp.StatusCode, nil
}
