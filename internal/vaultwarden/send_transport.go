// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func sendSize(n int64) string { return strconv.FormatInt(n, 10) }
func (c *Client) uploadSend(ctx context.Context, id, fileID, name, token string, spool *vaultcrypto.AttachmentSpool) (int, error) {
	if !validObjectID(id) || !validObjectID(fileID) || token == "" || spool == nil || spool.File == nil || len(name) > 16384 || strings.ContainsAny(name, "\r\n") {
		return 0, ErrValidation
	}
	if e := spool.Rewind(); e != nil {
		return 0, e
	}
	var envelope bytes.Buffer
	writer := multipart.NewWriter(&envelope)
	if _, e := writer.CreateFormFile("data", name); e != nil {
		return 0, ErrProtocol
	}
	prefix := bytes.Clone(envelope.Bytes())
	envelope.Reset()
	if writer.Close() != nil {
		return 0, ErrProtocol
	}
	suffix := bytes.Clone(envelope.Bytes())
	u := *c.base
	u.Path += "/api/sends/" + id + "/file/" + fileID
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), io.MultiReader(bytes.NewReader(prefix), io.LimitReader(spool.File, spool.Size), bytes.NewReader(suffix)))
	if e != nil {
		return 0, ErrProtocol
	}
	req.ContentLength = int64(len(prefix)+len(suffix)) + spool.Size
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Device-Type", "7")
	req.Header.Set("Accept", "application/json")
	resp, e := c.attachmentHTTPClient().Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return 0, ErrCancelled
		}
		return 0, ErrNetwork
	}
	defer resp.Body.Close()
	n, e := io.Copy(io.Discard, io.LimitReader(resp.Body, 65537))
	if e != nil || n > 65536 {
		return resp.StatusCode, ErrProtocol
	}
	if ctx.Err() != nil {
		return resp.StatusCode, ErrCancelled
	}
	return resp.StatusCode, nil
}

var ErrSendPasswordRequired = errors.New(i18n.T("server.send.err_password_required"))
var ErrSendPasswordInvalid = errors.New(i18n.T("server.send.err_password_invalid"))

// SendReceiver is independent of the owner session. Close cancels transfers and
// revokes publication. Do not log link, token, fields or key; Fields returns a
// caller-owned view which the UI must clear on lock/close.
type SendReceiver struct {
	mu                 sync.Mutex
	cancel             context.CancelFunc
	ctx                context.Context
	client             *Client
	seed               []byte
	token              string
	expires            time.Time
	wire               sendWire
	closed, downloaded bool
}

func (c *Client) sendRequest(ctx context.Context, endpoint, kind, body, token string) (int, []byte, error) {
	// Isolated client has no cookie jar; request() supplies only its explicit
	// scoped token. It never receives the owner's access token.
	isolated := &Client{base: c.base, http: c.attachmentHTTPClient(), deviceID: c.deviceID}
	return isolated.request(ctx, http.MethodPost, endpoint, kind, body, token)
}
func (c *Client) OpenSend(ctx context.Context, link, password string) (*SendReceiver, error) {
	id, seed, e := ParseSendLink(c.base.String(), link)
	if e != nil {
		return nil, e
	}
	defer clear(seed)
	if len(password) > 4096 {
		return nil, ErrValidation
	}
	form := url.Values{"grant_type": {"send_access"}, "client_id": {"desktop"}, "send_id": {id}}
	if password != "" {
		form.Set("password_hash_b64", sendPassword(password, seed))
	}
	status, b, e := c.sendRequest(ctx, "/identity/connect/token", "application/x-www-form-urlencoded", form.Encode(), "")
	if e != nil {
		return nil, e
	}
	defer clear(b)
	if status != 200 {
		var failure struct {
			Type string `json:"send_access_error_type"`
		}
		_ = json.Unmarshal(b, &failure)
		switch failure.Type {
		case "password_hash_b64_required":
			return nil, ErrSendPasswordRequired
		case "password_hash_b64_invalid":
			return nil, ErrSendPasswordInvalid
		}
		return nil, statusError(status)
	}
	var grant struct {
		Token   string `json:"access_token"`
		Expires int    `json:"expires_in"`
		Type    string `json:"token_type"`
		Scope   string `json:"scope"`
	}
	if strictJSON(b) != nil || json.Unmarshal(b, &grant) != nil || grant.Token == "" || len(grant.Token) > 16384 || strings.ContainsAny(grant.Token, "\r\n") || grant.Expires <= 0 || grant.Expires > 3600 || grant.Type != "Bearer" || grant.Scope != "api.send.access" {
		return nil, ErrProtocol
	}
	expires := time.Now().Add(time.Duration(grant.Expires) * time.Second)
	status, b, e = c.sendRequest(ctx, "/api/sends/access", "", "", grant.Token)
	if e != nil {
		return nil, &MutationUncertainError{Cause: e}
	}
	defer clear(b)
	if status != 200 {
		return nil, mutationStatusError(status)
	}
	w, e := decodeSend(b)
	if e != nil || w.ID != id {
		return nil, &MutationUncertainError{Cause: ErrProtocol}
	}
	if _, e = decryptSendFields(w, seed); e != nil {
		return nil, &MutationUncertainError{Cause: e}
	}
	if ctx.Err() != nil {
		return nil, &MutationUncertainError{Cause: ErrCancelled}
	}
	lifetime, cancel := context.WithCancel(ctx)
	return &SendReceiver{ctx: lifetime, cancel: cancel, client: c, seed: append([]byte(nil), seed...), token: grant.Token, expires: expires, wire: w}, nil
}
func (r *SendReceiver) Close() {
	if r == nil {
		return
	}
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.seed)
	r.seed = nil
	r.token = ""
	r.wire = sendWire{}
	r.closed = true
}
func (r *SendReceiver) Fields() (SendFields, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil {
		return SendFields{}, ErrExpired
	}
	return decryptSendFields(r.wire, r.seed)
}

// SaveFile never retries access (which increments the server's access counter).
// A failed/uncertain access consumes this receiver's download action. The caller
// may explicitly reopen the link to request a fresh capability.
func (r *SendReceiver) SaveFile(ctx context.Context, path string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.ctx.Err() != nil || r.downloaded || time.Now().After(r.expires) {
		return ErrExpired
	}
	if r.wire.Type != 1 || r.wire.File == nil {
		return ErrValidation
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	size, e := strconv.ParseInt(r.wire.File.Size, 10, 64)
	if e != nil {
		return ErrProtocol
	}
	key, e := sendKey(r.seed)
	if e != nil {
		return e
	}
	defer clear(key)
	// Validate/pin the destination before consuming a download access.
	destination, e := newSendDestination(path)
	if e != nil {
		return e
	}
	defer destination.close()
	if ctx.Err() != nil {
		return ErrCancelled
	}
	r.downloaded = true
	status, b, e := r.client.sendRequest(ctx, "/api/sends/access/file/"+r.wire.File.ID, "", "", r.token)
	if e != nil {
		return &MutationUncertainError{Cause: e}
	}
	defer clear(b)
	if status != 200 {
		return mutationStatusError(status)
	}
	var download struct{ ID, URL string }
	if strictJSON(b) != nil || json.Unmarshal(b, &download) != nil || download.ID != r.wire.File.ID {
		return &MutationUncertainError{Cause: ErrProtocol}
	}
	spool, e := r.client.downloadAttachment(ctx, download.URL, size, key)
	if e != nil {
		return e
	}
	defer spool.Close()
	return destination.publish(ctx, spool.File, spool.Size, func() error {
		if r.closed || r.ctx.Err() != nil {
			return ErrExpired
		}
		return nil
	})
}
