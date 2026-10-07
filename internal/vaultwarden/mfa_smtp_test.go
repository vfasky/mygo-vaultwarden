// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func mfaMailText(header mail.Header, reader io.Reader) string {
	media, params, _ := mime.ParseMediaType(header.Get("Content-Type"))
	if strings.HasPrefix(media, "multipart/") {
		parts := multipart.NewReader(reader, params["boundary"])
		var text string
		for {
			part, e := parts.NextPart()
			if e != nil {
				break
			}
			text += mfaMailText(mail.Header(part.Header), part)
		}
		return text
	}
	switch strings.ToLower(header.Get("Content-Transfer-Encoding")) {
	case "quoted-printable":
		reader = quotedprintable.NewReader(reader)
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, reader)
	}
	b, _ := io.ReadAll(io.LimitReader(reader, 1<<20))
	return string(b)
}
func mfaReadMail(t *testing.T, dir, email, pattern string) string {
	t.Helper()
	re := regexp.MustCompile(pattern)
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var message struct {
			Recipients []string
			Data       string
		}
		if json.Unmarshal(b, &message) != nil {
			continue
		}
		found := false
		for _, recipient := range message.Recipients {
			if recipient == email {
				found = true
			}
		}
		if !found {
			continue
		}
		parsed, e := mail.ReadMessage(strings.NewReader(message.Data))
		if e != nil {
			continue
		}
		text := mfaMailText(parsed.Header, parsed.Body)
		match := re.FindStringSubmatch(text)
		if len(match) > 1 {
			os.Remove(path)
			return match[1]
		}
	}
	t.Fatal("expected fixture email not found (contents withheld)")
	return ""
}
func TestLiveMFAEmail(t *testing.T) {
	server, spool := os.Getenv("MYGO_MFA_SMTP_URL"), os.Getenv("MYGO_MFA_SMTP_SPOOL")
	if server == "" || spool == "" {
		t.Skip("requires isolated SMTP fixture")
	}
	if !strings.HasPrefix(server, "http://127.0.0.1:") {
		t.Fatal("nonloopback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c, _ := NewClient(server, fixtureUUID())
	email := "smtp-" + fixtureUUID() + "@example.invalid"
	password := []byte("SMTP-test-passphrase-294-X!")
	defer clear(password)
	verification, e := c.AccountSendRegistrationEmail(ctx, email, "")
	if e != nil {
		t.Fatal(e)
	}
	token := verification.Token
	if verification.EmailSent {
		token = mfaReadMail(t, spool, email, `[?&]token=([A-Za-z0-9._~-]+)`)
	}
	if e = c.AccountRegister(ctx, email, password, KDF{Type: 0, Iterations: 100000}, "", token); e != nil {
		t.Fatal("registration", e)
	}
	s, e := c.Login(ctx, email, password, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	proof := AccountSensitiveInput{Password: password}
	persist := func(SessionCheckpoint) error { return nil }
	if _, e = s.MFAManage(ctx, "send-email", proof, map[string]json.RawMessage{"email": mfaJSON(email)}, true, persist); e != nil {
		t.Fatal("send setup", e)
	}
	otp := mfaReadMail(t, spool, email, `verification code is: (\d{6})`)
	if _, e = s.MFAManage(ctx, "email", proof, map[string]json.RawMessage{"email": mfaJSON(email), "token": mfaJSON(otp)}, true, persist); e != nil {
		t.Fatal("enable email", e)
	}
	result, e := c.LoginMFA(ctx, email, password, "", func(ctx context.Context, ch MFAChallenge) (MFAResponse, error) {
		if e := ch.SendEmail(ctx); e != nil {
			return MFAResponse{}, e
		}
		otp := mfaReadMail(t, spool, email, `verification code is: (\d{6})`)
		return MFAResponse{Provider: 1, Token: []byte(otp)}, nil
	})
	if e != nil {
		t.Fatal("email login", e)
	}
	result.Session.Close()
	if _, e = s.MFAManage(ctx, MFARequestOTP, AccountSensitiveInput{}, nil, false, persist); e != nil {
		t.Fatal("protected OTP", e)
	}
	protected := mfaReadMail(t, spool, email, `(?i)(?:code is:|code:)\s*(\d{6})`)
	if _, e = s.MFAManage(ctx, "get-email", AccountSensitiveInput{OTP: protected}, nil, false, persist); e != nil {
		t.Fatal("protected proof", e)
	}
}
