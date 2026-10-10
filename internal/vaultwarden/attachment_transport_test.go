// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAttachmentSignedDownloadNoCredentialsOrRedirect(t *testing.T) {
	key, encrypted, expected := officialAttachmentVector(t)
	var forwarded atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(500) }))
	defer destination.Close()
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		for _, header := range []string{"Authorization", "Cookie", "Referer", "Device-Type", "Bitwarden-Client-Name"} {
			if r.Header.Get(header) != "" {
				t.Errorf("leaked %s", header)
			}
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, destination.URL, 302)
			return
		}
		if r.URL.RawQuery != "signature=private%2Bsignature" {
			t.Error("signed query modified")
		}
		w.Write(encrypted)
	}))
	defer server.Close()
	client, err := NewClient("https://vault.example.invalid/vault", "attachment-test-device")
	if err != nil {
		t.Fatal(err)
	}
	client.http = server.Client()
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(server.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "account", Value: "secret"}})
	client.http.Jar = jar
	plain, err := client.downloadAttachment(context.Background(), server.URL+"/attachments/file?signature=private%2Bsignature", int64(len(encrypted)), key)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	actual, _ := io.ReadAll(plain.File)
	if !bytes.Equal(actual, expected) {
		t.Fatal("download mismatch")
	}
	output, err := client.downloadAttachment(context.Background(), server.URL+"/redirect", int64(len(encrypted)), key)
	if err == nil || output != nil || forwarded.Load() != 0 || hits.Load() != 2 {
		t.Fatal("redirect followed/accepted")
	}
}
func TestAttachmentDownloadURLValidation(t *testing.T) {
	client, _ := NewClient("http://127.0.0.1:1234/vault", "attachment-test-device")
	for _, raw := range []string{"/relative", "//other.test/path", "file:///etc/passwd", "https://user:example@other.test/file", "https://other.test/file#secret", "http://127.0.0.1:5678/file", "http://localhost:1234/file", "http://other.test/file", "https://other.test/a/../b", "https://other.test/%2e%2e/b", "https://other.test/a%5cb", "https://other.test/a%00b", "https://other.test/file?bad=%xx", " https://other.test/file", strings.Repeat("x", 16385)} {
		if _, err := client.attachmentDownloadURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"https://other.test/bucket/file%20name?sig=a%2Fb%3D", "http://127.0.0.1:1234/vault/attachments/id?token=test"} {
		if _, err := client.attachmentDownloadURL(raw); err != nil {
			t.Errorf("rejected valid signed URL: %v", err)
		}
	}
}
func TestAttachmentDownloadResponseBounds(t *testing.T) {
	key, encrypted, _ := officialAttachmentVector(t)
	for _, mode := range []string{"short", "long", "chunked-long", "encoding", "status", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "short":
					w.Write(encrypted[:len(encrypted)-1])
				case "long":
					w.Write(append(bytes.Clone(encrypted), 0))
				case "chunked-long":
					w.(http.Flusher).Flush()
					w.Write(append(bytes.Clone(encrypted), 0))
				case "encoding":
					w.Header().Set("Content-Encoding", "gzip")
					w.Write(encrypted)
				case "status":
					w.WriteHeader(403)
				case "corrupt":
					b := bytes.Clone(encrypted)
					b[17] ^= 1
					w.Write(b)
				}
			}))
			defer server.Close()
			client, _ := NewClient(server.URL, "attachment-test-device")
			spool, err := client.downloadAttachment(context.Background(), server.URL+"/file?secret=signed-token", int64(len(encrypted)), key)
			if err == nil || spool != nil {
				t.Fatal("accepted invalid response")
			}
			if strings.Contains(err.Error(), "signed-token") {
				t.Fatal("URL leaked in error")
			}
		})
	}
}
func TestAttachmentMultipartDirectUpload(t *testing.T) {
	key, _, _ := officialAttachmentVector(t)
	input := bytes.Repeat([]byte{0x80, 0xff, 0, 1}, 2*1024*1024)
	encrypted, err := vaultcrypto.EncryptAttachment(context.Background(), bytes.NewReader(input), int64(len(input)), key)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Close()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/vault/api/ciphers/cipher-id/attachment/attachment-id" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Cookie") != "" {
			t.Error("invalid direct upload")
		}
		reader, err := r.MultipartReader()
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		part, err := reader.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		if part.FormName() != "data" || part.FileName() != "attachment.bin" {
			t.Error("metadata leaked or wrong form")
		}
		plain, err := vaultcrypto.DecryptAttachment(r.Context(), part, encrypted.Size, key)
		if err != nil {
			t.Error(err)
			return
		}
		defer plain.Close()
		actual, _ := io.ReadAll(plain.File)
		if !bytes.Equal(actual, input) {
			t.Error("multipart content mismatch")
		}
		if _, err = reader.NextPart(); err != io.EOF {
			t.Error("unexpected extra form field")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	client, _ := NewClient(server.URL+"/vault", "attachment-test-device")
	status, err := client.uploadAttachment(context.Background(), "cipher-id", "attachment-id", "test-token", encrypted)
	if err != nil || status != 200 || hits.Load() != 1 {
		t.Fatalf("upload: %d %v", status, err)
	}
	for _, id := range []string{"../other", "bad/id", "bad?query", "bad%2fid", "bad\\id"} {
		if _, err = client.uploadAttachment(context.Background(), "cipher-id", id, "test-token", encrypted); err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	if hits.Load() != 1 {
		t.Fatal("invalid ID sent")
	}
}
func TestAttachmentUploadRedirectNotRetried(t *testing.T) {
	key, _, _ := officialAttachmentVector(t)
	encrypted, err := vaultcrypto.EncryptAttachment(context.Background(), bytes.NewReader(nil), 0, key)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Close()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); http.Redirect(w, r, "/other", 307) }))
	defer server.Close()
	client, _ := NewClient(server.URL, "attachment-test-device")
	status, err := client.uploadAttachment(context.Background(), "cipher", "attachment", "test-token", encrypted)
	if status != 307 || err == nil || hits.Load() != 1 {
		t.Fatalf("redirect/retry: %d %v %d", status, err, hits.Load())
	}
}
