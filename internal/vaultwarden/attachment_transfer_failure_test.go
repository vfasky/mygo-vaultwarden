// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAttachmentDownloadCancellationRemovesPrivateSpool(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("TMPDIR", directory)
	key, encrypted, _ := officialAttachmentVector(t)
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(encrypted[:65])
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	client, _ := NewClient(server.URL, "attachment-test-device")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		spool, err := client.downloadAttachment(ctx, server.URL+"/file", int64(len(encrypted)), key)
		if spool != nil {
			spool.close()
			result <- errors.New("cancelled download returned plaintext")
			return
		}
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("spool leak: %v %v", entries, err)
	}
}

func TestAttachmentUploadFailureDoesNotRetryOrDelete(t *testing.T) {
	key, _, _ := officialAttachmentVector(t)
	encrypted, err := encryptAttachment(context.Background(), bytes.NewReader([]byte("test")), 4, key)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.close()
	for _, mode := range []string{"unauthorized", "server-error", "oversized-response", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Method != "POST" {
					t.Error("unexpected compensation")
				}
				switch mode {
				case "unauthorized":
					w.WriteHeader(401)
				case "server-error":
					w.WriteHeader(500)
				case "oversized-response":
					w.Write([]byte(strings.Repeat("secret", 12000)))
				case "disconnect":
					conn, _, e := w.(http.Hijacker).Hijack()
					if e != nil {
						t.Error(e)
						return
					}
					conn.Close()
				}
			}))
			defer server.Close()
			client, _ := NewClient(server.URL, "attachment-test-device")
			status, err := client.uploadAttachment(context.Background(), "cipher", "attachment", "test-token", encrypted)
			if hits.Load() != 1 {
				t.Fatal("request retried or deleted")
			}
			switch mode {
			case "unauthorized":
				if status != 401 || err != nil {
					t.Fatalf("status: %d %v", status, err)
				}
			case "server-error":
				if status != 500 || err != nil {
					t.Fatalf("status: %d %v", status, err)
				}
			default:
				if err == nil || strings.Contains(err.Error(), "secret") {
					t.Fatalf("unsanitized or missing error: %v", err)
				}
			}
		})
	}
}
