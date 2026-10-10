// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendPasswordIndependentVector(t *testing.T) {
	seed := make([]byte, 16)
	for i := range seed {
		seed[i] = byte(i)
	}
	if sendPassword("send password 密码", seed) != "WKnBLLa5fnk8R90QegjI0JeljVp/0cTGsnRkaLai270=" {
		t.Fatal("Python hashlib PBKDF2-SHA256 independent vector")
	}
}
func TestSendReceiverFileIsolationAndPublication(t *testing.T) {
	for _, mode := range []string{"success", "mac", "oversize", "redirect", "wrong-id", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			seed := bytes.Repeat([]byte{9}, 16)
			key, _ := sendKey(seed)
			content := bytes.Repeat([]byte("private bytes"), 12345)
			encrypted, e := vaultcrypto.EncryptAttachment(context.Background(), bytes.NewReader(content), int64(len(content)), key)
			if e != nil {
				t.Fatal(e)
			}
			defer encrypted.Close()
			ciphertext, _ := io.ReadAll(encrypted.File)
			var signedRequests atomic.Int32
			foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				signedRequests.Add(1)
				for _, h := range []string{"Authorization", "Cookie", "Referer", "Device-Type"} {
					if r.Header.Get(h) != "" {
						t.Errorf("leaked header %s", h)
					}
				}
				if r.URL.RawQuery != "signature=public%2Bcap" {
					t.Error("signature rewritten")
				}
				switch mode {
				case "redirect":
					w.Header().Set("Location", "/leak")
					w.WriteHeader(307)
					return
				case "mac":
					b := bytes.Clone(ciphertext)
					b[17] ^= 1
					w.Write(b)
					return
				case "oversize":
					w.Write(append(ciphertext, 0))
					return
				}
				w.Write(ciphertext)
			}))
			defer foreign.Close()
			w, _ := encryptSend(SendFields{Name: "received", Type: 1, FileName: "file.bin", DeletionDate: time.Now().Add(time.Hour)}, seed, bytes.Repeat([]byte{4}, 64))
			w.File.ID = "file-id"
			w.File.Size = sendSize(int64(len(ciphertext)))
			w.ID = sendAccessID("b6d98b09-e6b1-42b0-93f1-d7f77aab9543")
			w.Notes = nil
			var downloads atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Cookie") != "" {
					t.Error("ambient owner cookie")
				}
				switch r.URL.Path {
				case "/identity/connect/token":
					if r.Header.Get("Authorization") != "" {
						t.Error("owner token in grant")
					}
					r.ParseForm()
					if r.Form.Get("grant_type") != "send_access" || r.Form.Get("send_id") != w.ID || r.Form.Get("password_hash_b64") != sendPassword("pass", seed) || strings.Contains(r.Form.Encode(), base64.RawURLEncoding.EncodeToString(seed)) {
						t.Error("grant fields")
					}
					json.NewEncoder(out).Encode(map[string]any{"access_token": "receiver-only-token", "expires_in": 120, "token_type": "Bearer", "scope": "api.send.access"})
				case "/api/sends/access":
					if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer receiver-only-token" {
						t.Error("receiver access")
					}
					json.NewEncoder(out).Encode(w)
				case "/api/sends/access/file/file-id":
					downloads.Add(1)
					id := w.File.ID
					if mode == "wrong-id" {
						id = "other"
					}
					json.NewEncoder(out).Encode(map[string]string{"id": id, "url": foreign.URL + "/file?signature=public%2Bcap"})
				default:
					t.Error("wrong route")
					out.WriteHeader(404)
				}
			}))
			defer srv.Close()
			c, _ := NewClient(srv.URL, fixtureUUID())
			c.http = foreign.Client()
			jar, _ := cookiejar.New(nil)
			jar.SetCookies(c.base, []*http.Cookie{{Name: "owner", Value: "secret"}})
			c.http.Jar = jar
			link := srv.URL + "/#/send/" + w.ID + "/" + base64.RawURLEncoding.EncodeToString(seed)
			receiver, e := c.OpenSend(context.Background(), link, "pass")
			if e != nil {
				t.Fatal(e)
			}
			defer receiver.Close()
			dir, _ := filepath.EvalSymlinks(t.TempDir())
			target := filepath.Join(dir, "saved")
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "cancel" {
				cancel()
			}
			defer cancel()
			e = receiver.SaveFile(ctx, target)
			if mode == "success" {
				if e != nil {
					t.Fatal(e)
				}
				actual, _ := os.ReadFile(target)
				info, _ := os.Stat(target)
				if !bytes.Equal(actual, content) || info.Mode().Perm() != 0600 {
					t.Fatal("published bytes/mode")
				}
			} else {
				if e == nil {
					t.Fatal("invalid transfer published")
				}
				if _, e = os.Stat(target); !os.IsNotExist(e) {
					t.Fatal("failed transfer exposed plaintext")
				}
			}
			entries, _ := os.ReadDir(dir)
			if mode != "success" && len(entries) != 0 {
				t.Fatal("temporary leaked")
			}
			if downloads.Load() > 1 || signedRequests.Load() > 1 {
				t.Fatal("retry or redirect")
			}
			if mode != "cancel" {
				if e = receiver.SaveFile(context.Background(), filepath.Join(dir, "again")); !errors.Is(e, ErrExpired) {
					t.Fatal("access retry allowed", e)
				}
			}
		})
	}
}
func TestSendFileSourceAndPublicationGuards(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	source := filepath.Join(dir, "source")
	os.WriteFile(source, []byte("hello"), 0600)
	r, n, name, e := OpenSendSource(source)
	if e != nil || n != 5 || name != "source" {
		t.Fatal(e)
	}
	r.Close()
	os.Symlink(source, filepath.Join(dir, "symlink"))
	if _, _, _, e = OpenSendSource(filepath.Join(dir, "symlink")); e == nil {
		t.Fatal("source symlink")
	}
	os.Mkdir(filepath.Join(dir, "sub"), 0700)
	os.Symlink(filepath.Join(dir, "sub"), filepath.Join(dir, "alias"))
	if _, e = newSendDestination(filepath.Join(dir, "alias", "saved")); e == nil {
		t.Fatal("parent symlink")
	}
	if _, e = newSendDestination(source); !errors.Is(e, ErrConflict) {
		t.Fatal("existing target")
	}
	target := filepath.Join(dir, "saved")
	d, e := newSendDestination(target)
	if e != nil {
		t.Fatal(e)
	}
	e = d.publish(context.Background(), strings.NewReader("secret"), 6, func() error { return ErrExpired })
	d.close()
	if !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	if _, e = os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("guard published")
	}
	d, e = newSendDestination(target)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(target, []byte("prior"), 0600)
	e = d.publish(context.Background(), strings.NewReader("secret"), 6, func() error { return nil })
	d.close()
	if !errors.Is(e, ErrConflict) {
		t.Fatal("no replace race", e)
	}
	b, _ := os.ReadFile(target)
	if string(b) != "prior" {
		t.Fatal("overwrote target")
	}
}
func TestSendUploadPartialFailureAndMultipart(t *testing.T) {
	for _, status := range []int{200, 401, 500, 307} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var saved sendWire
			var uploads atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/sync":
					json.NewEncoder(w).Encode(emptyPolicySyncFixture())
				case r.URL.Path == "/api/sends/file/v2":
					if json.NewDecoder(r.Body).Decode(&saved) != nil {
						t.Error("metadata")
					}
					saved = sendTestReply(saved)
					saved.File.ID = "file-id"
					saved.File.Size = sendSize(*saved.FileLength)
					saved.FileLength = nil
					json.NewEncoder(w).Encode(map[string]any{"fileUploadType": 0, "url": "/sends/" + saved.ID + "/file/file-id", "sendResponse": saved})
				case r.URL.Path == "/api/sends/"+saved.ID+"/file/file-id":
					uploads.Add(1)
					if r.Header.Get("Authorization") != "Bearer access-not-persisted" {
						t.Error("upload auth")
					}
					m, e := r.MultipartReader()
					if e != nil {
						t.Error(e)
						return
					}
					part, e := m.NextPart()
					if e != nil {
						t.Error(e)
						return
					}
					_, params, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
					if part.FormName() != "data" || params["filename"] != saved.File.FileName {
						t.Error("encrypted multipart filename")
					}
					b, _ := io.ReadAll(part)
					if len(b) != 65 || b[0] != 2 {
						t.Error("binary size")
					}
					w.Header().Set("Location", "/must-not-follow")
					w.WriteHeader(status)
				default:
					t.Error("unexpected route")
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			s, _ := resumableFixture(t, srv.URL)
			defer s.Close()
			v := sendTestVault(t, s)
			d, e := s.NewSend(v, 1)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			d.Fields = sendTestFields()
			d.Fields.Type = 1
			d.Fields.FileName = "secret-file"
			next, e := s.SaveSend(context.Background(), d, strings.NewReader("abc"), 3, nil)
			if status == 200 {
				if e != nil {
					t.Fatal(e)
				}
				next.Close()
			} else {
				var partial *SendUploadError
				if next != nil || !errors.As(e, &partial) || partial.ID != saved.ID {
					t.Fatal("partial incorrectly succeeded", e)
				}
			}
			if uploads.Load() != 1 {
				t.Fatal("upload retry")
			}
			if _, e = s.SaveSend(context.Background(), d, strings.NewReader("abc"), 3, nil); !errors.Is(e, ErrExpired) {
				t.Fatal("partial retry", e)
			}
		})
	}
}
