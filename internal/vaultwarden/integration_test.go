// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func fixtureTOTP(secret []byte, at time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}
func TestLiveVaultwarden(t *testing.T) {
	server := os.Getenv("MYGO_VW_TEST_URL")
	if server == "" {
		t.Skip("set MYGO_VW_TEST_URL to an isolated loopback Vaultwarden fixture")
	}
	if !strings.HasPrefix(server, "http://127.0.0.1:") {
		t.Fatal("integration fixture refuses non-loopback servers")
	}
	for _, tc := range []struct {
		name string
		kdf  KDF
		mfa  bool
	}{
		{"pbkdf2", KDF{Type: 0, Iterations: 600000}, false},
		{"argon2id", KDF{Type: 1, Iterations: 3, Memory: 64, Parallelism: 4}, false},
		{"totp", KDF{Type: 0, Iterations: 600000}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(server, fixtureUUID())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			email := "mygo-" + tc.name + "-" + strings.ReplaceAll(fixtureUUID(), "-", "") + "@example.invalid"
			password := []byte("Public-phase3-fixture-password!")
			master, err := DeriveMaster(password, email, tc.kdf)
			if err != nil {
				t.Fatal(err)
			}
			stretched, _ := StretchMaster(master)
			defer clear(master)
			defer clear(stretched)
			key := make([]byte, 64)
			_, _ = rand.Read(key)
			defer clear(key)
			hash := AuthorizationHash(master, password)
			private, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			privateDER, _ := x509.MarshalPKCS8PrivateKey(private)
			publicDER, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
			registration := map[string]any{"email": email, "name": "MyGo isolated test", "masterPasswordHash": hash, "key": encryptFixture(key, stretched), "kdf": tc.kdf.Type, "kdfIterations": tc.kdf.Iterations,
				"keys": map[string]string{"publicKey": base64.StdEncoding.EncodeToString(publicDER), "encryptedPrivateKey": encryptFixture(privateDER, key)}}
			if tc.kdf.Type == 1 {
				registration["kdfMemory"] = tc.kdf.Memory
				registration["kdfParallelism"] = tc.kdf.Parallelism
			}
			post := func(endpoint string, body any, token string) []byte {
				encoded, _ := json.Marshal(body)
				status, data, err := client.request(ctx, "POST", endpoint, "application/json", string(encoded), token)
				if err != nil || status < 200 || status >= 300 {
					t.Fatalf("fixture endpoint %s: status=%d error=%v", endpoint, status, err)
				}
				return data
			}
			verification := post("/identity/accounts/register/send-verification-email", map[string]string{"email": email, "name": "MyGo isolated test"}, "")
			var registrationToken string
			if json.Unmarshal(verification, &registrationToken) != nil || registrationToken == "" {
				t.Fatal("fixture registration token missing")
			}
			registration["emailVerificationToken"] = registrationToken
			post("/identity/accounts/register/finish", registration, "")
			session, err := client.Login(ctx, email, password, nil)
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			defer session.Close()
			empty, err := session.Sync(ctx)
			if err != nil {
				t.Fatalf("empty sync: %v", err)
			}
			fixture := map[string]string{"username": "demo@mygo.invalid", "password": "MyGo-Demo-Only-2026!"}
			for i := 0; i < 2; i++ {
				itemKey := key
				var wrapped any
				if i == 1 {
					itemKey = make([]byte, 64)
					_, _ = rand.Read(itemKey)
					defer clear(itemKey)
					wrapped = encryptFixture(itemKey, key)
				}
				body := map[string]any{"type": 1, "encryptedFor": empty.Scope.Account, "organizationId": nil, "key": wrapped, "name": encryptFixture([]byte(fmt.Sprintf("MyGo %s fixture %d", tc.name, i)), itemKey), "reprompt": 0, "favorite": false,
					"login": map[string]any{"username": encryptFixture([]byte(fixture["username"]), itemKey), "password": encryptFixture([]byte(fixture["password"]), itemKey), "uris": []any{map[string]any{"uri": encryptFixture([]byte("http://localhost:18472/"), itemKey), "match": 0}}}}
				post("/api/ciphers", body, session.access)
			}
			if tc.mfa {
				secret := make([]byte, 20)
				_, _ = rand.Read(secret)
				post("/api/two-factor/authenticator", map[string]any{"key": base32.StdEncoding.EncodeToString(secret), "token": fixtureTOTP(secret, time.Now().Add(-30*time.Second)), "masterPasswordHash": hash}, session.access)
				session.Close()
				if _, err := client.Login(ctx, email, password, nil); err != ErrMFA {
					t.Fatalf("expected MFA challenge, got %v", err)
				}
				session, err = client.Login(ctx, email, password, func() ([]byte, error) { return []byte(fixtureTOTP(secret, time.Now())), nil })
				if err != nil {
					t.Fatalf("TOTP login: %v", err)
				}
				defer session.Close()
			}
			result, err := session.Sync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if result.Scope.Server != server || result.Scope.Account != empty.Scope.Account || len(result.Credentials) != 2 {
				t.Fatal("scope or cipher count mismatch")
			}
			for _, item := range result.Credentials {
				if item.Username != fixture["username"] || item.Password != fixture["password"] || len(item.URIs) != 1 {
					t.Fatal("server roundtrip did not decrypt expected fixture")
				}
			}
			if tc.name == "pbkdf2" {
				testLiveCipherComparison(t, ctx, session, result.Scope)
				testLiveProtectedItem(t, ctx, session, result.Scope, password)
				testLiveBackups(t, ctx, session, result.Scope, email, password)
				testLiveFoldersAndBulk(t, ctx, session, result.Scope)
				for kind := 1; kind <= 8; kind++ {
					created, err := session.CreatePersonalCipher(ctx, result.Scope, CipherFields{Type: kind, Name: fmt.Sprintf("Writable type %d", kind), Login: map[string]any{"password": "initial fixture password"}, Fields: []map[string]any{{"name": "fixture custom", "value": "initial custom value", "type": 0}}, SSHKey: map[string]any{"privateKey": "fixture private", "publicKey": "fixture public", "keyFingerprint": "fixture fingerprint"}}, nil)
					if err != nil {
						t.Fatalf("create type %d: %v", kind, err)
					}
					fields, err := DecryptCipherDocument(created, key)
					if err != nil {
						t.Fatal(err)
					}
					fields.Name = "Updated " + fields.Name
					fields.Fields[0]["value"] = "updated custom value"
					fields.Fields = append(fields.Fields, map[string]any{"name": "fixture boolean", "value": "true", "type": json.Number("2")})
					if kind == 1 {
						fields.Fields = append(fields.Fields, map[string]any{"name": "fixture linked", "value": nil, "type": json.Number("3"), "linkedId": json.Number("101")})
						fields.Login["password"] = "updated fixture password"
						fields.Login["uris"] = []any{map[string]any{"uri": "https://example.invalid/", "match": 0}}
					}
					updated, err := session.UpdatePersonalCipher(ctx, result.Scope, created, fields, nil)
					if err != nil {
						t.Fatalf("update type %d: %v", kind, err)
					}
					verified, err := DecryptCipherDocument(updated, key)
					if err != nil || verified.Name != fields.Name {
						t.Fatalf("verify type %d: %v", kind, err)
					}
					if verified.Fields[0]["value"] != "updated custom value" {
						t.Fatal("custom field update lost")
					}
					if verified.Fields[1]["value"] != "true" || verified.Fields[1]["type"] != json.Number("2") {
						t.Fatal("boolean custom field lost")
					}
					if kind == 1 && (verified.Fields[2]["linkedId"] != json.Number("101") || verified.Fields[2]["value"] != nil) {
						t.Fatal("linked field lost")
					}
					if kind == 1 && (len(verified.PasswordHistory) != 1 || verified.PasswordHistory[0]["password"] != "initial fixture password" || verified.Login["uris"].([]any)[0].(map[string]any)["uriChecksum"] == nil) {
						t.Fatal("password history or URI checksum lost")
					}
					copied, err := session.CopyPersonalCipher(ctx, result.Scope, updated, verified, nil)
					if err != nil {
						t.Fatalf("copy type %d: %v", kind, err)
					}
					copyFields, err := DecryptCipherDocument(copied, key)
					if err != nil || copyFields.ID == verified.ID || copyFields.Name != verified.Name || len(copyFields.PasswordHistory) != len(verified.PasswordHistory) {
						t.Fatalf("copy roundtrip type %d: %v", kind, err)
					}
					if kind == 1 && (copyFields.PasswordHistory[0]["password"] != "initial fixture password" || copyFields.Login["uris"].([]any)[0].(map[string]any)["uriChecksum"] == nil) {
						t.Fatal("copy lost history/checksum")
					}
					if kind == 1 {
						verified.PasswordHistory = nil
						withoutHistory, err := session.UpdatePersonalCipher(ctx, result.Scope, updated, verified, nil)
						if err != nil {
							t.Fatal("delete password history", err)
						}
						cleared, err := DecryptCipherDocument(withoutHistory, key)
						if err != nil || len(cleared.PasswordHistory) != 0 || cleared.Login["password"] != "updated fixture password" {
							t.Fatal("history deletion damaged current password", err)
						}
					}
					if err := session.ChangeCipherState(ctx, result.Scope, copyFields.ID, CipherDeletePermanently, nil); err != nil {
						t.Fatal(err)
					}
					for _, action := range []CipherAction{CipherArchive, CipherUnarchive, CipherTrash, CipherRestore, CipherDeletePermanently} {
						if err := session.ChangeCipherState(ctx, result.Scope, fields.ID, action, nil); err != nil {
							t.Fatalf("state type %d %s: %v", kind, action, err)
						}
						if kind == 1 && action == CipherArchive {
							snapshot, err := session.Sync(ctx)
							if err != nil {
								t.Fatal(err)
							}
							for _, credential := range snapshot.Credentials {
								if credential.ID == fields.ID {
									t.Fatal("archived cipher entered AutoFill")
								}
							}
						}
					}
				}
			}
			// Force token refresh and acknowledge its persistence in this isolated
			// fixture; application persistence is covered by the Swift store tests.
			session.expires = time.Now().Add(-time.Minute)
			if _, err := session.SyncWithCheckpoint(ctx, func(SessionCheckpoint) error { return nil }); err != nil {
				t.Fatalf("refresh/sync: %v", err)
			}
			if dir := os.Getenv("MYGO_VW_FIXTURE_DIR"); dir != "" && !tc.mfa {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				blob, _ := json.Marshal(map[string]any{"server": server, "email": email, "password": string(password), "expectedUsername": fixture["username"], "expectedPassword": fixture["password"], "account": result.Scope.Account, "kdf": tc.kdf})
				if err := os.WriteFile(filepath.Join(dir, tc.name+".json"), blob, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
