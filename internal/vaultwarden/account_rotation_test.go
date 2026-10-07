// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

type accountTestAdapter func(context.Context, AccountRotationInput) (AccountRotationConversion, error)

func (f accountTestAdapter) Convert(ctx context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
	return f(ctx, in)
}
func accountEmptyRotation(_ context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
	return AccountRotationConversion{Revalidate: func(context.Context, func(context.Context, string) (json.RawMessage, error)) error { return nil }, Data: AccountRotationData{Ciphers: []json.RawMessage{}, Folders: []AccountRotationFolder{}, Sends: []json.RawMessage{}}, Emergency: []AccountRotationEmergency{}, Recovery: []AccountRotationRecovery{}, Coverage: AccountRotationCoverage{Scope: in.Scope, Revision: in.Revision, Epoch: in.Epoch, SnapshotHash: in.SnapshotHash, EmergencyComplete: true, RecoveryComplete: true}}, nil
}
func TestAccountRotationContractAndPartialRecovery(t *testing.T) {
	for _, scenario := range []string{"missing-adapter", "missing-coverage", "missing-revalidate", "recipient-change", "wrong-scope", "wrong-ID", "mutate-source", "storage-fail", "partial", "success"} {
		t.Run(scenario, func(t *testing.T) {
			writes := 0
			var saved []byte
			s, v := accountFixture(t, func(w http.ResponseWriter, r *http.Request, _ *Session, _ *VaultData) {
				writes++
				if len(saved) == 0 {
					t.Error("recovery missing")
				}
				if scenario == "partial" {
					w.WriteHeader(400)
				} else {
					w.WriteHeader(200)
				}
			})
			var adapter AccountRotationAdapter = accountTestAdapter(func(ctx context.Context, in AccountRotationInput) (AccountRotationConversion, error) {
				out, _ := accountEmptyRotation(ctx, in)
				switch scenario {
				case "missing-revalidate":
					out.Revalidate = nil
				case "recipient-change":
					out.Revalidate = func(context.Context, func(context.Context, string) (json.RawMessage, error)) error {
						return ErrConflict
					}
				case "missing-coverage":
					out.Coverage.EmergencyComplete = false
				case "wrong-scope":
					out.Coverage.Scope.Account = "other"
				case "wrong-ID":
					out.Data.Ciphers = []json.RawMessage{json.RawMessage(`{"id":"unexpected"}`)}
				case "mutate-source":
					in.Sync[0] = 'x'
				}
				return out, nil
			})
			if scenario == "missing-adapter" {
				adapter = nil
			}
			plan, err := s.PrepareAccountRotation(context.Background(), v, accountTestPassword, adapter, nil)
			if scenario != "partial" && scenario != "success" && scenario != "storage-fail" && scenario != "recipient-change" {
				if err == nil || writes != 0 {
					t.Fatal("unsafe adapter accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer plan.Close()
			if bytes.Equal(plan.recovery.NewUserKey, s.key) {
				t.Fatal("rotation reused old key")
			}
			result, err := s.CommitAccountChange(context.Background(), plan, string(AccountRotateKey), nil, func(r AccountRecovery) error {
				if scenario == "storage-fail" {
					return ErrCheckpoint
				}
				saved = mustAccountJSON(t, r)
				return nil
			})
			defer clear(saved)
			if scenario == "storage-fail" || scenario == "recipient-change" {
				if err == nil || writes != 0 {
					t.Fatal("write after persistence failure")
				}
				return
			}
			if writes != 1 || !result.Dispatched {
				t.Fatal("missing dispatch")
			}
			if scenario == "partial" {
				if err == nil || !result.Unknown {
					t.Fatal("nontransaction failure hidden")
				}
			} else if err != nil || !result.Confirmed {
				t.Fatal(err)
			}
			var rec AccountRecovery
			if json.Unmarshal(saved, &rec) != nil {
				t.Fatal("bad recovery")
			}
			defer rec.Close()
			var req AccountRotationRequest
			if json.Unmarshal(rec.Request, &req) != nil {
				t.Fatal("bad DTO")
			}
			old, err := RestoreSession(rec.OldSession, rec.Scope, &rec.OldUnlock.Config)
			if err != nil {
				t.Fatal(err)
			}
			defer old.Close()
			var sync struct {
				Profile struct {
					PrivateKey string `json:"privateKey"`
				}
			}
			var vault VaultData
			_ = json.Unmarshal(rec.OldVault, &vault)
			_ = json.Unmarshal(vault.Sync, &sync)
			oldDER, err := DecryptString(sync.Profile.PrivateKey, old.key)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(oldDER)
			newDER, err := DecryptString(req.Keys.PrivateKey, rec.NewUserKey)
			if err != nil || !bytes.Equal(newDER, oldDER) {
				t.Fatal("RSA pair not preserved")
			}
			defer clear(newDER)
		})
	}
}
func TestAccountRotationHelpersPreserveOpaqueAndValidateCoverage(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 64)
	newKey := bytes.Repeat([]byte{2}, 64)
	for _, size := range []int{16, 64} {
		key := bytes.Repeat([]byte{3}, size)
		wrapped, _ := EncryptString(key, oldKey)
		raw := json.RawMessage(`{"id":"row","key":` + string(mustAccountJSON(t, wrapped)) + `,"unknown":{"huge":9007199254740993123,"nested":"opaque"}}`)
		got, err := AccountRewrapRotationObject(raw, oldKey, newKey, size)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(got, []byte("9007199254740993123")) {
			t.Fatal("lost integer")
		}
		var object map[string]json.RawMessage
		_ = json.Unmarshal(got, &object)
		var keyString string
		_ = json.Unmarshal(object["key"], &keyString)
		decoded, err := DecryptString(keyString, newKey)
		if err != nil || !bytes.Equal(decoded, key) {
			t.Fatal("bad key rewrap")
		}
		clear(decoded)
	}
	if _, err := AccountRewrapRotationObject(json.RawMessage(`{"id":"legacy","name":"ciphertext"}`), oldKey, newKey, 64); err == nil {
		t.Fatal("legacy silently converted")
	}
	if _, err := AccountRewrapRotationObject(json.RawMessage(`{"key":"x","key":"y"}`), oldKey, newKey, 64); err == nil {
		t.Fatal("duplicate JSON accepted")
	}
	encrypted, _ := EncryptString([]byte("folder name"), oldKey)
	folder, err := AccountRewrapRotationFolder(AccountRotationFolder{ID: "folder", Name: encrypted}, oldKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := DecryptString(folder.Name, newKey)
	defer clear(plain)
	if string(plain) != "folder name" {
		t.Fatal("bad folder")
	}
	if accountExactIDs([]string{"a", "b"}, []string{"a", "a"}) == nil || accountExactIDs([]string{"a"}, nil) == nil {
		t.Fatal("incomplete IDs accepted")
	}
}
