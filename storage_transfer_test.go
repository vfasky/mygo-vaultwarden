// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestStorageTransferLargeAndFailures(t *testing.T) {
	input := []byte(`{"operation":"publishVault","padding":"` + strings.Repeat("x", 5*1024*1024) + `"}`)
	output := []byte(`{"ok":true,"padding":"` + strings.Repeat("y", 5*1024*1024) + `"}`)
	for _, mode := range []string{"ok", "appendFailure", "shortPage", "badDigest", "hugeReply"} {
		t.Run(mode, func(t *testing.T) {
			var uploaded []byte
			cancelled := false
			offset := 0
			call := func(raw []byte) ([]byte, error) {
				if len(raw) > 512*1024 {
					t.Fatalf("unbounded frame %d", len(raw))
				}
				var frame storageTransferFrame
				if err := json.Unmarshal(raw, &frame); err != nil {
					t.Fatal(err)
				}
				reply := storageTransferReply{OK: true}
				switch frame.Action {
				case "begin":
					reply.Handle = "test-handle"
					if frame.Total != len(input) {
						t.Fatal("bad length")
					}
				case "append":
					if mode == "appendFailure" {
						return nil, errors.New("injected")
					}
					if frame.Offset != len(uploaded) || len(frame.Data) > storageChunkBytes {
						t.Fatal("bad upload order")
					}
					uploaded = append(uploaded, frame.Data...)
				case "finish":
					if string(uploaded) != string(input) {
						t.Fatal("changed request")
					}
					sum := sha256.Sum256(output)
					reply.Digest = hex.EncodeToString(sum[:])
					reply.Total = len(output)
					if mode == "badDigest" {
						reply.Digest = strings.Repeat("0", 64)
					}
					if mode == "hugeReply" {
						reply.Total = storageTransferBytes + 1
					}
				case "read":
					if frame.Offset != offset {
						t.Fatal("bad read order")
					}
					end := min(offset+storageChunkBytes, len(output))
					reply.Data = output[offset:end]
					offset = end
					if mode == "shortPage" {
						reply.Data = reply.Data[:1]
					}
				case "cancel":
					cancelled = true
				default:
					t.Fatal("unknown transfer action")
				}
				return json.Marshal(reply)
			}
			got, err := boundedStorageCall(input, call)
			if mode == "ok" {
				if err != nil || string(got) != string(output) {
					t.Fatalf("round trip: %v", err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid transfer")
			}
			if !cancelled {
				t.Fatal("transfer not cleaned up")
			}
		})
	}
}

func TestStorageTransferControlBypassesBusyTransport(t *testing.T) {
	storageTransferMutex.Lock()
	defer storageTransferMutex.Unlock()
	for _, op := range []string{"lock", "logout", "status", "copySecret"} {
		input := []byte(`{"operation":"` + op + `"}`)
		_, err := boundedStorageCall(input, func(raw []byte) ([]byte, error) {
			if string(raw) != string(input) {
				t.Fatal("changed control")
			}
			return []byte(`{"ok":true}`), nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
