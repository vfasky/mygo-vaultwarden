// SPDX-License-Identifier: GPL-3.0-only
package localstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
)

const storageChunkBytes = 256 * 1024
const storageTransferBytes = 64 * 1024 * 1024

var storageTransferMutex sync.Mutex

type storageTransferFrame struct {
	Operation string `json:"operation"`
	Action    string `json:"action"`
	Handle    string `json:"handle,omitempty"`
	Offset    int    `json:"offset,omitempty"`
	Total     int    `json:"total,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Data      []byte `json:"data,omitempty"`
}
type storageTransferReply struct {
	OK     bool   `json:"ok"`
	Handle string `json:"handle"`
	Total  int    `json:"total"`
	Digest string `json:"digest"`
	Data   []byte `json:"data"`
}

// Retains storageRequest/storageReply unchanged. Control operations use v1 so a
// lock/logout can revoke an in-flight authenticated download immediately.
func BoundedStorageCall(input []byte, call func([]byte) ([]byte, error)) ([]byte, error) {
	var request struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(input, &request); err != nil {
		return nil, err
	}
	switch request.Operation {
	case "status", "settings", "lock", "logout", "retryCleanup", "clearSecretClipboard", "copySecret", "authorizeSecretDisplay":
		return call(input)
	}
	if len(input) == 0 || len(input) > storageTransferBytes {
		return nil, errSnapshotTooLarge
	}
	storageTransferMutex.Lock()
	defer storageTransferMutex.Unlock()
	exchange := func(frame storageTransferFrame) (storageTransferReply, error) {
		frame.Operation = "__transfer_v1"
		encoded, err := json.Marshal(frame)
		if err != nil {
			return storageTransferReply{}, err
		}
		defer clear(encoded)
		raw, err := call(encoded)
		if err != nil {
			return storageTransferReply{}, err
		}
		defer clear(raw)
		var reply storageTransferReply
		if json.Unmarshal(raw, &reply) != nil || !reply.OK {
			clear(reply.Data)
			return storageTransferReply{}, errors.New("snapshot transfer rejected")
		}
		return reply, nil
	}
	digest := sha256.Sum256(input)
	begin, err := exchange(storageTransferFrame{Action: "begin", Total: len(input), Digest: hex.EncodeToString(digest[:])})
	if err != nil {
		return nil, err
	}
	if begin.Handle == "" {
		return nil, errors.New("invalid transfer handle")
	}
	defer func() { _, _ = exchange(storageTransferFrame{Action: "cancel", Handle: begin.Handle}) }()
	for offset := 0; offset < len(input); offset += storageChunkBytes {
		end := min(offset+storageChunkBytes, len(input))
		if _, err = exchange(storageTransferFrame{Action: "append", Handle: begin.Handle, Offset: offset, Data: input[offset:end]}); err != nil {
			return nil, err
		}
	}
	ready, err := exchange(storageTransferFrame{Action: "finish", Handle: begin.Handle})
	if err != nil {
		return nil, err
	}
	if ready.Total <= 0 || ready.Total > storageTransferBytes {
		return nil, errSnapshotTooLarge
	}
	output := make([]byte, 0, ready.Total)
	success := false
	defer func() {
		if !success {
			clear(output)
		}
	}()
	for len(output) < ready.Total {
		page, err := exchange(storageTransferFrame{Action: "read", Handle: begin.Handle, Offset: len(output)})
		if err != nil {
			return nil, err
		}
		expected := min(storageChunkBytes, ready.Total-len(output))
		if len(page.Data) != expected {
			clear(page.Data)
			return nil, errors.New("invalid transfer page")
		}
		output = append(output, page.Data...)
		clear(page.Data)
	}
	actual := sha256.Sum256(output)
	if hex.EncodeToString(actual[:]) != ready.Digest {
		return nil, errors.New("invalid transfer digest")
	}
	success = true
	return output, nil
}
