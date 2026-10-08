// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

var errRuntimeSecretUnavailable = errors.New("原生临时秘密许可不可用或已撤销")
var runtimeSecretGeneration atomic.Uint64

func nextRuntimeSecretGeneration() uint64 {
	for {
		previous := runtimeSecretGeneration.Load()
		next := uint64(time.Now().UnixNano())
		if next <= previous {
			next = previous + 1
		}
		if runtimeSecretGeneration.CompareAndSwap(previous, next) {
			return next
		}
	}
}

type runtimeSecretRequest struct {
	Operation      string            `json:"operation"`
	Purpose        string            `json:"purpose"`
	Scope          vaultwarden.Scope `json:"scope"`
	Generation     uint64            `json:"generation"`
	DeadlineUnixMS int64             `json:"deadlineUnixMS"`
	LeaseID        string            `json:"leaseID,omitempty"`
	OperationID    string            `json:"operationID,omitempty"`
	SummaryHash    string            `json:"summaryHash,omitempty"`
	RequestID      string            `json:"requestID,omitempty"`
	Secret         string            `json:"secret,omitempty"`
}
type runtimeSecretReply struct {
	OK             bool   `json:"ok"`
	Code           string `json:"code"`
	LeaseID        string `json:"leaseID"`
	Generation     uint64 `json:"generation"`
	DeadlineUnixMS int64  `json:"deadlineUnixMS"`
}
type nativeRuntimeSecrets struct {
	mu      sync.Mutex
	binding runtimeSecretRequest
	serial  uint64
	call    func([]byte) ([]byte, error)
}

func newRuntimeSecrets() *nativeRuntimeSecrets {
	return &nativeRuntimeSecrets{call: nativeRuntimeSecretCall}
}
func runtimeSecretExchange(call func([]byte) ([]byte, error), request runtimeSecretRequest) (runtimeSecretReply, error) {
	var reply runtimeSecretReply
	input, err := json.Marshal(request)
	if err != nil || len(input) > 96*1024 {
		return reply, errRuntimeSecretUnavailable
	}
	defer clear(input)
	output, err := call(input)
	defer clear(output)
	if err != nil {
		return reply, err
	}
	if len(output) > 96*1024 || json.Unmarshal(output, &reply) != nil || !reply.OK {
		return reply, errRuntimeSecretUnavailable
	}
	if request.Operation != "revoke" && (reply.LeaseID == "" || len(reply.LeaseID) > 256 || reply.Generation != request.Generation || reply.DeadlineUnixMS != request.DeadlineUnixMS) {
		return runtimeSecretReply{}, errRuntimeSecretUnavailable
	}
	if request.Operation != "activate" && request.Operation != "revoke" && reply.LeaseID != request.LeaseID {
		return runtimeSecretReply{}, errRuntimeSecretUnavailable
	}
	return reply, nil
}
func (n *nativeRuntimeSecrets) Revoke() {
	n.mu.Lock()
	n.serial++
	binding := n.binding
	n.binding = runtimeSecretRequest{}
	n.mu.Unlock()
	if binding.LeaseID != "" {
		binding.Operation = "revoke"
		_, _ = runtimeSecretExchange(n.call, binding)
	}
}
func (n *nativeRuntimeSecrets) activate(scope vaultwarden.Scope, purpose, operationID, summaryHash string, deadline time.Time) (runtimeSecretRequest, error) {
	return n.activateBound(scope, purpose, deadline, func(uint64, int64) (string, string) { return operationID, summaryHash })
}
func (n *nativeRuntimeSecrets) activateBound(scope vaultwarden.Scope, purpose string, deadline time.Time, binding func(uint64, int64) (string, string)) (runtimeSecretRequest, error) {
	n.Revoke()
	n.mu.Lock()
	n.serial++
	serial := n.serial
	n.mu.Unlock()
	if !time.Now().Before(deadline) || deadline.After(time.Now().Add(30*time.Second)) {
		return runtimeSecretRequest{}, vaultwarden.ErrExpired
	}
	generation := nextRuntimeSecretGeneration()
	operationID, summaryHash := binding(generation, deadline.UnixMilli())
	request := runtimeSecretRequest{Operation: "activate", Purpose: purpose, Scope: scope, Generation: generation, DeadlineUnixMS: deadline.UnixMilli(), OperationID: operationID, SummaryHash: summaryHash}
	reply, err := runtimeSecretExchange(n.call, request)
	if err != nil {
		return request, err
	}
	request.LeaseID = reply.LeaseID
	n.mu.Lock()
	if n.serial != serial {
		n.mu.Unlock()
		request.Operation = "revoke"
		_, _ = runtimeSecretExchange(n.call, request)
		return runtimeSecretRequest{}, vaultwarden.ErrCancelled
	}
	n.binding = request
	n.mu.Unlock()
	return request, nil
}
func (n *nativeRuntimeSecrets) Use(scope vaultwarden.Scope, _ uint64, deadline time.Time, secret string, copy bool) error {
	request, err := n.activate(scope, "secret", "", "", deadline)
	if err != nil {
		return err
	}
	request.Operation = "authorizeDisplay"
	if copy {
		request.Operation = "copy"
		request.Secret = secret
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			n.Revoke()
			return err
		}
		id[6] = (id[6] & 15) | 64
		id[8] = (id[8] & 63) | 128
		raw := hex.EncodeToString(id[:])
		request.RequestID = raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
	}
	_, err = runtimeSecretExchange(n.call, request)
	if err != nil {
		n.Revoke()
	}
	return err
}

// Every newly activated native generation revokes old display authorization.
// Clear Go-owned display values before acquiring a new runtime secret/recovery
// permission, including when activation subsequently fails.
func (a *app) prepareRuntimeSecret() {
	if a.runtimeVault == nil {
		return
	}
	a.runtimeVault.revokeSecrets()
	if a.editor != nil {
		a.editor.shownSecret = ""
		clear(a.editor.shownHistory)
		a.editor.shownHistory = nil
		a.editor.showHistory = false
		clearCipherRowReveal(a.editor)
	}
}
