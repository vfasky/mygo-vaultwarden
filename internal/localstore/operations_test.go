// SPDX-License-Identifier: GPL-3.0-only
package localstore

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestOperationSchemaAndWire(t *testing.T) {
	raw, err := os.ReadFile("../../tools/storage-operations/operations.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		Name      Operation
		Control   bool
		Publishes bool
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	// This compatibility assertion deliberately pins the seven existing publishers.
	publishers := map[Operation]bool{OperationPublishBoundAccount: true, OperationPublishVault: true, OperationRestoreOrganizationAccess: true, OperationRestorePolicyAccess: true, OperationAccountRecoveryResolve: true, OperationTargetRecoveryResolve: true, OperationTargetRecoveryResolveLocal: true}
	if len(entries) != 34 {
		t.Fatalf("operation inventory changed: %d", len(entries))
	}
	for _, entry := range entries {
		t.Run(string(entry.Name), func(t *testing.T) {
			if !entry.Name.Valid() || entry.Name.AllowsTransfer() == entry.Control || entry.Name.PublishesCredentials() != publishers[entry.Name] {
				t.Fatal("operation metadata changed")
			}
			encoded, err := json.Marshal(Request{Operation: entry.Name})
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Operation   string
				Credentials json.RawMessage
			}
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			expected := []byte("null")
			if publishers[entry.Name] {
				expected = []byte("[]")
			}
			if wire.Operation != string(entry.Name) || !bytes.Equal(wire.Credentials, expected) {
				t.Fatalf("wire changed: %s", encoded)
			}
		})
	}
	for _, unknown := range []Operation{"", "STATUS", "unsupported-test-operation", "__transfer_v1", "activate"} {
		if unknown.Valid() || unknown.AllowsTransfer() || unknown.PublishesCredentials() {
			t.Fatalf("unknown operation accepted: %q", unknown)
		}
	}
}

func TestGeneratedOperationsCurrent(t *testing.T) {
	cmd := exec.Command("go", "run", "./tools/storage-operations", "-check")
	cmd.Dir = "../.."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("regenerate with go run ./tools/storage-operations: %v\n%s", err, output)
	}
}
