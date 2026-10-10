// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"io"
	"os"
	"testing"
)

// Keep this fixture consistent with the same fixture in internal/ui/organization tests.
func orgResourceUIFixture(t *testing.T) *vaultwarden.ResourceImportPlan {
	t.Helper()
	metadata := json.RawMessage(`{"format":"mygo-organization-backup","version":1,"organizationId":"source-org","collections":[{"id":"source-col","organizationId":"source-org","name":"Source","type":0}],"items":[{"id":"source-item","organizationId":"source-org","collectionIds":["source-col"],"type":2,"name":"Note","favorite":false,"reprompt":0,"secureNote":{"type":0},"folderId":"source-folder","archivedDate":"2026-01-01T00:00:00Z","deletedDate":"2026-01-02T00:00:00Z"}]}`)
	content := []byte("resource body")
	hash := sha256.Sum256(content)
	manifest, err := json.Marshal(map[string]any{"format": "mygo-vaultwarden-resource-backup", "version": 1, "organizationId": "source-org", "metadata": metadata, "resources": []vaultwarden.BackupResource{{CipherID: "source-item", AttachmentID: "source-file", FileName: "test.bin", Path: "files/000000.bin", Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"manifest.json", manifest}, {"files/000000.bin", content}} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		header.SetMode(0600)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		file.Write(entry.data)
	}
	writer.Close()
	file, err := os.CreateTemp("", "mygo-org-resource-ui-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	file.Write(buffer.Bytes())
	file.Seek(0, io.SeekStart)
	plan, err := vaultwarden.ParseResourceImport(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plan.Clear)
	return plan
}
