// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"
)

func resourceArchiveFixture(t *testing.T, alter func(*resourceManifest), entryAlter func(*zip.FileHeader), extra bool) []byte {
	t.Helper()
	s, vault, ids := backupFixture(t, MyGoBackup, 1)
	defer s.Close()
	metadata, err := s.ExportPersonalBackup(context.Background(), vault, ids, MyGoBackup)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(metadata)
	content := []byte("resource\x00\xff")
	sum := sha256.Sum256(content)
	manifest := resourceManifest{Format: resourceBackupSignature, Version: 1, Metadata: metadata, Resources: []BackupResource{{CipherID: ids[0], AttachmentID: "file-a", FileName: "文件.bin", Path: "files/000000.bin", Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}}}
	if alter != nil {
		alter(&manifest)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	header := &zip.FileHeader{Name: "files/000000.bin", Method: zip.Store}
	header.SetMode(0600)
	if entryAlter != nil {
		entryAlter(header)
	}
	file, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	file.Write(content)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	file, err = writer.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	file.Write(raw)
	if extra {
		file, err = writer.Create("undeclared.bin")
		if err != nil {
			t.Fatal(err)
		}
		file.Write(content)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	// Create defaults to Deflate: rewrite manifest as Store so fixture complies.
	reader, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var final bytes.Buffer
	output := zip.NewWriter(&final)
	for _, entry := range reader.File {
		header := entry.FileHeader
		if entry.Name == "manifest.json" {
			header.Method = zip.Store
		}
		read, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(read)
		read.Close()
		if err != nil {
			t.Fatal(err)
		}
		write, err := output.CreateHeader(&header)
		if err != nil {
			t.Fatal(err)
		}
		write.Write(body)
	}
	output.Close()
	return final.Bytes()
}
func parseResourceBytes(t *testing.T, data []byte) (*ResourceImportPlan, error) {
	t.Helper()
	file, err := os.CreateTemp("", "mygo-resource-parse-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	file.Write(data)
	file.Seek(0, io.SeekStart)
	return ParseResourceImport(context.Background(), file)
}
func TestResourceArchiveStrictPreflight(t *testing.T) {
	valid := resourceArchiveFixture(t, nil, nil, false)
	plan, err := parseResourceBytes(t, valid)
	if err != nil {
		t.Fatal(err)
	}
	name := plan.file.Name()
	resources := plan.Resources()
	resources[0].FileName = "tampered"
	if plan.Resources()[0].FileName != "文件.bin" {
		t.Fatal("preview aliases plan")
	}
	plan.Clear()
	if _, err = os.Stat(name); !os.IsNotExist(err) {
		t.Fatal("private archive not removed")
	}
	cases := []struct {
		name  string
		alter func(*resourceManifest)
		entry func(*zip.FileHeader)
		extra bool
	}{
		{name: "unknown source", alter: func(m *resourceManifest) { m.Resources[0].CipherID = "other" }},
		{name: "path traversal", alter: func(m *resourceManifest) { m.Resources[0].Path = "../escape" }},
		{name: "wrong size", alter: func(m *resourceManifest) { m.Resources[0].Size++ }},
		{name: "wrong hash", alter: func(m *resourceManifest) { m.Resources[0].SHA256 = "invalid" }},
		{name: "bad filename", alter: func(m *resourceManifest) { m.Resources[0].FileName = "../secret" }},
		{name: "version", alter: func(m *resourceManifest) { m.Version = 2 }},
		{name: "missing declaration", alter: func(m *resourceManifest) { m.Resources = nil }},
		{name: "duplicate resource", alter: func(m *resourceManifest) { m.Resources = append(m.Resources, m.Resources[0]) }},
		{name: "oversized entry", alter: func(m *resourceManifest) { m.Resources[0].Size = (512 << 20) + 1 }},
		{name: "compression", entry: func(h *zip.FileHeader) { h.Method = zip.Deflate }},
		{name: "symlink", entry: func(h *zip.FileHeader) { h.SetMode(os.ModeSymlink | 0600) }},
		{name: "extra entry", extra: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := resourceArchiveFixture(t, tc.alter, tc.entry, tc.extra)
			plan, err := parseResourceBytes(t, archive)
			if plan != nil {
				plan.Clear()
			}
			if err == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
}
func TestResourcePublicationRequiresCurrentLeaseAndGrants(t *testing.T) {
	for _, scenario := range []string{"success", "cancel", "lock", "expired-file-proof", "replay"} {
		t.Run(scenario, func(t *testing.T) {
			s, vault, ids := backupFixture(t, MyGoBackup, 1)
			defer s.Close()
			var archive bytes.Buffer
			proof, err := s.WriteResourceBackup(context.Background(), vault, ids, "", nil, true, &archive, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "cancel" {
				cancel()
			}
			if scenario == "lock" {
				s.Close()
			}
			if scenario == "expired-file-proof" {
				proof.expires = time.Now().Add(-time.Second)
			}
			count := 0
			publish := func() error { count++; return nil }
			err = s.PublishResourceBackup(ctx, proof, nil, publish)
			success := scenario == "success" || scenario == "replay"
			if success && (err != nil || count != 1) {
				t.Fatal("valid publication", err)
			}
			if !success && (err == nil || count != 0) {
				t.Fatal("revoked publication", err)
			}
			if scenario == "replay" {
				if err = s.PublishResourceBackup(ctx, proof, nil, publish); err == nil || count != 1 {
					t.Fatal("replayed publication")
				}
			}
		})
	}
}
