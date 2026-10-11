// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
)

type backupServiceFake struct {
	t          *testing.T
	content    []byte
	resource   BackupResource
	events     []string
	publishErr error
}

func (f *backupServiceFake) DownloadAttachmentForBackup(_ context.Context, _ *VaultData, _, _ string, _ *ItemAuthorization, _ func(SessionCheckpoint) error, consume func(*os.File, int64) error) (*AttachmentPublication, error) {
	f.events = append(f.events, "download")
	file, err := os.CreateTemp("", "backup-service-test-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(f.content); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return &AttachmentPublication{}, consume(file, int64(len(f.content)))
}
func (f *backupServiceFake) PublishAttachment(_ context.Context, _ *AttachmentPublication, _ *ItemAuthorization, publish func() error) error {
	f.events = append(f.events, "publish-attachment")
	if f.publishErr != nil {
		return f.publishErr
	}
	return publish()
}
func (f *backupServiceFake) UploadAttachment(_ context.Context, _ *VaultData, _, name string, file *os.File, _ *ItemAuthorization, _ func(SessionCheckpoint) error) (AttachmentUploadResult, error) {
	f.events = append(f.events, "upload")
	got, err := io.ReadAll(file)
	if err != nil {
		return AttachmentUploadResult{}, err
	}
	if name != f.resource.FileName || !bytes.Equal(got, f.content) {
		f.t.Fatal("restore changed content or name")
	}
	return AttachmentUploadResult{}, nil
}
func (f *backupServiceFake) backupResourceDescriptions(*VaultData, []string, map[string]*ItemAuthorization) ([]BackupResource, error) {
	return []BackupResource{f.resource}, nil
}
func (f *backupServiceFake) prepareResourcePublication(_ context.Context, _ *ResourceBackupPublication, _ map[string]*ItemAuthorization, _ func(SessionCheckpoint) error, _ bool) error {
	f.events = append(f.events, "prepare-publication")
	return nil
}

func TestResourceBackupServiceArchiveRestoreAndVerification(t *testing.T) {
	ctx := context.Background()
	content := []byte("binary fixture\x00\xff")
	hash := sha256.Sum256(content)
	resource := BackupResource{CipherID: "cipher-1", AttachmentID: "attachment-1", FileName: "file.bin", Path: "files/000000.bin", Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}
	fake := &backupServiceFake{t: t, content: content, resource: resource}
	service := resourceBackupService{access: fake}
	var archive bytes.Buffer
	proof := &ResourceBackupPublication{}
	got, err := service.writeResourceArchive(ctx, nil, nil, resourceManifest{Resources: []BackupResource{resource}}, proof, &archive, nil)
	if err != nil || got != proof {
		t.Fatalf("archive: %v", err)
	}
	if events := fake.events; len(events) != 3 || events[0] != "download" || events[1] != "publish-attachment" || events[2] != "prepare-publication" {
		t.Fatalf("authority order: %v", events)
	}
	reader, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp("", "backup-service-plan-*")
	if err != nil {
		t.Fatal(err)
	}
	plan := &ResourceImportPlan{file: file, manifest: resourceManifest{Resources: []BackupResource{resource}}, entries: map[string]*zip.File{}}
	defer plan.Clear()
	for _, entry := range reader.File {
		plan.entries[entry.Name] = entry
	}
	if _, err := service.UploadResource(ctx, nil, "target", plan, 0, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := service.VerifyRestoredResource(ctx, nil, "target", resource.AttachmentID, plan, 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake.events = nil
	plan.manifest.Resources[0].SHA256 = "bad"
	if _, err := service.UploadResource(ctx, nil, "target", plan, 0, true, nil, nil); !errors.Is(err, ErrEncryption) {
		t.Fatalf("bad hash: %v", err)
	}
	if len(fake.events) != 0 {
		t.Fatal("uploaded before integrity validation")
	}
	delete(plan.entries, resource.Path)
	if _, err := service.UploadResource(ctx, nil, "target", plan, 0, true, nil, nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing archive entry: %v", err)
	}
	fake.events = nil
	fake.publishErr = ErrPermission
	if _, err := service.writeResourceArchive(ctx, nil, nil, resourceManifest{Resources: []BackupResource{resource}}, proof, io.Discard, nil); !errors.Is(err, ErrPermission) {
		t.Fatal(err)
	}
	if len(fake.events) != 2 {
		t.Fatalf("archive continued after revoked authority: %v", fake.events)
	}
}
