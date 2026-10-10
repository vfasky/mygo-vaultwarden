// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"io"
	"os"
)

// resourceBackupAccess is the authority boundary for the resource backup domain.
// The service owns archive assembly, restore staging and content verification;
// the adapter owns authentication, operation lifetime and publication authority.
// In particular the service cannot read Session keys or bypass a grant check.
type resourceBackupAccess interface {
	DownloadAttachmentForBackup(context.Context, *VaultData, string, string, *ItemAuthorization, func(SessionCheckpoint) error, func(*os.File, int64) error) (*AttachmentPublication, error)
	PublishAttachment(context.Context, *AttachmentPublication, *ItemAuthorization, func() error) error
	UploadAttachment(context.Context, *VaultData, string, string, *os.File, *ItemAuthorization, func(SessionCheckpoint) error) (AttachmentUploadResult, error)
	backupResourceDescriptions(*VaultData, []string, map[string]*ItemAuthorization) ([]BackupResource, error)
	prepareResourcePublication(context.Context, *ResourceBackupPublication, map[string]*ItemAuthorization, func(SessionCheckpoint) error, bool) error
}

type resourceBackupService struct{ access resourceBackupAccess }

func (s *Session) writeResourceArchive(ctx context.Context, vault *VaultData, grants map[string]*ItemAuthorization, manifest resourceManifest, publication *ResourceBackupPublication, writer io.Writer, persist func(SessionCheckpoint) error) (*ResourceBackupPublication, error) {
	return (resourceBackupService{access: s}).writeResourceArchive(ctx, vault, grants, manifest, publication, writer, persist)
}

func (s *Session) UploadResource(ctx context.Context, vault *VaultData, targetID string, plan *ResourceImportPlan, index int, confirmed bool, grant *ItemAuthorization, persist func(SessionCheckpoint) error) (AttachmentUploadResult, error) {
	return (resourceBackupService{access: s}).UploadResource(ctx, vault, targetID, plan, index, confirmed, grant, persist)
}

func (s *Session) VerifyRestoredResource(ctx context.Context, vault *VaultData, targetID, attachmentID string, plan *ResourceImportPlan, index int, grant *ItemAuthorization, persist func(SessionCheckpoint) error) error {
	return (resourceBackupService{access: s}).VerifyRestoredResource(ctx, vault, targetID, attachmentID, plan, index, grant, persist)
}
