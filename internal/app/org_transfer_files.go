// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

// exportOrgBackupFile is the safe-save binding for the independent organization
// export form. The host must hold its authenticated snapshot lease for this call,
// propagate lock/scope cancellation, and obtain explicit plaintext-file consent.
func exportOrgBackupFile(ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData, orgID, path string, grants map[string]*vaultwarden.ItemAuthorization, confirmed bool, persist func(vaultwarden.SessionCheckpoint) error) error {
	if session == nil {
		return vaultwarden.ErrExpired
	}
	return exportOrgBackupFormatFile(ctx, session, vault, orgID, path, grants, confirmed, false, persist)
}

func exportOrgBackupFormatFile(ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData, orgID, path string, grants map[string]*vaultwarden.ItemAuthorization, confirmed, official bool, persist func(vaultwarden.SessionCheckpoint) error, leases ...func() error) error {
	if session == nil {
		return vaultwarden.ErrExpired
	}
	export := session.WithOrganizationBackup
	if official {
		export = session.WithBitwardenOrganizationJSON
	}
	return export(ctx, vault, orgID, grants, confirmed, func(data []byte) error {
		if len(leases) > 0 && leases[0] != nil {
			if err := leases[0](); err != nil {
				return err
			}
		}
		stage, err := stageBackupFile(ctx, path, data)
		if err != nil {
			return err
		}
		defer stage.Close()
		if ctx.Err() != nil {
			return vaultwarden.ErrCancelled
		}
		if len(leases) > 0 && leases[0] != nil {
			if err := leases[0](); err != nil {
				return err
			}
		}
		return stage.Commit()
	}, persist)
}

func readOrgImportPlan(ctx context.Context, path string) (*vaultwarden.OrganizationImportPlan, error) {
	return readOrgImportFormatPlan(ctx, path, false)
}

func readOrgImportFormatPlan(ctx context.Context, path string, official bool) (*vaultwarden.OrganizationImportPlan, error) {
	raw, err := readBackupFile(ctx, path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if official {
		return vaultwarden.ParseBitwardenOrganizationJSON(raw)
	}
	return vaultwarden.ParseOrganizationImport(raw)
}

func exportOrgResourceFile(ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData, orgID, path string, grants map[string]*vaultwarden.ItemAuthorization, confirmed bool, lease func() error, persist func(vaultwarden.SessionCheckpoint) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if session == nil {
		return vaultwarden.ErrExpired
	}
	if lease == nil {
		return vaultwarden.ErrPermission
	}
	if err := lease(); err != nil {
		return err
	}
	var proof *vaultwarden.ResourceBackupPublication
	stage, err := stageBackupStream(ctx, path, func(file *os.File) error {
		var err error
		proof, err = session.WriteResourceBackup(ctx, vault, nil, orgID, grants, confirmed, file, persist)
		return err
	})
	if err != nil {
		return err
	}
	defer stage.Close()
	return session.PublishResourceBackup(ctx, proof, grants, func() error {
		if err := lease(); err != nil {
			return err
		}
		return stage.Commit()
	})
}

func readOrgResourceImportPlan(ctx context.Context, path string) (*vaultwarden.ResourceImportPlan, *vaultwarden.OrganizationImportPlan, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	file, err := openAttachmentInput(path)
	if err != nil {
		return nil, nil, err
	}
	resources, err := vaultwarden.ParseResourceImport(ctx, file)
	if err != nil {
		return nil, nil, err
	}
	metadata, err := resources.OrganizationRestoreMetadata()
	if err != nil {
		resources.Clear()
		return nil, nil, err
	}
	return resources, metadata, nil
}

// prepareOrgResourceCopy validates every source binary before creating the new
// metadata. Its returned plan remains owned by the caller for explicit per-file
// restore/verification, including when a create response is ambiguous.
func prepareOrgResourceCopy(ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData, sourceID, targetOrgID, targetCollectionID string, grant *vaultwarden.ItemAuthorization, lease func() error, persist func(vaultwarden.SessionCheckpoint) error) (*vaultwarden.ResourceImportPlan, vaultwarden.CipherDocument, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if session == nil {
		return nil, vaultwarden.CipherDocument{}, vaultwarden.ErrExpired
	}
	if lease == nil {
		return nil, vaultwarden.CipherDocument{}, vaultwarden.ErrPermission
	}
	if err := lease(); err != nil {
		return nil, vaultwarden.CipherDocument{}, err
	}
	file, err := os.CreateTemp("", "mygo-org-resource-copy-*")
	if err != nil {
		return nil, vaultwarden.CipherDocument{}, err
	}
	defer func() { file.Close(); os.Remove(file.Name()) }()
	proof, err := session.WriteOrganizationCipherResourceCopy(ctx, vault, sourceID, grant, file, persist)
	if err != nil {
		return nil, vaultwarden.CipherDocument{}, err
	}
	if err = session.PublishResourceBackup(ctx, proof, map[string]*vaultwarden.ItemAuthorization{sourceID: grant}, func() error { return nil }); err != nil {
		return nil, vaultwarden.CipherDocument{}, err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, vaultwarden.CipherDocument{}, err
	}
	plan, err := vaultwarden.ParseResourceImport(ctx, file)
	if err != nil {
		return nil, vaultwarden.CipherDocument{}, err
	}
	if err := lease(); err != nil {
		return plan, vaultwarden.CipherDocument{}, err
	}
	created, err := session.CopyOrganizationResourceMetadata(ctx, vault, sourceID, targetOrgID, targetCollectionID, plan, grant, persist)
	return plan, created, err
}
