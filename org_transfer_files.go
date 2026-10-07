// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"

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

func exportOrgBackupFormatFile(ctx context.Context, session *vaultwarden.Session, vault *vaultwarden.VaultData, orgID, path string, grants map[string]*vaultwarden.ItemAuthorization, confirmed, official bool, persist func(vaultwarden.SessionCheckpoint) error) error {
	if session == nil {
		return vaultwarden.ErrExpired
	}
	export := session.WithOrganizationBackup
	if official {
		export = session.WithBitwardenOrganizationJSON
	}
	return export(ctx, vault, orgID, grants, confirmed, func(data []byte) error {
		stage, err := stageBackupFile(ctx, path, data)
		if err != nil {
			return err
		}
		defer stage.Close()
		if ctx.Err() != nil {
			return vaultwarden.ErrCancelled
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
