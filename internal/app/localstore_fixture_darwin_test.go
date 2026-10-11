// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin

package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/testfixture"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func recoveryNativeCall(t *testing.T) func(localstore.Request) localstore.Reply {
	return testfixture.RecoveryNativeCall[localstore.Request, localstore.Reply](t, localstore.BoundedStorageCall)
}

func targetFixture(scope vaultwarden.Scope) vaultwarden.SyncResult {
	return testfixture.TargetSnapshot(scope)
}
