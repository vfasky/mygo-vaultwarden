// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"github.com/vfasky/mygo-vaultwarden/internal/testfixture"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"testing"
)

func orgResourceUIFixture(t *testing.T) *vaultwarden.ResourceImportPlan {
	return testfixture.OrganizationResource(t)
}
