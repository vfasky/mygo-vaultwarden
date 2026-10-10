// SPDX-License-Identifier: GPL-3.0-only
package app

import ()

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
