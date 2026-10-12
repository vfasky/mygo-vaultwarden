// SPDX-License-Identifier: GPL-3.0-only
package app

import "github.com/vfasky/mygo-vaultwarden/internal/localstore"

type autofillSettingsState struct {
	started, loaded, busy bool
	copyTOTP              bool
	message               string
}

func (a *app) loadAutofillSettings() {
	state := &a.autofillSettings
	if state.started {
		return
	}
	state.started, state.copyTOTP = true, true
	// Preview windows have no native storage or UI dispatcher.
	if !a.windows.native && a.storageBackend == nil {
		return
	}
	a.requestAutofillSettings(nil)
}

func (a *app) requestAutofillSettings(value *bool) {
	state := &a.autofillSettings
	if state.busy {
		return
	}
	previous := state.copyTOTP
	request := localstore.Request{Operation: localstore.OperationAutofillSettings}
	if value != nil {
		next := *value
		request.AutofillCopyTOTP = &next
		state.copyTOTP = next
	}
	state.busy, state.message = true, ""
	storage := a.storageCall
	go func() {
		reply := storage(request)
		a.dispatchUI(func() {
			state.busy = false
			if !reply.OK {
				state.copyTOTP, state.message = previous, reply.Message
				a.status = reply.Message
				return
			}
			state.copyTOTP, state.loaded = reply.AutofillCopyTOTP, true
		})
	}()
}
