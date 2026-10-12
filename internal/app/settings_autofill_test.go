// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
)

func TestAutofillSettingsLoadSaveAndFailure(t *testing.T) {
	requests := make(chan localstore.Request, 4)
	replies := make(chan localstore.Reply, 4)
	updates := make(chan func(), 4)
	a := &app{
		storageBackend: func(request localstore.Request) localstore.Reply {
			requests <- request
			return <-replies
		},
		uiDispatcher: func(f func()) { updates <- f },
	}
	request := func() localstore.Request {
		t.Helper()
		select {
		case request := <-requests:
			if request.Operation != localstore.OperationAutofillSettings || request.Scope != nil || len(request.UnlockKey) != 0 {
				t.Fatalf("unexpected request: %+v", request)
			}
			return request
		case <-time.After(time.Second):
			t.Fatal("missing preference request")
			return localstore.Request{}
		}
	}
	complete := func(reply localstore.Reply) {
		t.Helper()
		replies <- reply
		select {
		case f := <-updates:
			f()
		case <-time.After(time.Second):
			t.Fatal("missing UI completion")
		}
	}
	a.loadAutofillSettings()
	a.loadAutofillSettings()
	if !a.autofillSettings.busy || a.autofillSettings.loaded || !a.autofillSettings.copyTOTP {
		t.Fatal("initial preference should be on and loading")
	}
	if request().AutofillCopyTOTP != nil {
		t.Fatal("read sent a write")
	}
	complete(localstore.Reply{OK: true, AutofillCopyTOTP: true})
	value := false
	a.requestAutofillSettings(&value)
	if r := request(); r.AutofillCopyTOTP == nil || *r.AutofillCopyTOTP {
		t.Fatal("disable was omitted")
	}
	complete(localstore.Reply{OK: true, AutofillCopyTOTP: false})
	if a.autofillSettings.copyTOTP || !a.autofillSettings.loaded {
		t.Fatal("saved value not reflected")
	}
	value = true
	a.requestAutofillSettings(&value)
	if r := request(); r.AutofillCopyTOTP == nil || !*r.AutofillCopyTOTP {
		t.Fatal("enable was omitted")
	}
	complete(localstore.Reply{Message: "fixture failure"})
	if a.autofillSettings.copyTOTP || a.autofillSettings.busy || a.autofillSettings.message != "fixture failure" || a.status != "fixture failure" {
		t.Fatal("failed save did not restore the value and display the failure")
	}
	a.loadAutofillSettings()
	if len(requests) != 0 || a.epoch != 0 || a.pending != 0 {
		t.Fatal("preference reloaded or changed vault lifecycle")
	}
}

func TestAutofillSettingsPreview(t *testing.T) {
	a := previewApp()
	a.windows.settingsTab = settingsTabStorage
	tt := ui.NewTester(a.settingsWindowView, 860, 1000)
	if !tt.HasText(i18n.T("settings.storage.copy_totp")) || !tt.HasText(i18n.T("settings.storage.copy_totp_hint")) {
		t.Fatal("missing AutoFill preference")
	}
	if !a.autofillSettings.copyTOTP || a.autofillSettings.loaded || a.autofillSettings.busy {
		t.Fatal("preview preference must remain on and disabled without storage")
	}
}
