// SPDX-License-Identifier: GPL-3.0-only
package account

import (
	"context"
	"encoding/base64"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/kit"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func previewDevicePanel() *DevicePanel {
	ctx, cancel := context.WithCancel(context.Background())
	return &DevicePanel{ctx: ctx, cancel: cancel,
		Devices:  []vaultwarden.Device{{Name: "Alex’s MacBook Pro", Identifier: "macbook-preview", Type: 7, RevisionDate: "2026-07-19 10:24"}},
		Requests: []vaultwarden.AuthRequest{{ID: "preview-request", RequestDeviceType: "macOS", RequestIPAddress: "192.0.2.8", CreationDate: "2026-07-19 10:25", Origin: "https://vault.example.com", PublicKey: base64.StdEncoding.EncodeToString([]byte("public-preview-key"))}},
	}
}

func TestPanelsAccountVisualPreviews(t *testing.T) {
	dir := os.Getenv("MYGO_UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set MYGO_UI_PREVIEW_DIR to export panel previews")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer i18n.Set(i18n.Current())
	for _, lang := range []i18n.Lang{i18n.Chinese, i18n.English} {
		i18n.Set(lang)
		suffix := "zh"
		if lang == i18n.English {
			suffix = "en"
		}
		devices := previewDevicePanel()
		defer devices.Close()
		password := NewForm(vaultwarden.Scope{}, 1, nil)
		password.Mode = "password"
		defer password.Close()
		api := NewForm(vaultwarden.Scope{}, 1, nil)
		api.Mode = "api-key"
		api.confirmAction = "rotate-api-key"
		api.confirming = true
		defer api.Close()
		mfa := NewAuthManagementForm(vaultwarden.Scope{}, 1, nil)
		defer mfa.Close()
		setup := NewAuthManagementForm(vaultwarden.Scope{}, 1, nil)
		setup.operation = "authenticator"
		setup.confirming = true
		defer setup.Close()
		emptyDevices := previewDevicePanel()
		emptyDevices.Devices, emptyDevices.Requests = nil, nil
		defer emptyDevices.Close()
		emptyEmergency := NewEmergencyPanel(nil, true, nil, nil, nil)
		defer emptyEmergency.Close()
		viewer := NewEmergencyViewer(vaultwarden.EmergencyContact{Name: "Alex Chen", Email: "alex@example.com", Status: 4}, nil, nil)
		defer viewer.Close()
		emergency := NewEmergencyPanel([]vaultwarden.EmergencyContact{{ID: "contact-preview", Name: "Alex Chen", Email: "alex@example.com", Status: 2, WaitTimeDays: 7}}, true, nil, nil, nil)
		defer emergency.Close()
		recovery := NewRecoveryPanel([]RecoveryMemberChoice{{OrganizationID: "org", MemberID: "member", Label: "Alex · Example team", Administrator: true}}, nil, nil, nil)
		recovery.selected = 0
		recovery.operation = "administrator"
		defer recovery.Close()
		views := []struct {
			name, title string
			view        func(*ui.Context)
		}{
			{"devices", i18n.T("account.device.title"), devices.View},
			{"security", i18n.T("account.form.title"), func(c *ui.Context) { FormView(c, password) }},
			{"security-confirm", i18n.T("account.form.title"), func(c *ui.Context) { FormView(c, api) }},
			{"mfa", i18n.T("account.mfa.methods_title"), func(c *ui.Context) { AuthManagementView(c, mfa) }},
			{"mfa-setup", i18n.T("account.mfa.methods_title"), func(c *ui.Context) { AuthManagementView(c, setup) }},
			{"devices-empty", i18n.T("account.device.title"), emptyDevices.View},
			{"emergency-empty", i18n.T("account.emergency.title"), emptyEmergency.View},
			{"emergency-view", i18n.T("account.emergency.title"), viewer.View},
			{"emergency", i18n.T("account.emergency.title"), emergency.View},
			{"recovery", i18n.T("account.recovery.title"), recovery.View},
			{"device-approval", i18n.T("account.device.title"), func(c *ui.Context) {
				devices.Selected = &devices.Requests[0]
				devices.Confirm = "auth"
				devices.View(c)
			}},
		}
		for _, view := range views {
			tt := ui.NewTester(func(c *ui.Context) {
				c.SetTheme(kit.Theme)
				ui.Scroll(c).Fill().Background(kit.Panel).Children(func() {
					ui.Column(c).Padding(24).Gap(16).Children(func() { kit.PageHeader(c, view.title, "", nil); view.view(c) })
				})
			}, 820, 900)
			path := filepath.Join(dir, view.name+"-"+suffix+".png")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			err = png.Encode(f, tt.Image())
			closeErr := f.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			if view.name == "mfa-setup" {
				tt.Scroll(750, 700, 0, 600)
				tt.Frame()
				f, err := os.Create(filepath.Join(dir, view.name+"-footer-"+suffix+".png"))
				if err != nil {
					t.Fatal(err)
				}
				err = png.Encode(f, tt.Image())
				closeErr := f.Close()
				if err != nil {
					t.Fatal(err)
				}
				if closeErr != nil {
					t.Fatal(closeErr)
				}
			}
		}
	}
}

func TestDeviceApprovalRequiresFingerprintAndRetainsCancel(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	p := previewDevicePanel()
	defer p.Close()
	p.Selected = &p.Requests[0]
	p.Confirm = "auth"
	tt := ui.NewTester(p.View, 820, 1400)
	if err := tt.Click(i18n.T("account.device.confirm_approve_login")); err != nil {
		t.Fatal(err)
	}
	if p.Selected == nil || p.Confirm != "auth" || p.Verified {
		t.Fatal("approval bypassed fingerprint verification")
	}
	p.Uncertain = true
	tt.Frame()
	if err := tt.Click(i18n.T("account.device.confirm_fingerprint")); err != nil {
		t.Fatal(err)
	}
	if p.Verified {
		t.Fatal("uncertain operation allowed fingerprint confirmation")
	}
	if err := tt.Click(i18n.T("account.device.cancel_approval")); err != nil {
		t.Fatal(err)
	}
	if p.Selected != nil || p.Confirm != "" {
		t.Fatal("cancel did not clear approval")
	}
}

func TestManagementOperationRowsPreserveUnknownResultGate(t *testing.T) {
	defer i18n.Set(i18n.Current())
	i18n.Set(i18n.English)
	f := NewAuthManagementForm(vaultwarden.Scope{}, 1, nil)
	defer f.Close()
	tt := ui.NewTester(func(c *ui.Context) { AuthManagementView(c, f) }, 820, 1800)
	for _, entry := range authManagementOperations() {
		if err := tt.Click(entry.label); err != nil {
			t.Fatal(err)
		}
		if f.operation != entry.op {
			t.Fatalf("operation %s is inaccessible", entry.op)
		}
	}
	f.uncertain = true
	f.operation = vaultwarden.MFAList
	tt.Frame()
	if err := tt.Click(i18n.T("account.mfa.enable_authenticator")); err != nil {
		t.Fatal(err)
	}
	if f.operation != vaultwarden.MFAList {
		t.Fatal("unknown result allowed mutation selection")
	}
	if err := tt.Click(i18n.T("account.mfa.load_methods")); err != nil {
		t.Fatal(err)
	}
	if f.operation != vaultwarden.MFAList {
		t.Fatal("refresh unavailable after unknown result")
	}
}
