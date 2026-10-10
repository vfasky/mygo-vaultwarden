// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/platform/sysauth"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func authenticationSummary(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return i18n.T("account.mfa.status_request_completed"), nil
	}
	var data struct {
		Enabled      *bool  `json:"enabled"`
		Key          string `json:"key"`
		Email        string `json:"email"`
		RecoveryCode string `json:"code"`
		Host         string `json:"host"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Keys         []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"keys"`
		Data []struct {
			Type    int  `json:"type"`
			Enabled bool `json:"enabled"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return "", vaultwarden.ErrProtocol
	}
	var lines []string
	if data.Enabled != nil {
		lines = append(lines, i18n.Tf("account.mfa.status_enabled", *data.Enabled))
	}
	for _, field := range []struct{ label, value string }{
		{i18n.T("account.mfa.authenticator_key"), data.Key},
		{i18n.T("common.email"), data.Email},
		{i18n.T("account.mfa.recovery_code"), data.RecoveryCode},
		{i18n.T("account.mfa.duo_host"), data.Host},
		{i18n.T("account.mfa.duo_client_id"), data.ClientID},
		{i18n.T("account.mfa.duo_client_secret"), data.ClientSecret},
	} {
		if field.value != "" {
			lines = append(lines, field.label+"："+field.value)
		}
	}
	for _, key := range data.Keys {
		lines = append(lines, i18n.Tf("account.mfa.security_key_summary", key.ID, key.Name))
	}
	for _, provider := range data.Data {
		lines = append(lines, i18n.Tf("account.mfa.method_summary", provider.Type, provider.Enabled))
	}
	if len(lines) == 0 {
		return i18n.T("account.mfa.status_no_settings"), nil
	}
	return strings.Join(lines, "\n"), nil
}
func (a *app) openAuthenticationManagement() {
	a.openAuthenticationManagementWith(a.dispatchUI, a.storageCall)
}
func (a *app) openAuthenticationManagementWith(dispatch func(func()), storage func(localstore.Request) localstore.Reply) {
	if a.pending != 0 || !a.sessionOwnsSnapshot() {
		return
	}
	session, ok := a.session.(*vaultwarden.Session)
	if !ok {
		return
	}
	a.advanceEpoch()
	storage = a.routeStorage(storage, a.epoch)
	lease := a.newControllerLease()
	if lease == nil {
		return
	}
	epoch, scope := a.epoch, *a.liveScope
	ctx, cancel := context.WithCancel(context.Background())
	a.componentCancel = cancel
	platform := sysauth.NewAuthenticationPlatform(a.window)
	f := account.NewAuthManagementForm(scope, epoch, nil)
	complete := a.componentDispatch(session, lease, epoch, dispatch)
	f.Submit = func(r account.AuthManagementRequest) {
		a.pending++
		go func() {
			defer r.Close()
			opctx, done := context.WithTimeout(ctx, 5*time.Minute)
			defer done()
			stop := context.AfterFunc(r.Context, done)
			defer stop()
			err := lease.check(storage)
			persist := func(cp vaultwarden.SessionCheckpoint) error { return lease.persist(cp, storage) }
			var raw json.RawMessage
			if err == nil {
				for _, field := range []string{"id", "type"} {
					if value, ok := r.Fields[field]; ok {
						var text string
						if json.Unmarshal(value, &text) != nil {
							err = vaultwarden.ErrValidation
							break
						}
						n, e := strconv.Atoi(text)
						if e != nil {
							err = vaultwarden.ErrValidation
							break
						}
						r.Fields[field], _ = json.Marshal(n)
					}
				}
			}
			if err == nil {
				if r.Operation == "get-webauthn-challenge" {
					id, name := r.Fields["id"], r.Fields["name"]
					delete(r.Fields, "id")
					delete(r.Fields, "name")
					if len(r.Input.Password) == 0 || len(id) == 0 || len(name) == 0 {
						err = vaultwarden.ErrValidation
					} else {
						raw, err = session.MFAManage(opctx, r.Operation, r.Input, nil, r.Confirmed, persist)
						if err == nil {
							var response json.RawMessage
							response, err = platform.WebAuthn(opctx, scope.Server, raw, true, epoch)
							clear(raw)
							raw = nil
							if err == nil {
								if err = lease.check(storage); err == nil {
									raw, err = session.MFAManage(opctx, "webauthn", r.Input, map[string]json.RawMessage{"id": id, "name": name, "deviceResponse": response}, r.Confirmed, persist)
								}
							}
							clear(response)
						}
					}
					clear(id)
					clear(name)
				} else {
					raw, err = session.MFAManage(opctx, r.Operation, r.Input, r.Fields, r.Confirmed, persist)
				}
			}
			summary := ""
			if err == nil {
				summary, err = authenticationSummary(raw)
			}
			clear(raw)
			complete(func() {
				a.componentBusy(false)
				if a.epoch == epoch && a.authManagement == f {
					f.Complete(scope, epoch, r.Sequence, summary, err)
				}
			})
		}()
	}
	a.authManagement = f
	a.category, a.showSettings = "mfa", false
}
