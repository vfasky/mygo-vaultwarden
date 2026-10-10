// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func authenticationSummary(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "请求已完成，请重新读取设置核验。", nil
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
		lines = append(lines, fmt.Sprintf("已启用：%t", *data.Enabled))
	}
	for _, field := range []struct{ label, value string }{{"验证器密钥", data.Key}, {"邮箱", data.Email}, {"恢复码", data.RecoveryCode}, {"Duo 主机", data.Host}, {"Duo 客户端 ID", data.ClientID}, {"Duo 客户端秘密", data.ClientSecret}} {
		if field.value != "" {
			lines = append(lines, field.label+"："+field.value)
		}
	}
	for _, key := range data.Keys {
		lines = append(lines, fmt.Sprintf("安全密钥 %d：%s", key.ID, key.Name))
	}
	for _, provider := range data.Data {
		lines = append(lines, fmt.Sprintf("验证方式 %d，已启用：%t", provider.Type, provider.Enabled))
	}
	if len(lines) == 0 {
		return "服务器已返回；没有已启用的验证方式或额外设置。", nil
	}
	return strings.Join(lines, "\n"), nil
}
func (a *app) openAuthenticationManagement() {
	a.openAuthenticationManagementWith(a.dispatchUI, a.storageCall)
}
func (a *app) openAuthenticationManagementWith(dispatch func(func()), storage func(storageRequest) storageReply) {
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
	platform := NewAuthenticationPlatform(a.window)
	f := newAuthManagementForm(scope, epoch, nil)
	complete := a.componentDispatch(session, lease, epoch, dispatch)
	f.submit = func(r authManagementRequest) {
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
					f.complete(scope, epoch, r.Sequence, summary, err)
				}
			})
		}()
	}
	a.authManagement = f
	a.category, a.showSettings = "mfa", false
}
