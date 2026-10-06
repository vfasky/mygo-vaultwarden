// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type vaultSession interface {
	Sync(context.Context) (vaultwarden.SyncResult, error)
	Close()
}

// Only a successful publication by this session grants its next CAS revision.
// Reading current state is observational; it never renews write authority.
func (a *app) sessionOwnsSnapshot() bool {
	return a.session != nil && a.sessionRevision != "" && a.snapshot != nil &&
		a.snapshot.Available && a.snapshot.Revision == a.sessionRevision &&
		a.liveScope != nil && a.snapshot.Scope != nil && *a.liveScope == *a.snapshot.Scope
}

func (a *app) observeSnapshot(state *snapshotStatus) {
	a.snapshot = state
	if state == nil || state.Revision != a.itemsRevision {
		a.items = nil
		a.itemsRevision = ""
		a.selectedID = ""
	}
	if a.session != nil && !a.sessionOwnsSnapshot() {
		a.stopNetwork()
	}
}

func (a *app) syncFailed(reply storageReply, err error) {
	if reply.State != nil {
		a.observeSnapshot(reply.State)
	}
	var storageErr *storageFailure
	if errors.As(err, &storageErr) || errors.Is(err, vaultwarden.ErrExpired) || errors.Is(err, vaultwarden.ErrIdentity) {
		a.stopNetwork()
	}
	a.status = err.Error()
	if storageErr != nil {
		a.status += " 请重新登录后再同步。"
	}
}

func (a *app) stopNetwork() {
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	nativeCancelSecretInput()
	if a.session != nil {
		session := a.session
		a.session = nil
		go session.Close()
	}
	a.liveScope = nil
	a.sessionRevision = ""
	a.items = nil
	a.itemsRevision = ""
	a.selectedID = ""
}

func (a *app) syncVault(login bool) {
	if a.pending != 0 || a.snapshot == nil {
		return
	}
	server, email := a.serverURL, vaultwarden.NormalizeEmail(a.email)
	if login {
		canonical, err := vaultwarden.CanonicalServer(server)
		if err != nil {
			a.status = err.Error()
			return
		}
		if !strings.Contains(email, "@") || len(email) > 1024 {
			a.status = "请输入登录邮箱。"
			return
		}
		server = canonical
		a.stopNetwork()
	} else if a.session == nil {
		a.status = "请先登录。重启或锁定后仍可离线解锁，但在线同步需要重新登录。"
		return
	} else if !a.sessionOwnsSnapshot() {
		a.stopNetwork()
		a.status = vaultwarden.ErrIdentity.Error()
		return
	}
	existing := a.session
	deviceID := a.deviceID
	expected := a.snapshot.Revision
	if !login {
		expected = a.sessionRevision
	}
	a.epoch++
	epoch := a.epoch
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.pending++
	a.status = "正在登录并同步…"
	if !login {
		a.status = "正在同步只读密码库…"
	}
	go func() {
		var session vaultSession = existing
		var result vaultwarden.SyncResult
		var metadata []displayCredential
		var reply storageReply
		var workErr error
		if login {
			// Revoke the previous account before prompting, including offline copies.
			reply = callStorage(storageRequest{Operation: "logout", ExpectedRevision: expected})
			if !reply.OK || reply.State == nil {
				workErr = reply.failure()
				if reply.OK {
					workErr = (storageReply{Code: "invalid_reply", Message: "未能确认本机账号撤销结果。"}).failure()
				}
			} else {
				expected = reply.State.Revision
			}
			if workErr == nil && ctx.Err() == nil {
				secret, err := nativeSecretInput(0, "服务器："+server+"\n账号："+email)
				if err != nil {
					workErr = vaultwarden.ErrCancelled
				} else {
					client, err := vaultwarden.NewClient(server, deviceID)
					if err != nil {
						workErr = err
					} else {
						var loggedIn *vaultwarden.Session
						loggedIn, workErr = client.Login(ctx, email, secret, func() ([]byte, error) {
							if ctx.Err() != nil {
								return nil, vaultwarden.ErrCancelled
							}
							return nativeSecretInput(1, "服务器："+server+"\n输入验证器中的 6 位 TOTP 验证码。")
						})
						if workErr == nil {
							session = loggedIn
						}
					}
					clear(secret)
				}
			}
		}
		if workErr == nil && ctx.Err() != nil {
			workErr = vaultwarden.ErrCancelled
		}
		if workErr == nil {
			result, workErr = session.Sync(ctx)
		}
		if workErr == nil && ctx.Err() == nil {
			metadata = make([]displayCredential, 0, len(result.Credentials))
			for _, item := range result.Credentials {
				metadata = append(metadata, displayCredential{ID: item.ID, Title: item.Title, Username: item.Username, URL: item.URL})
			}
			reply = callStorage(storageRequest{Operation: "publishVault", ExpectedRevision: expected, Scope: &result.Scope, Credentials: result.Credentials})
			if !reply.OK {
				workErr = reply.failure()
			} else if reply.State == nil || !reply.State.Available || reply.State.Scope == nil || *reply.State.Scope != result.Scope || reply.State.Revision == "" || reply.State.Revision == expected {
				workErr = (storageReply{Code: "invalid_reply", Message: "未能确认本次快照的发布版本。"}).failure()
			}
		}
		// No password-bearing results live in the UI model.
		for i := range result.Credentials {
			result.Credentials[i].Password = ""
		}
		result.Credentials = nil
		if errors.Is(workErr, vaultwarden.ErrExpired) || errors.Is(workErr, vaultwarden.ErrIdentity) {
			reply = callStorage(storageRequest{Operation: "logout", ExpectedRevision: expected})
			if session != nil {
				session.Close()
			}
		}
		if workErr == nil && ctx.Err() != nil {
			workErr = vaultwarden.ErrCancelled
		}
		a.window.Update(func() {
			a.pending--
			if a.epoch != epoch {
				if login && session != nil {
					go session.Close()
				}
				return
			}
			a.cancel = nil
			cancel()
			if workErr != nil {
				if login && session != nil {
					go session.Close()
				}
				a.syncFailed(reply, workErr)
				return
			}
			a.snapshot = reply.State
			a.session = session
			a.liveScope = &result.Scope
			a.sessionRevision = reply.State.Revision
			a.items = metadata
			a.itemsRevision = a.snapshot.Revision
			a.showSettings = false
			s := result.Summary
			a.status = fmt.Sprintf("已同步 %d 条个人登录条目。排除：组织 %d、其他类型 %d、需再次输入主密码 %d；未支持/禁用的网址规则 %d。", s.Logins, s.Organizations, s.OtherTypes, s.Reprompt, s.UnsupportedURIs)
		})
	}()
}
