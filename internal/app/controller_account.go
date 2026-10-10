// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) openAccount()      { a.openAccountWith(a.dispatchUI, a.storageCall, false) }
func (a *app) openRegistration() { a.openAccountWith(a.dispatchUI, a.storageCall, true) }
func (a *app) openAccountWith(dispatch func(func()), storage func(storageRequest) storageReply, registration bool) {
	if a.pending != 0 {
		return
	}
	var session *vaultwarden.Session
	var scope vaultwarden.Scope
	if registration {
		server, err := vaultwarden.CanonicalServer(a.serverURL)
		if err != nil {
			a.status = err.Error()
			return
		}
		scope.Server = server
	} else {
		if !a.sessionOwnsSnapshot() {
			return
		}
		var ok bool
		session, ok = a.session.(*vaultwarden.Session)
		if !ok {
			return
		}
		scope = *a.liveScope
	}
	client, err := vaultwarden.NewClient(scope.Server, a.deviceID)
	if err != nil {
		a.status = err.Error()
		return
	}
	a.advanceEpoch()
	epoch := a.epoch
	storage = a.routeStorage(storage, epoch)
	var lease *controllerLease
	if !registration {
		lease = a.newControllerLease()
		if lease == nil {
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.componentCancel = cancel
	vault := a.vault
	f := newAccountForm(scope, epoch, nil)
	f.email = a.email
	f.openRotationPreparation = func(id string, deleted bool) {
		a.advanceEpoch()
		a.category = "personal"
		if deleted {
			a.category = "trash"
		}
		a.openCipherEditor(id, 0)
	}
	if registration {
		f.mode = "register"
		f.modes = []string{"register"}
	} else {
		f.modes = []string{"profile", "password", "email", "kdf", "api-key", "security-stamp", "purge", "delete", "rotate-user-key"}
	}
	f.submit = func(r accountFormRequest) {
		if a.epoch != epoch || a.accountForm != f {
			r.Close()
			return
		}
		a.pending++
		go func() {
			defer r.Close()
			opctx, done := context.WithTimeout(ctx, 5*time.Minute)
			defer done()
			var err error
			var plan *vaultwarden.AccountChangePlan
			var recipients vaultwarden.RotationTrustRequirements
			var result vaultwarden.AccountChangeResult
			var key vaultwarden.AccountAPIKey
			var registered vaultwarden.AccountRegistrationVerification
			var journal *accountRecoveryStorage
			persist := func(cp vaultwarden.SessionCheckpoint) error { return lease.persist(cp, storage) }
			if !registration {
				err = lease.check(storage)
			}
			if err == nil {
				switch r.Operation {
				case "register-send":
					registered, err = client.AccountSendRegistrationEmail(opctx, r.Email, r.Name)
				case "register-finish":
					err = client.AccountRegister(opctx, r.Email, r.NewPassword, r.KDF, r.Hint, r.Token)
				case "password-hint":
					err = client.AccountPasswordHint(opctx, r.Email)
				default:
					if session == nil {
						err = vaultwarden.ErrPermission
						break
					}
					switch r.Operation {
					case "profile":
						_, err = session.AccountUpdateProfile(opctx, r.Name, persist)
					case "avatar":
						color := r.Avatar
						errColor := &color
						if color == "" {
							errColor = nil
						}
						_, err = session.AccountUpdateAvatar(opctx, errColor, persist)
					case "verify-email":
						err = session.AccountSendVerificationEmail(opctx, persist)
					case "verify-email-token":
						err = client.AccountVerifyEmailToken(opctx, scope.Account, r.Token)
					case "email-token":
						err = session.AccountRequestEmailChange(opctx, r.Password, r.Email, persist)
					case "api-key", "rotate-api-key":
						key, err = session.AccountAPIKey(opctx, vaultwarden.AccountSensitiveInput{Password: r.Password, OTP: r.OTP}, r.Operation == "rotate-api-key", r.Confirmation == r.Operation, persist)
					case "rotation-recipients":
						recipients, err = session.AccountRotationTrustRequirements(opctx, vault, persist)
					case "prepare-rotate-user-key":
						plan, err = session.PrepareVerifiedAccountRotation(opctx, vault, r.Password, r.RotationTrust, persist)
					case "prepare-password", "prepare-email", "prepare-kdf":
						plan, err = session.PrepareAccountCredentials(opctx, vault, vaultwarden.AccountChangeKind(strings.TrimPrefix(r.Operation, "prepare-")), r.Password, r.NewPassword, r.Email, r.KDF, r.Hint, r.Token, persist)
					case "prepare-security-stamp", "prepare-purge", "prepare-delete":
						plan, err = session.PrepareAccountDestructive(opctx, vault, vaultwarden.AccountChangeKind(strings.TrimPrefix(r.Operation, "prepare-")), vaultwarden.AccountSensitiveInput{Password: r.Password, OTP: r.OTP}, persist)
					case "commit":
						defer r.Plan.Close()
						result, err = session.CommitAccountChange(opctx, r.Plan, r.Confirmation, persist, func(record vaultwarden.AccountRecovery) error {
							prior, active := lease.state()
							if !active || record.OldUnlock == nil {
								return vaultwarden.ErrCancelled
							}
							var e error
							journal, e = newAccountRecoveryStorage(&prior, epoch, a.workerEpoch.Load, record.OldUnlock.Key, storage)
							if e != nil {
								return e
							}
							return journal.Begin(record)
						})
						// Persist independently of UI adoption; a revoked epoch deliberately
						// leaves the already durable prepared barrier for explicit Query.
						if journal != nil {
							resultErr := journal.Result(result)
							if resultErr != nil && err == nil {
								err = resultErr
							}
							journal.Close()
						}
					default:
						err = vaultwarden.ErrValidation
					}
				}
			}
			var state *snapshotStatus
			if journal != nil {
				reply := storage(storageRequest{Operation: "status"})
				state = reply.State
			}
			dispatch(func() {
				a.componentBusy(false)
				if a.epoch != epoch || a.accountForm != f {
					plan.Close()
					return
				}
				if cp := lease.takeCheckpoint(); cp != nil {
					if !a.adoptSessionCheckpoint(cp) {
						plan.Close()
						a.stopNetwork()
						a.status = vaultwarden.ErrIdentity.Error()
						return
					}
					if journal == nil {
						plan.Close()
						a.advanceEpoch()
						a.status = "登录凭据已更新，请重新打开账号页面。"
						return
					}
				}
				if journal != nil {
					f.completed(scope, epoch, r.Sequence, result, err)
					message := f.status
					a.stopNetwork()
					if state != nil {
						a.snapshot = state
					}
					a.status = message + " 请进入账号恢复以核验，原恢复记录不会因普通登录或同步清除。"
					return
				}
				switch {
				case r.Operation == "register-send":
					f.registration(scope, epoch, r.Sequence, registered, err)
				case strings.HasPrefix(r.Operation, "prepare-"):
					f.prepared(scope, epoch, r.Sequence, plan, err)
					var preparations *vaultwarden.RotationCipherPreparationError
					if errors.As(err, &preparations) {
						f.rotationPreparations = append([]vaultwarden.RotationCipherPreparation(nil), preparations.Readiness.Preparations...)
						f.status = "先升级旧附件、核验新旧文件并明确删除原件，再同步后重新准备轮换。"
					}
					if errors.Is(err, vaultwarden.ErrRotationCompatibility) {
						f.status = err.Error()
					}
				case r.Operation == "rotation-recipients":
					if f.completed(scope, epoch, r.Sequence, result, err) && err == nil {
						f.rotationRequirements = recipients
						f.status = "请从可信独立渠道取得并核对以上公钥，再准备轮换。"
					}
				case r.Operation == "api-key" || r.Operation == "rotate-api-key":
					f.apiKeyCompleted(scope, epoch, r.Sequence, key, err)
				default:
					f.completed(scope, epoch, r.Sequence, result, err)
					if err == nil && r.Operation == "register-finish" {
						f.status = "注册已完成，请返回登录并同步。"
					}
				}
			})
		}()
	}
	a.accountForm = f
	if !registration {
		a.category, a.showSettings = "account", false
	}
}
