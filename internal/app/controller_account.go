// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/localstore"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/account"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func (a *app) openAccount()      { a.openAccountWith(a.dispatchUI, a.storageCall, false) }
func (a *app) openRegistration() { a.openAccountWith(a.dispatchUI, a.storageCall, true) }

// openPasswordHint asks the server to email the master password hint; it
// needs no session, as registration does.
func (a *app) openPasswordHint() {
	prior := a.accountForm
	a.openRegistration()
	if f := a.accountForm; f != nil && f != prior {
		f.Mode, f.Modes = "hint", []string{"hint"}
	}
}
func (a *app) openAccountWith(dispatch func(func()), storage func(localstore.Request) localstore.Reply, registration bool) {
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
	f := account.NewForm(scope, epoch, nil)
	f.Email = a.email
	f.OpenRotationPreparation = func(id string, deleted bool) {
		a.advanceEpoch()
		a.category = "personal"
		if deleted {
			a.category = "trash"
		}
		a.openCipherEditor(id, 0)
	}
	if registration {
		f.Mode = "register"
		f.Modes = []string{"register"}
	} else {
		f.Modes = []string{"profile", "password", "email", "kdf", "api-key", "security-stamp", "purge", "delete", "rotate-user-key"}
	}
	f.Submit = func(r account.FormRequest) {
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
			var journal *localstore.AccountRecoveryStorage
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
							journal, e = localstore.NewAccountRecoveryStorage(&prior, epoch, a.workerEpoch.Load, record.OldUnlock.Key, storage)
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
			var state *localstore.SnapshotStatus
			if journal != nil {
				reply := storage(localstore.Request{Operation: "status"})
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
						a.status = i18n.T("account.form.status_credentials_updated")
						return
					}
				}
				if journal != nil {
					f.Completed(scope, epoch, r.Sequence, result, err)
					message := f.Status
					a.stopNetwork()
					if state != nil {
						a.snapshot = state
					}
					a.status = i18n.Tf("account.recovery.status_verification_required", message)
					return
				}
				switch {
				case r.Operation == "register-send":
					f.Registration(scope, epoch, r.Sequence, registered, err)
				case strings.HasPrefix(r.Operation, "prepare-"):
					f.Prepared(scope, epoch, r.Sequence, plan, err)
					var preparations *vaultwarden.RotationCipherPreparationError
					if errors.As(err, &preparations) {
						f.RotationPreparations = append([]vaultwarden.RotationCipherPreparation(nil), preparations.Readiness.Preparations...)
						f.Status = i18n.T("account.rotation.status_upgrade_attachments")
					}
					if errors.Is(err, vaultwarden.ErrRotationCompatibility) {
						f.Status = err.Error()
					}
				case r.Operation == "rotation-recipients":
					if f.Completed(scope, epoch, r.Sequence, result, err) && err == nil {
						f.RotationRequirements = recipients
						f.Status = i18n.T("account.rotation.status_verify_public_keys")
					}
				case r.Operation == "api-key" || r.Operation == "rotate-api-key":
					f.APIKeyCompleted(scope, epoch, r.Sequence, key, err)
				case r.Operation == "password-hint":
					// Servers answer alike whether or not the address has an
					// account, so the result never says which.
					if f.Completed(scope, epoch, r.Sequence, result, err) {
						f.Status = i18n.T("account.hint.status_sent")
						if err != nil {
							f.Status = i18n.T("account.hint.err_failed")
						}
					}
				default:
					f.Completed(scope, epoch, r.Sequence, result, err)
					if err == nil && r.Operation == "register-finish" {
						// Back to the login page, ready for the new account.
						email := f.Email
						a.advanceEpoch()
						a.email, a.masterPassword = email, ""
						a.status = i18n.T("account.register.status_created")
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
