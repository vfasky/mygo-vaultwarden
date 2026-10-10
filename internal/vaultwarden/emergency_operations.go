// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"net/mail"
	"reflect"
	"strings"
)

type EmergencyRequest struct {
	Action, ID, Email, Token, TrustedPublicKey string
	Trusted                                    bool
	Type, WaitTimeDays                         int
}

func recoveryWrapUserKey(public string, key []byte) (string, error) {
	pub, err := decodeRecoveryPublicKey(public)
	if err != nil {
		return "", err
	}
	if len(key) != 64 {
		return "", ErrEncryption
	}
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	if err != nil {
		return "", ErrEncryption
	}
	return "3." + base64.StdEncoding.EncodeToString(encrypted), nil
}
func emergencyFind(rows []EmergencyContact, id string) (EmergencyContact, error) {
	for _, c := range rows {
		if c.ID == id {
			return c, nil
		}
	}
	return EmergencyContact{}, ErrIdentity
}
func (s *Session) emergencyPublicLocked(ctx context.Context, id string, persist func(SessionCheckpoint) error, guard func() error) (string, error) {
	if !validObjectID(id) {
		return "", ErrIdentity
	}
	body, err := s.recoveryReadLocked(ctx, "/api/users/"+id+"/public-key", persist, guard)
	if err != nil {
		return "", err
	}
	var r struct{ UserID, PublicKey string }
	if json.Unmarshal(body, &r) != nil || r.UserID != id {
		return "", ErrIdentity
	}
	if _, err = decodeRecoveryPublicKey(r.PublicKey); err != nil {
		return "", err
	}
	return r.PublicKey, nil
}

// PrepareEmergencyOperation reads authoritative state. TrustedPublicKey must be
// obtained via an independent trusted channel, never copied automatically from
// a network reply. Token is opaque and sent in JSON only; JWT claims authorize
// nothing locally. The server validates signature, recipient, expiry and ID.
func (s *Session) PrepareEmergencyOperation(ctx context.Context, vault *VaultData, r EmergencyRequest, persist func(SessionCheckpoint) error) (*RecoveryPlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return nil, err
	}
	defer data.close()
	epoch, revision := s.authorizationEpoch, s.authorizationRevision
	guard := s.recoveryGuardLocked(epoch, revision)
	path := "/api/emergency-access/"
	method := "POST"
	target := s.account
	var payload any = struct{}{}
	var selected EmergencyContact
	impact := i18n.T("此操作会通知对方并改变紧急访问授权。服务器可能先保存再发送邮件；未知结果必须核对，不能重试。")
	switch r.Action {
	case "invite":
		email := strings.ToLower(strings.TrimSpace(r.Email))
		address, e := mail.ParseAddress(email)
		if e != nil || address.Address != email || email == s.email || r.Type < 0 || r.Type > 1 || r.WaitTimeDays < 0 || r.WaitTimeDays > 365 {
			return nil, ErrValidation
		}
		path += "invite"
		payload = struct {
			Email        string `json:"email"`
			Type         int    `json:"type"`
			WaitTimeDays int    `json:"waitTimeDays"`
		}{email, r.Type, r.WaitTimeDays}
	case "accept":
		if !validObjectID(r.ID) || len(r.Token) == 0 || len(r.Token) > 16384 {
			return nil, ErrValidation
		}
		// If already in the granted list, do not replay an accepted invitation.
		rows, e := s.emergencyContactsLocked(ctx, false, persist, guard)
		if e != nil {
			return nil, e
		}
		for _, c := range rows {
			if c.ID == r.ID {
				return nil, ErrConflict
			}
		}
		path += r.ID + "/accept"
		payload = struct {
			Token string `json:"token"`
		}{r.Token}
	default:
		if !validObjectID(r.ID) {
			return nil, ErrValidation
		}
		rows, e := s.emergencyContactsLocked(ctx, r.Trusted, persist, guard)
		if e != nil {
			return nil, e
		}
		selected, e = emergencyFind(rows, r.ID)
		if e != nil {
			return nil, e
		}
		if !EmergencyActionAllowed(selected, r.Trusted, r.Action) {
			return nil, ErrPermission
		}
		if !r.Trusted {
			target = selected.GrantorID
		}
		path += r.ID + "/" + r.Action
		switch r.Action {
		case "confirm":
			public, e := s.emergencyPublicLocked(ctx, selected.GranteeID, persist, guard)
			if e != nil {
				return nil, e
			}
			if public != r.TrustedPublicKey {
				return nil, ErrIdentity
			}
			wrapped, e := recoveryWrapUserKey(public, s.key)
			if e != nil {
				return nil, e
			}
			payload = struct {
				Key string `json:"key"`
			}{wrapped}
			impact = i18n.T("确认后将把当前用户密钥加密给此受托人。获批后对方可以查看个人密码库，或接管账号。请独立核对公钥、对象、类型及等待天数。")
		case "update":
			if r.Type < 0 || r.Type > 1 || r.WaitTimeDays < 0 || r.WaitTimeDays > 365 {
				return nil, ErrValidation
			}
			path = "/api/emergency-access/" + r.ID
			method = "PUT"
			payload = struct {
				Type         int `json:"type"`
				WaitTimeDays int `json:"waitTimeDays"`
			}{r.Type, r.WaitTimeDays}
		case "delete":
			path = "/api/emergency-access/" + r.ID
			method = "DELETE"
		case "reinvite", "initiate", "approve", "reject":
		default:
			return nil, ErrValidation
		}
	}
	p, err := s.recoveryPlanLocked("emergency-"+r.Action, method, path, r.ID, target, impact, payload)
	if err != nil {
		return nil, err
	}
	// Bind to the pre-read epoch, never absorb a changed checkpoint silently.
	p.epoch = epoch
	p.record.PreviousRevision = revision
	p.record.TargetEmail = s.email
	p.record.EmergencyType, p.record.WaitTimeDays = selected.Type, selected.WaitTimeDays
	p.record.CounterpartyID, p.record.CounterpartyEmail = selected.GranteeID, selected.Email
	if !r.Trusted && selected.GrantorID != "" {
		p.record.CounterpartyID = selected.GrantorID
		p.record.TargetEmail = selected.Email
	}
	if r.Action == "invite" || r.Action == "update" {
		p.record.EmergencyType, p.record.WaitTimeDays = r.Type, r.WaitTimeDays
	}
	if r.Action == "invite" {
		p.record.CounterpartyEmail = strings.ToLower(strings.TrimSpace(r.Email))
	}
	trustedPublic := r.TrustedPublicKey
	action, id, trusted := r.Action, r.ID, r.Trusted
	p.revalidate = func(ctx context.Context, persist func(SessionCheckpoint) error, guard func() error) error {
		if action == "invite" {
			return guard()
		}
		rows, e := s.emergencyContactsLocked(ctx, trusted && action != "accept", persist, guard)
		if e != nil {
			return e
		}
		if action == "accept" {
			for _, c := range rows {
				if c.ID == id {
					return ErrConflict
				}
			}
			return nil
		}
		now, e := emergencyFind(rows, id)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(now, selected) {
			return ErrConflict
		}
		if action == "confirm" {
			pub, e := s.emergencyPublicLocked(ctx, now.GranteeID, persist, guard)
			if e != nil {
				return e
			}
			if pub != trustedPublic {
				return ErrConflict
			}
		}
		return nil
	}
	return p, nil
}
