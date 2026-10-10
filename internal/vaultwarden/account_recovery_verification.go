// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden/vaultcrypto"
	"reflect"
	"sort"
	"strings"
)

var ErrRecoveryUnverified = errors.New(i18n.T("恢复核验尚未完成；保留原记录与旧新材料，不重放请求"))

type AccountRecoveryEvidenceKind string

const (
	RecoveryEvidenceNoDispatch      AccountRecoveryEvidenceKind = "verified-client-nondispatch-current-authentication"
	RecoveryEvidenceCredentials     AccountRecoveryEvidenceKind = "verified-credential-change"
	RecoveryEvidenceOrderedRotation AccountRecoveryEvidenceKind = "verified-ordered-rotation"
)

type AccountRecoveryVerification struct {
	Kind                   AccountRecoveryEvidenceKind
	ExternalCurrentChanges []string
	Ready                  bool
	AuthorityEvidence      []string
	ResourceEvidence       []string
	Issues                 []string
	CipherResources        RotationCipherVerification
	SendResources          SendRotationVerification
}

// SyncVerifiedAccountRecovery owns the real fresh Sync and key relationship
// checks. It does not accept a caller-created SyncResult or a UI success flag.
// phase must come from the authenticated journal Query with the same operation
// binding. A UI flag, missing Result, HTTP failure or zero result cannot supply
// not-dispatched. The storage phase transition separately enforces this origin.
// Returned secret-bearing SyncResult must be cleared even on verification error.
func (s *Session) SyncVerifiedAccountRecovery(ctx context.Context, record AccountRecovery, phase string, persist func(SessionCheckpoint) error) (SyncResult, AccountRecoveryVerification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	report := AccountRecoveryVerification{}
	ctx, done, err := s.beginOperationLocked(ctx)
	if err != nil {
		return SyncResult{}, report, err
	}
	defer done()
	fresh, err := s.syncLocked(ctx, persist)
	if err != nil {
		return fresh, report, err
	}
	reject := func(reason string) (SyncResult, AccountRecoveryVerification, error) {
		report.Issues = append(report.Issues, reason)
		return fresh, report, ErrRecoveryUnverified
	}
	if record.Version != 1 || record.Scope != fresh.Scope || record.OperationID == "" || record.OldUnlock == nil || len(record.OldUnlock.Key) != 32 || s.passwordUnlock == nil || s.runtimeOnly {
		return reject(i18n.T("身份或持久密码材料不匹配"))
	}
	var old savedSession
	if strictJSON(record.OldSession) != nil || json.Unmarshal(record.OldSession, &old) != nil || old.Version != 1 || len(old.UserKey) != 64 || old.Scope != record.Scope || old.PasswordUnlock == nil || len(old.PasswordUnlock.Key) != 32 || old.PasswordUnlock.Config != record.OldUnlock.Config || subtle.ConstantTimeCompare(old.PasswordUnlock.Key, record.OldUnlock.Key) != 1 || old.Email != record.OldUnlock.Config.Email {
		return reject(i18n.T("原认证材料不可核验"))
	}
	defer clear(old.UserKey)
	if old.PasswordUnlock != nil {
		defer clear(old.PasswordUnlock.Key)
	}
	var prior VaultData
	if strictJSON(record.OldVault) != nil || json.Unmarshal(record.OldVault, &prior) != nil || prior.Scope != record.Scope || (prior.Version != 1 && prior.Version != 2) {
		return reject(i18n.T("原完整密码库不可核验"))
	}
	var previous, current map[string]json.RawMessage
	if json.Unmarshal(prior.Sync, &previous) != nil || json.Unmarshal(fresh.Vault.Sync, &current) != nil {
		return reject(i18n.T("完整资源数据不可核验"))
	}
	var oldProfile, newProfile struct{ ID, Key, PrivateKey, Email string }
	if json.Unmarshal(previous["profile"], &oldProfile) != nil || json.Unmarshal(current["profile"], &newProfile) != nil || oldProfile.ID != record.Scope.Account || oldProfile.Key != old.WrappedKey || newProfile.Key != s.wrapped || newProfile.ID != record.Scope.Account {
		return reject(i18n.T("权威账号包装不匹配"))
	}
	unchangedAttempt := phase == "not-dispatched"
	if record.Kind != AccountRotateKey || unchangedAttempt {
		if subtle.ConstantTimeCompare(old.UserKey, s.key) != 1 {
			return reject(i18n.T("非用户密钥轮换操作改变了实际user key"))
		}
		expectedWrapper := record.NewWrappedKey
		if expectedWrapper == "" || unchangedAttempt {
			expectedWrapper = old.WrappedKey
		}
		if s.wrapped != expectedWrapper {
			return reject(i18n.T("尚未观察到本次凭据请求的权威包装"))
		}
		if unchangedAttempt && (old.PasswordUnlock.Config != s.passwordUnlock.Config || subtle.ConstantTimeCompare(old.PasswordUnlock.Key, s.passwordUnlock.Key) != 1) {
			return reject(i18n.T("原主密码/KDF授权关系不匹配"))
		}
		if !unchangedAttempt && record.NewUnlock != nil && (record.NewUnlock.Config != s.passwordUnlock.Config || subtle.ConstantTimeCompare(record.NewUnlock.Key, s.passwordUnlock.Key) != 1) {
			return reject(i18n.T("新邮箱/KDF/密码包装未匹配"))
		}
		if record.Kind == AccountDelete && !unchangedAttempt {
			return reject(i18n.T("删除账号须使用已确认删除的专用本机清理流程"))
		}
		if record.Kind == AccountSecurityStamp && phase != "confirmed" && !unchangedAttempt {
			return reject(i18n.T("注销会话结果未知，不能从一次新登录推断旧会话已全部撤销"))
		}
		if record.Kind == AccountPurge && !unchangedAttempt {
			if !emptyPersonalRecoveryInventory(current["ciphers"]) || !jsonEmptyArray(current["folders"]) {
				return reject(i18n.T("个人条目或文件夹尚未清空"))
			}
			if !sameOrganizationRecoveryInventory(previous["ciphers"], current["ciphers"]) {
				return reject(i18n.T("组织资源发生外部变化"))
			}
		} else if !unchangedAttempt {
			if !AccountRotationCipherInventoryEqual(previous["ciphers"], current["ciphers"]) || !rawJSONEqual(previous["folders"], current["folders"]) {
				return reject(i18n.T("条目或文件夹发生变化，须保留恢复记录核对"))
			}
		}
		if !unchangedAttempt && !rawJSONEqual(previous["sends"], current["sends"]) {
			return reject(i18n.T("Send资源发生变化"))
		}
		if !unchangedAttempt && oldProfile.PrivateKey != newProfile.PrivateKey {
			return reject(i18n.T("账户私钥包装发生外部变化"))
		}
		if unchangedAttempt {
			private, privateErr := accountPrivateKey(current["profile"], s.key)
			if privateErr != nil {
				return reject(i18n.T("当前账户RSA私钥不可核验"))
			}
			publicDER, marshalErr := x509.MarshalPKIXPublicKey(&private.PublicKey)
			clearAccountPrivateKey(private)
			status, body, readErr := s.authenticatedLocked(ctx, "GET", "/api/accounts/keys", "", "", persist)
			var keys struct{ Key, PrivateKey, PublicKey string }
			if readErr != nil || status != 200 || strictJSON(body) != nil || json.Unmarshal(body, &keys) != nil || keys.Key != s.wrapped || keys.PrivateKey != newProfile.PrivateKey {
				return reject(i18n.T("当前权威账户密钥不匹配"))
			}
			expectedDER, decodeErr := base64.StdEncoding.Strict().DecodeString(keys.PublicKey)
			if marshalErr != nil || decodeErr != nil || !bytes.Equal(publicDER, expectedDER) {
				return reject(i18n.T("当前账户RSA公私钥不一致"))
			}
		}
		if _, err = AnalyzeAccountRotationCipherResources(ctx, AccountRotationInput{Scope: fresh.Scope, Sync: fresh.Vault.Sync, OldUserKey: s.key}); err != nil {
			return reject(i18n.T("完整cipher/folder加密字段未通过核验"))
		}
		rows, e := sendRotationRows(fresh.Vault.Sync, fresh.Scope)
		if e != nil {
			return reject(i18n.T("完整Send清单未通过核验"))
		}
		for _, row := range rows {
			_, wire, e := sendRotationOwner(row)
			if e != nil {
				return reject(i18n.T("Send结构未通过核验"))
			}
			seed, e := sendRotationSeed(wire, s.key)
			clear(seed)
			if e != nil {
				return reject(i18n.T("Send种子包装未通过核验"))
			}
		}
		report.AuthorityEvidence = []string{"fresh-login-and-sync: expected account/wrapper/unlock configuration; unchanged authenticated user key"}
		report.ResourceEvidence = []string{"cipher/folder/Send inventories and encrypted fields verified; unchanged owner key and ciphertext (binary files were not downloaded)"}
		if unchangedAttempt {
			report.Kind = RecoveryEvidenceNoDispatch
			for _, name := range []string{"ciphers", "folders", "sends"} {
				same := rawJSONEqual(previous[name], current[name])
				if name == "ciphers" {
					same = AccountRotationCipherInventoryEqual(previous[name], current[name])
				}
				if !same {
					report.ExternalCurrentChanges = append(report.ExternalCurrentChanges, name)
				}
			}
			report.AuthorityEvidence = append(report.AuthorityEvidence, "authenticated journal records no transport dispatch; fresh login proves the original key/wrapper; no old Session restored")
			report.ResourceEvidence = []string{"complete current personal cipher/folder/Send cryptography checked under the original user key; authoritative current organization policy/identity chain; external current changes allowed; hidden recovery wrappers not claimed read-back verified; binary files not downloaded"}
		} else {
			report.Kind = RecoveryEvidenceCredentials
		}
		if err = s.completeRecoveryVerificationLocked(ctx, &fresh); err != nil {
			return fresh, report, err
		}
		report.Ready = true
		return fresh, report, nil
	}
	evidence := record.RotationEvidence
	if evidence == nil || evidence.Version != 1 {
		return reject(i18n.T("缺少本次轮换的已认证版本与收件人证据"))
	}
	version, commit, e := s.client.rotationCompatibility(ctx)
	if e != nil || version != evidence.ServerVersion || commit != evidence.GitHash {
		return reject(i18n.T("无法确认固定Vaultwarden轮换写入顺序"))
	}
	hash := sha256.Sum256(record.Request)
	if hex.EncodeToString(hash[:]) != evidence.RequestDigest {
		return reject(i18n.T("轮换证据不属于原始单次请求"))
	}
	var request AccountRotationRequest
	if strictJSON(record.Request) != nil || json.Unmarshal(record.Request, &request) != nil || len(record.NewUserKey) != 64 || subtle.ConstantTimeCompare(record.NewUserKey, old.UserKey) == 1 || subtle.ConstantTimeCompare(s.key, record.NewUserKey) != 1 {
		return reject(i18n.T("本次新user key的唯一性或权威关系不成立"))
	}
	if record.NewWrappedKey == "" || request.Unlock.Master.Key != record.NewWrappedKey || s.wrapped != record.NewWrappedKey || s.wrapped == old.WrappedKey || request.Keys.PrivateKey == "" || request.Keys.PrivateKey != newProfile.PrivateKey || request.Keys.PrivateKey == oldProfile.PrivateKey {
		return reject(i18n.T("缺少本次唯一最终双包装写入见证"))
	}
	if old.PasswordUnlock == nil || old.PasswordUnlock.Config != s.passwordUnlock.Config || subtle.ConstantTimeCompare(old.PasswordUnlock.Key, s.passwordUnlock.Key) != 1 {
		return reject(i18n.T("用户key轮换意外改变主密码/KDF"))
	}
	status, raw, e := s.authenticatedLocked(ctx, "GET", "/api/accounts/keys", "", "", persist)
	var keys struct{ Key, PrivateKey, PublicKey string }
	if e != nil || status != 200 || strictJSON(raw) != nil || json.Unmarshal(raw, &keys) != nil || keys.Key != s.wrapped || keys.PrivateKey != request.Keys.PrivateKey || keys.PublicKey != request.Keys.PublicKey {
		return reject(i18n.T("权威账户密钥读回不匹配"))
	}
	oldDER, e := vaultcrypto.DecryptString(oldProfile.PrivateKey, old.UserKey)
	if e != nil {
		return reject(i18n.T("原账户私钥不可解包"))
	}
	defer clear(oldDER)
	newDER, e := vaultcrypto.DecryptString(keys.PrivateKey, s.key)
	if e != nil {
		return reject(i18n.T("新账户私钥不可解包"))
	}
	defer clear(newDER)
	if !bytes.Equal(oldDER, newDER) {
		return reject(i18n.T("账户RSA私钥发生非预期变化"))
	}
	private, e := accountPrivateKey(current["profile"], s.key)
	if e != nil {
		return reject(i18n.T("新私钥解析失败"))
	}
	publicDER, e := x509.MarshalPKIXPublicKey(&private.PublicKey)
	clearAccountPrivateKey(private)
	expectedDER, decodeErr := base64.StdEncoding.Strict().DecodeString(request.Keys.PublicKey)
	if e != nil || decodeErr != nil || !bytes.Equal(publicDER, expectedDER) {
		return reject(i18n.T("账户RSA公私钥不一致"))
	}
	report.AuthorityEvidence = append(report.AuthorityEvidence, "fresh-login + sync + accounts/keys: unique expected master-userKey and privateKey ciphertext; new userKey distinct; unchanged RSA pair")
	report.CipherResources, e = VerifyAccountRotationCipherResources(ctx, RotationCipherVerificationInput{Scope: record.Scope, CurrentScope: fresh.Scope, OriginalSync: prior.Sync, CurrentSync: fresh.Vault.Sync, Target: RotationCipherResources{Ciphers: request.Data.Ciphers, Folders: request.Data.Folders}, OldUserKey: old.UserKey, NewUserKey: s.key})
	if e != nil || report.CipherResources.State != RotationCipherNew {
		return reject(i18n.T("cipher/folder缺失、混合或外部变化"))
	}
	report.SendResources, e = VerifySendRotationResources(ctx, SendRotationVerificationInput{Scope: record.Scope, FreshScope: fresh.Scope, OldSync: prior.Sync, FreshSync: fresh.Vault.Sync, RequestSends: request.Data.Sends, OldUserKey: old.UserKey, NewUserKey: s.key})
	if e != nil || !report.SendResources.Enumerated || report.SendResources.State != SendRotationNew {
		return reject(i18n.T("Send缺失、混合或外部变化"))
	}
	report.ResourceEvidence = append(report.ResourceEvidence, "read-back verified: complete cipher/folder/Send metadata and preserved independent content keys; binary content not downloaded")
	read := func(ctx context.Context, path string) (json.RawMessage, error) {
		if !strings.HasPrefix(path, "/api/emergency-access/") && !strings.HasPrefix(path, "/api/organizations/") && !strings.HasPrefix(path, "/api/users/") {
			return nil, ErrPermission
		}
		status, body, err := s.authenticatedLocked(ctx, "GET", path, "", "", persist)
		if err != nil {
			return nil, err
		}
		if path == emergencyAvailabilityPath {
			return recoveryAvailabilityResponse(status, body)
		}
		if status != 200 {
			return nil, statusError(status)
		}
		return body, nil
	}
	if e = verifyRotationRecipients(ctx, read, fresh.Vault, request, evidence); e != nil {
		return reject(i18n.T("恢复收件人、登记、身份、可信公钥或完整清单发生变化"))
	}
	report.ResourceEvidence = append(report.ResourceEvidence, "protocol-ordered commit evidence: Vaultwarden 1.37.4/7c188967 saves all enumerated EA/recovery wrappers before the unique final account double-wrapper witness; hidden wrappers were not independently read back")
	if ctx.Err() != nil {
		return fresh, report, ErrCancelled
	}
	if err = s.completeRecoveryVerificationLocked(ctx, &fresh); err != nil {
		return fresh, report, err
	}
	report.Kind = RecoveryEvidenceOrderedRotation
	report.Ready = true
	return fresh, report, nil
}
func (s *Session) completeRecoveryVerificationLocked(ctx context.Context, fresh *SyncResult) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if !s.itemSessionActiveLocked() {
		return ErrExpired
	}
	data, err := s.savedLocked()
	if err != nil {
		return err
	}
	clear(fresh.Session)
	fresh.Session = data
	if fresh.PasswordUnlock != nil {
		clear(fresh.PasswordUnlock.Key)
	}
	fresh.PasswordUnlock = &PasswordUnlock{Config: s.passwordUnlock.Config, Key: append([]byte(nil), s.passwordUnlock.Key...)}
	return nil
}

func jsonEmptyArray(raw json.RawMessage) bool {
	var rows []json.RawMessage
	return json.Unmarshal(raw, &rows) == nil && rows != nil && len(rows) == 0
}
func emptyPersonalRecoveryInventory(raw json.RawMessage) bool {
	var rows []struct{ OrganizationID *string }
	if json.Unmarshal(raw, &rows) != nil || rows == nil {
		return false
	}
	for _, row := range rows {
		if row.OrganizationID == nil {
			return false
		}
	}
	return true
}
func sameOrganizationRecoveryInventory(a, b json.RawMessage) bool {
	project := func(raw json.RawMessage) json.RawMessage {
		var rows []json.RawMessage
		if json.Unmarshal(raw, &rows) != nil || rows == nil {
			return nil
		}
		out := []json.RawMessage{}
		for _, row := range rows {
			var meta struct{ OrganizationID *string }
			if json.Unmarshal(row, &meta) != nil {
				return nil
			}
			if meta.OrganizationID != nil {
				out = append(out, row)
			}
		}
		data, _ := json.Marshal(out)
		return data
	}
	return AccountRotationCipherInventoryEqual(project(a), project(b))
}
func verifyRotationRecipients(ctx context.Context, read func(context.Context, string) (json.RawMessage, error), vault *VaultData, request AccountRotationRequest, evidence *AccountRotationEvidence) error {
	probe, err := read(ctx, emergencyAvailabilityPath)
	if err != nil {
		return err
	}
	if string(probe) != `{"emergencyAccessEnabled":true}` {
		return ErrEmergencyUnavailable
	}
	raw, err := read(ctx, "/api/emergency-access/trusted")
	if err != nil {
		return err
	}
	contacts, err := decodeEmergencyContacts(raw, true, vault.Scope.Account)
	if err != nil {
		return err
	}
	sort.Slice(contacts, func(i, j int) bool { return contacts[i].ID < contacts[j].ID })
	if !reflect.DeepEqual(contacts, evidence.Contacts) {
		return ErrConflict
	}
	expectedIDs, actualIDs := []string{}, []string{}
	for _, c := range contacts {
		if c.Status >= 2 {
			expectedIDs = append(expectedIDs, c.ID)
			public, err := rotationRecoveryPublic(ctx, read, "/api/users/"+c.GranteeID+"/public-key", c.GranteeID)
			if err != nil {
				return err
			}
			if public == "" || public != evidence.Trust.Users[c.GranteeID] {
				return ErrIdentity
			}
		}
	}
	for _, row := range request.Unlock.Emergency {
		if row.KeyEncrypted == "" {
			return ErrProtocol
		}
		actualIDs = append(actualIDs, row.ID)
	}
	if err = accountExactIDs(expectedIDs, actualIDs); err != nil {
		return err
	}
	var sync struct {
		Profile struct {
			Organizations []struct {
				Organization
				ResetPasswordEnrolled *bool
			}
		}
	}
	if json.Unmarshal(vault.Sync, &sync) != nil || sync.Profile.Organizations == nil {
		return ErrProtocol
	}
	members := map[string]RotationRecoveryMemberEvidence{}
	for _, org := range sync.Profile.Organizations {
		if org.ResetPasswordEnrolled == nil {
			return ErrProtocol
		}
		if !*org.ResetPasswordEnrolled {
			continue
		}
		if org.Status != 2 || !org.Enabled || org.UserID != vault.Scope.Account {
			return ErrIdentity
		}
		public, err := rotationRecoveryPublic(ctx, read, "/api/organizations/"+org.ID+"/public-key", "")
		if err != nil {
			return err
		}
		if public == "" || public != evidence.Trust.Organizations[org.ID] {
			return ErrIdentity
		}
		members[org.ID] = RotationRecoveryMemberEvidence{OrganizationID: org.ID, MemberID: org.OrganizationUserID, UserID: org.UserID, PublicKey: public}
	}
	if len(members) != len(evidence.Members) {
		return ErrIdentity
	}
	expectedIDs, actualIDs = []string{}, []string{}
	for _, member := range evidence.Members {
		if members[member.OrganizationID] != member {
			return ErrIdentity
		}
		expectedIDs = append(expectedIDs, member.OrganizationID)
	}
	for _, row := range request.Unlock.Recovery {
		if row.ResetPasswordKey == "" {
			return ErrProtocol
		}
		actualIDs = append(actualIDs, row.OrganizationID)
	}
	return accountExactIDs(expectedIDs, actualIDs)
}
