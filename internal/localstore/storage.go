// SPDX-License-Identifier: GPL-3.0-only

// Package localstore implements native snapshot storage and recovery protocols.
package localstore

import (
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"log"
)

var errSnapshotTooLarge = errors.New("snapshot bridge size limit")

type SnapshotStatus struct {
	AccountSwitchPending  bool                              `json:"accountSwitchPending"`
	TargetRecoveryPresent bool                              `json:"targetRecoveryPresent"`
	RecoveryPending       bool                              `json:"recoveryPending"`
	Revision              string                            `json:"revision"`
	Available             bool                              `json:"available"`
	Count                 int                               `json:"count"`
	IndexPending          bool                              `json:"indexPending"`
	CleanupPending        bool                              `json:"cleanupPending"`
	SnapshotID            string                            `json:"snapshotID,omitempty"`
	Scope                 *vaultwarden.Scope                `json:"scope,omitempty"`
	UpdatedAt             int64                             `json:"updatedAt,omitempty"`
	PasswordUnlock        *vaultwarden.PasswordUnlockConfig `json:"passwordUnlock,omitempty"`
}

type Request struct {
	SwitchBinding      *AccountSwitchBinding              `json:"switchBinding,omitempty"`
	SwitchOperationID  string                             `json:"switchOperationID,omitempty"`
	TargetRuntime      *TargetRecoveryRuntimeAuthority    `json:"targetRuntime,omitempty"`
	TargetLogin        *targetRecoveryResolution          `json:"targetLogin,omitempty"`
	TargetBinding      *TargetRecoveryBinding             `json:"targetBinding,omitempty"`
	TargetSummary      []byte                             `json:"targetSummary,omitempty"`
	TargetPhase        string                             `json:"targetPhase,omitempty"`
	TargetResolution   *targetRecoveryResolution          `json:"targetResolution,omitempty"`
	RecoveryBinding    *accountRecoveryBinding            `json:"recoveryBinding,omitempty"`
	RecoveryRecord     []byte                             `json:"recoveryRecord,omitempty"`
	RecoveryPhase      string                             `json:"recoveryPhase,omitempty"`
	RecoveryResolution *accountRecoveryResolution         `json:"recoveryResolution,omitempty"`
	ClearingPolicy     *vaultwarden.PendingPolicyMutation `json:"clearingPolicy,omitempty"`
	PendingPolicy      *vaultwarden.PendingPolicyMutation `json:"pendingPolicy,omitempty"`
	OrganizationID     string                             `json:"organizationID,omitempty"`
	Operation          string                             `json:"operation"`
	ExpectedRevision   string                             `json:"expectedRevision,omitempty"`
	Credentials        []vaultwarden.Credential           `json:"credentials"`
	Scope              *vaultwarden.Scope                 `json:"scope,omitempty"`
	PasswordUnlock     *vaultwarden.PasswordUnlock        `json:"passwordUnlock,omitempty"`
	UnlockKey          []byte                             `json:"unlockKey,omitempty"`
	Session            []byte                             `json:"session,omitempty"`
	Vault              *vaultwarden.VaultData             `json:"vault,omitempty"`
	Secret             string                             `json:"secret,omitempty"`
	SecretProtocol     int                                `json:"secretProtocol,omitempty"`
	SecretNotAfter     int64                              `json:"secretNotAfter,omitempty"`
}

// A zero-result sync is an explicit replacement, never an absent field.
func (r Request) MarshalJSON() ([]byte, error) {
	type wireRequest Request
	if (r.Operation == "publishBoundAccount" || r.Operation == "publishVault" || r.Operation == "restoreOrganizationAccess" || r.Operation == "restorePolicyAccess" || r.Operation == "accountRecoveryResolve" || r.Operation == "targetRecoveryResolve" || r.Operation == "targetRecoveryResolveLocal") && r.Credentials == nil {
		r.Credentials = []vaultwarden.Credential{}
	}
	return json.Marshal(wireRequest(r))
}

type Failure struct{ Code, Message string }

func (e *Failure) Error() string { return e.Message }
func (r Reply) Failure() error   { return &Failure{Code: r.Code, Message: r.Message} }

type DisplayCredential struct {
	OrganizationID   string   `json:"-"`
	CollectionIDs    []string `json:"-"`
	Readable         bool     `json:"-"`
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Username         string   `json:"username"`
	URL              string   `json:"url"`
	Type             int      `json:"type,omitempty"`
	Favorite         bool     `json:"favorite,omitempty"`
	Archived         bool     `json:"archived,omitempty"`
	Deleted          bool     `json:"deleted,omitempty"`
	Editable         bool     `json:"editable,omitempty"`
	RequiresPassword bool     `json:"requiresPassword,omitempty"`
	FolderID         string   `json:"folderId,omitempty"`
}

type Reply struct {
	AccountSwitch    *AccountSwitchReceipt     `json:"accountSwitch,omitempty"`
	TargetProtection *TargetRecoveryProtection `json:"targetProtection,omitempty"`
	TargetRecords    []TargetRecoveryRecord    `json:"targetRecords,omitempty"`
	Recovery         *accountRecoveryJournal   `json:"recovery,omitempty"`
	OK               bool                      `json:"ok"`
	Code             string                    `json:"code"`
	Message          string                    `json:"message"`
	State            *SnapshotStatus           `json:"state,omitempty"`
	Items            []DisplayCredential       `json:"items,omitempty"`
	Truncated        bool                      `json:"truncated,omitempty"`
	DeviceID         string                    `json:"deviceID,omitempty"`
	Session          []byte                    `json:"session,omitempty"`
	Vault            *vaultwarden.VaultData    `json:"vault,omitempty"`
}

func Call(request Request) Reply {
	input, err := json.Marshal(request)
	if err != nil {
		return Reply{Code: "invalid_input", Message: i18n.T("无法编码快照请求。")}
	}
	defer clear(input)
	output, err := nativeStorageCall(input)
	if err != nil {
		if errors.Is(err, errSnapshotTooLarge) {
			return Reply{Code: "snapshot_too_large", Message: i18n.T("密码库超过本版有界传输上限，无法保存。")}
		}
		// Loader/ABI failures contain paths and codes only, never the request body.
		log.Printf("snapshot bridge unavailable: %v", err)
		return Reply{Code: "bridge_unavailable", Message: i18n.T("安全存储组件不可用，请运行完整签名安装版。")}
	}
	defer clear(output)
	var reply Reply
	if err := json.Unmarshal(output, &reply); err != nil {
		clear(reply.Session)
		return Reply{Code: "invalid_reply", Message: i18n.T("安全存储返回了无效响应。")}
	}
	return reply
}
