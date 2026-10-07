// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"errors"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
	"log"
)

var errSnapshotTooLarge = errors.New("snapshot bridge size limit")

type snapshotStatus struct {
	Revision       string                            `json:"revision"`
	Available      bool                              `json:"available"`
	Count          int                               `json:"count"`
	IndexPending   bool                              `json:"indexPending"`
	CleanupPending bool                              `json:"cleanupPending"`
	SnapshotID     string                            `json:"snapshotID,omitempty"`
	Scope          *vaultwarden.Scope                `json:"scope,omitempty"`
	UpdatedAt      int64                             `json:"updatedAt,omitempty"`
	PasswordUnlock *vaultwarden.PasswordUnlockConfig `json:"passwordUnlock,omitempty"`
}

type storageRequest struct {
	ClearingPolicy   *vaultwarden.PendingPolicyMutation `json:"clearingPolicy,omitempty"`
	PendingPolicy    *vaultwarden.PendingPolicyMutation `json:"pendingPolicy,omitempty"`
	OrganizationID   string                             `json:"organizationID,omitempty"`
	Operation        string                             `json:"operation"`
	ExpectedRevision string                             `json:"expectedRevision,omitempty"`
	Credentials      []vaultwarden.Credential           `json:"credentials"`
	Scope            *vaultwarden.Scope                 `json:"scope,omitempty"`
	PasswordUnlock   *vaultwarden.PasswordUnlock        `json:"passwordUnlock,omitempty"`
	UnlockKey        []byte                             `json:"unlockKey,omitempty"`
	Session          []byte                             `json:"session,omitempty"`
	Vault            *vaultwarden.VaultData             `json:"vault,omitempty"`
	Secret           string                             `json:"secret,omitempty"`
	SecretProtocol   int                                `json:"secretProtocol,omitempty"`
	SecretNotAfter   int64                              `json:"secretNotAfter,omitempty"`
}

// A zero-result sync is an explicit replacement, never an absent field.
func (r storageRequest) MarshalJSON() ([]byte, error) {
	type wireRequest storageRequest
	if (r.Operation == "publishVault" || r.Operation == "restoreOrganizationAccess" || r.Operation == "restorePolicyAccess") && r.Credentials == nil {
		r.Credentials = []vaultwarden.Credential{}
	}
	return json.Marshal(wireRequest(r))
}

type storageFailure struct{ Code, Message string }

func (e *storageFailure) Error() string { return e.Message }
func (r storageReply) failure() error   { return &storageFailure{Code: r.Code, Message: r.Message} }

type displayCredential struct {
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

type storageReply struct {
	OK        bool                   `json:"ok"`
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	State     *snapshotStatus        `json:"state,omitempty"`
	Items     []displayCredential    `json:"items,omitempty"`
	Truncated bool                   `json:"truncated,omitempty"`
	DeviceID  string                 `json:"deviceID,omitempty"`
	Session   []byte                 `json:"session,omitempty"`
	Vault     *vaultwarden.VaultData `json:"vault,omitempty"`
}

func callStorage(request storageRequest) storageReply {
	input, err := json.Marshal(request)
	if err != nil {
		return storageReply{Code: "invalid_input", Message: "无法编码快照请求。"}
	}
	defer clear(input)
	output, err := nativeStorageCall(input)
	if err != nil {
		if errors.Is(err, errSnapshotTooLarge) {
			return storageReply{Code: "snapshot_too_large", Message: "密码库或显示数据超过本版 4 MiB 传输上限，请缩小范围后重试。"}
		}
		// Loader/ABI failures contain paths and codes only, never the request body.
		log.Printf("snapshot bridge unavailable: %v", err)
		return storageReply{Code: "bridge_unavailable", Message: "安全存储组件不可用，请运行完整签名安装版。"}
	}
	defer clear(output)
	var reply storageReply
	if err := json.Unmarshal(output, &reply); err != nil {
		clear(reply.Session)
		return storageReply{Code: "invalid_reply", Message: "安全存储返回了无效响应。"}
	}
	return reply
}
