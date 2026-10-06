// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import "errors"

// Error messages deliberately exclude response bodies, URLs, tokens and secrets.
var (
	ErrServer         = errors.New("服务器地址必须是 HTTPS；仅本机测试允许 HTTP，不能包含用户名、查询参数或片段")
	ErrNetwork        = errors.New("无法连接服务器，请检查地址、网络和 TLS 证书")
	ErrProtocol       = errors.New("服务器响应不符合支持的 Vaultwarden 协议")
	ErrCredentials    = errors.New("邮箱、主密码或验证码不正确")
	ErrMFA            = errors.New("账号需要 TOTP 验证码")
	ErrUnsupportedMFA = errors.New("此账号的验证方式暂不支持；当前仅支持 TOTP 双重验证")
	ErrExpired        = errors.New("会话或账号密钥已变化，请重新登录")
	ErrIdentity       = errors.New("服务器返回的账号身份发生变化，已拒绝同步")
	ErrKDF            = errors.New("KDF 类型或参数不在支持的安全范围内")
	ErrEncryption     = errors.New("加密格式不支持或完整性校验失败，未替换离线快照")
	ErrCancelled      = errors.New("操作已取消")
)

type Scope struct {
	Server  string `json:"server"`
	Account string `json:"account"`
}

type URI struct {
	URI               string `json:"uri"`
	Match             int    `json:"match"`
	BaseDomain        string `json:"baseDomain,omitempty"`
	IncludeSubdomains bool   `json:"includeSubdomains"`
}

type Credential struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Hosts    []string `json:"hosts"`
	URL      string   `json:"url"`
	URIs     []URI    `json:"uris"`
}

type Summary struct {
	Logins          int
	Organizations   int
	OtherTypes      int
	Reprompt        int
	Deleted         int
	UnsupportedURIs int
}

type SyncResult struct {
	Scope       Scope
	Credentials []Credential
	Summary     Summary
}
