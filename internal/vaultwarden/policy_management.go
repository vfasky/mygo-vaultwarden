// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strconv"
)

// PolicyDefinition describes only fields exposed by the pinned clients commit.
// Other data remains opaque and is preserved on a round trip.
type PolicyDefinition struct {
	Type              int
	Name, Consumption string
	Fields            []PolicyFieldDefinition
}
type PolicyFieldDefinition struct {
	Key, Label, Kind string
	Min, Max         int
}

func OrganizationPolicyDefinitions() []PolicyDefinition {
	b := func(k, l string) PolicyFieldDefinition { return PolicyFieldDefinition{k, l, "bool", 0, 0} }
	n := func(k, l string, min, max int) PolicyFieldDefinition {
		return PolicyFieldDefinition{k, l, "number", min, max}
	}
	return []PolicyDefinition{
		{0, "要求双因素认证", "服务器执行成员撤销；本应用完整 MFA 登录与管理待接。", nil},
		{1, "主密码要求", "主密码变更及兼容 zxcvbn 强度验证待接，保存策略不代表本机执行。", []PolicyFieldDefinition{n("minComplexity", "最低强度评分（0–4）", 0, 4), n("minLength", "最短主密码长度", 12, 128), b("requireUpper", "要求大写字母"), b("requireLower", "要求小写字母"), b("requireNumbers", "要求数字"), b("requireSpecial", "要求特殊字符"), b("enforceOnLogin", "登录时执行")}},
		{2, "密码生成器", "本应用受策略约束的生成器待接。", []PolicyFieldDefinition{{Key: "overridePasswordType", Label: "生成方式", Kind: "generator"}, n("minLength", "最短密码长度", 5, 128), b("useUpper", "使用大写字母"), b("useLower", "使用小写字母"), b("useNumbers", "使用数字"), b("useSpecial", "使用特殊字符"), n("minNumbers", "最少数字", 0, 9), n("minSpecial", "最少特殊字符", 0, 9), n("minNumberWords", "最少单词", 3, 20), b("capitalize", "单词首字母大写"), b("includeNumber", "包含数字")}},
		{3, "单一组织", "服务器执行加入限制与成员撤销；本机组织生命周期前置检查待补。", nil},
		{5, "限制个人所有权", "已约束个人保存；已有个人条目仍可读取。", nil},
		{6, "禁用 Send", "服务器执行限制；本应用 Send 产品流程待接。", nil},
		{7, "Send 选项", "服务器执行隐藏邮箱限制；本应用 Send 产品流程待接。", []PolicyFieldDefinition{b("disableHideEmail", "禁止隐藏发送者邮箱")}},
		{8, "账号恢复", "邀请自动登记已接；完整管理员恢复待接。服务器配置可能要求先启用单一组织。", []PolicyFieldDefinition{b("autoEnrollEnabled", "自动登记账号恢复")}},
		{14, "移除 PIN 解锁", "本应用没有 PIN 解锁入口；未来 PIN 功能须消费此策略。", nil},
		{15, "受限条目类型", "已约束写入、读取与 AutoFill。固定客户端默认限制卡片，保留服务器扩展数据。", nil},
		{16, "默认 URI 匹配", "默认 URI 策略消费待接；显式 URI 规则保持原值。", []PolicyFieldDefinition{{Key: "uriMatchDetection", Label: "默认匹配方式", Kind: "uri", Min: 0, Max: 5}}},
		{20, "组织用户通知", "固定服务器支持保存此类型，未发现其通知执行逻辑；保留原始扩展数据。", nil},
	}
}
func policyDefinition(t int) (PolicyDefinition, bool) {
	for _, d := range OrganizationPolicyDefinitions() {
		if d.Type == t {
			return d, true
		}
	}
	return PolicyDefinition{}, false
}

type PolicyField struct {
	PolicyFieldDefinition
	Value string
}
type PolicyDraft struct {
	Enabled                  bool
	Fields                   []PolicyField
	mutationID               string
	kind                     int
	organizationID, revision string
	scope                    Scope
	original                 map[string]json.RawMessage
	baseline                 []PolicyField
	policies                 []policyRecord
}
type PolicyConsent struct{ draft *PolicyDraft }
type policyRecord struct {
	OrganizationID string          `json:"organizationId"`
	Type           *int            `json:"type"`
	Enabled        *bool           `json:"enabled"`
	Data           json.RawMessage `json:"data"`
}

func (d *PolicyDraft) PendingMutation() PendingPolicyMutation {
	if d == nil {
		return PendingPolicyMutation{}
	}
	return PendingPolicyMutation{d.organizationID, d.kind, d.mutationID}
}
func (d *PolicyDraft) Type() int {
	if d == nil {
		return -1
	}
	return d.kind
}
func (d *PolicyDraft) Close() {
	if d != nil {
		*d = PolicyDraft{}
	}
}
func (d *PolicyDraft) Clone() *PolicyDraft {
	if d == nil {
		return nil
	}
	c := *d
	c.Fields = append([]PolicyField(nil), d.Fields...)
	c.baseline = append([]PolicyField(nil), d.baseline...)
	c.original = map[string]json.RawMessage{}
	for k, v := range d.original {
		c.original[k] = append(json.RawMessage(nil), v...)
	}
	c.policies = append([]policyRecord(nil), d.policies...)
	for i, row := range c.policies {
		c.policies[i].Data = append(json.RawMessage(nil), row.Data...)
		if row.Type != nil {
			value := *row.Type
			c.policies[i].Type = &value
		}
		if row.Enabled != nil {
			value := *row.Enabled
			c.policies[i].Enabled = &value
		}
	}
	return &c
}
func (d *PolicyDraft) Confirm() *PolicyConsent {
	if _, err := d.body(); err != nil {
		return nil
	}
	return &PolicyConsent{d.Clone()}
}
func (c *PolicyConsent) Close() {
	if c != nil {
		c.draft.Close()
		c.draft = nil
	}
}
func (c *PolicyConsent) Clone() *PolicyConsent {
	if c == nil {
		return nil
	}
	return &PolicyConsent{c.draft.Clone()}
}
func (d *PolicyDraft) body() (map[string]any, error) {
	if d == nil || len(d.Fields) != len(d.baseline) {
		return nil, ErrValidation
	}
	if d.kind == 16 && d.Enabled && (len(d.Fields) != 1 || d.Fields[0].Value == "") {
		return nil, ErrValidation
	}
	data := append(json.RawMessage(nil), d.original["data"]...)
	var fields map[string]json.RawMessage
	changed := false
	for i, f := range d.Fields {
		old := d.baseline[i]
		if f.PolicyFieldDefinition != old.PolicyFieldDefinition {
			return nil, ErrValidation
		}
		if f.Value == old.Value {
			continue
		}
		if !changed {
			if json.Unmarshal(data, &fields) != nil {
				return nil, ErrProtocol
			}
			if fields == nil {
				fields = map[string]json.RawMessage{}
			}
		}
		changed = true
		var value any
		if f.Value != "" {
			switch f.Kind {
			case "bool":
				if f.Value != "true" && f.Value != "false" {
					return nil, ErrValidation
				}
				value = f.Value == "true"
			case "generator":
				if f.Value != "password" && f.Value != "passphrase" {
					return nil, ErrValidation
				}
				value = f.Value
			case "number", "uri":
				v, err := strconv.Atoi(f.Value)
				if err != nil || v < f.Min || v > f.Max || (f.Kind == "uri" && (v == 2 || v == 4)) {
					return nil, ErrValidation
				}
				value = v
			default:
				return nil, ErrValidation
			}
		}
		fields[f.Key], _ = json.Marshal(value)
	}
	if changed {
		data, _ = json.Marshal(fields)
	}
	return map[string]any{"policy": map[string]any{"enabled": d.Enabled, "data": data}}, nil
}
func equalPolicyRecords(a, b []policyRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x.OrganizationID != y.OrganizationID || x.Type == nil || y.Type == nil || *x.Type != *y.Type || x.Enabled == nil || y.Enabled == nil || *x.Enabled != *y.Enabled || !rawJSONEqual(x.Data, y.Data) {
			return false
		}
	}
	return true
}

func validPolicyRecord(r policyRecord, orgID string) bool {
	if r.OrganizationID != orgID || r.Type == nil || r.Enabled == nil || len(r.Data) == 0 {
		return false
	}
	_, ok := policyDefinition(*r.Type)
	return ok
}
func (s *Session) policyReadLocked(ctx context.Context, path string, target any, persist func(SessionCheckpoint) error) error {
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, path, "", "", persist, s.organizationManagementGuardLocked(s.authorizationRevision))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return cipherUpdateStatusError(status, body)
	}
	if strictJSON(body) != nil || json.Unmarshal(body, target) != nil {
		return ErrProtocol
	}
	return nil
}
func (s *Session) policyListLocked(ctx context.Context, orgID string, persist func(SessionCheckpoint) error) ([]policyRecord, error) {
	var list struct {
		Data              []policyRecord
		ContinuationToken *string
	}
	if err := s.policyReadLocked(ctx, "/api/organizations/"+orgID+"/policies", &list, persist); err != nil {
		return nil, err
	}
	if list.Data == nil || list.ContinuationToken != nil || len(list.Data) > 12 {
		return nil, ErrProtocol
	}
	seen := map[int]bool{}
	for _, r := range list.Data {
		if !validPolicyRecord(r, orgID) || seen[*r.Type] {
			return nil, ErrProtocol
		}
		seen[*r.Type] = true
	}
	sort.Slice(list.Data, func(i, j int) bool { return *list.Data[i].Type < *list.Data[j].Type })
	return list.Data, nil
}

type PolicyEntry struct {
	Type    int
	Enabled bool
}

func (s *Session) OrganizationPolicies(ctx context.Context, vault *VaultData, orgID string, persist func(SessionCheckpoint) error) ([]PolicyEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if _, err = s.memberAdministratorLocked(vault, orgID); err != nil {
		return nil, err
	}
	rows, err := s.policyListLocked(ctx, orgID, persist)
	if err != nil {
		return nil, err
	}
	result := []PolicyEntry{}
	for _, def := range OrganizationPolicyDefinitions() {
		entry := PolicyEntry{Type: def.Type}
		for _, r := range rows {
			if *r.Type == def.Type {
				entry.Enabled = *r.Enabled
			}
		}
		result = append(result, entry)
	}
	return result, nil
}
func (s *Session) policyDraftLocked(ctx context.Context, vault *VaultData, orgID string, kind int, persist func(SessionCheckpoint) error) (*PolicyDraft, error) {
	def, ok := policyDefinition(kind)
	if !ok {
		return nil, ErrValidation
	}
	rows, err := s.policyListLocked(ctx, orgID, persist)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err = s.policyReadLocked(ctx, "/api/organizations/"+orgID+"/policies/"+strconv.Itoa(kind), &raw, persist); err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(raw)
	var r policyRecord
	if json.Unmarshal(encoded, &r) != nil || !validPolicyRecord(r, orgID) || *r.Type != kind {
		return nil, ErrIdentity
	}
	var fields map[string]json.RawMessage
	if len(def.Fields) > 0 && json.Unmarshal(r.Data, &fields) != nil {
		return nil, ErrProtocol
	}
	// A fresh default has a random id on each GET; compare effective values, not id.
	for _, row := range rows {
		if *row.Type == kind && (*row.Enabled != *r.Enabled || !rawJSONEqual(row.Data, r.Data)) {
			return nil, ErrConflict
		}
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return nil, err
	}
	d := &PolicyDraft{mutationID: hex.EncodeToString(id), Enabled: *r.Enabled, kind: kind, organizationID: orgID, revision: s.authorizationRevision, scope: vault.Scope, original: raw, policies: rows}
	for _, f := range def.Fields {
		v := ""
		if value := fields[f.Key]; len(value) > 0 && string(value) != "null" {
			if f.Kind == "generator" {
				if json.Unmarshal(value, &v) != nil {
					return nil, ErrProtocol
				}
			} else {
				v = string(value)
				if f.Kind == "bool" {
					if v != "true" && v != "false" {
						return nil, ErrProtocol
					}
				} else if _, err := strconv.Atoi(v); err != nil {
					return nil, ErrProtocol
				}
			}
		}
		d.Fields = append(d.Fields, PolicyField{f, v})
	}
	d.baseline = append([]PolicyField(nil), d.Fields...)
	return d, nil
}
func (s *Session) OrganizationPolicy(ctx context.Context, vault *VaultData, orgID string, kind int, persist func(SessionCheckpoint) error) (*PolicyDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	if _, err = s.memberAdministratorLocked(vault, orgID); err != nil {
		return nil, err
	}
	return s.policyDraftLocked(ctx, vault, orgID, kind, persist)
}

// SaveOrganizationPolicy consumes a confirmation and isolates before any write.
// Neither the last GET nor PUT provides CAS; partial failures never retry.
func (s *Session) SaveOrganizationPolicy(ctx context.Context, vault *VaultData, d *PolicyDraft, consent *PolicyConsent, isolate, persist func(SessionCheckpoint) error) error {
	if consent == nil || !reflect.DeepEqual(d, consent.draft) {
		return ErrValidation
	}
	body, err := d.body()
	if err != nil {
		return err
	}
	consent.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return err
	}
	defer finish()
	if vault == nil || d.scope != vault.Scope || d.revision == "" || d.revision != s.authorizationRevision {
		return ErrExpired
	}
	org, err := s.memberAdministratorLocked(vault, d.organizationID)
	if err != nil {
		return err
	}
	if _, err = s.membersLocked(ctx, org, persist); err != nil {
		return err
	}
	fresh, err := s.policyDraftLocked(ctx, vault, org.ID, d.kind, persist)
	if err != nil {
		return err
	}
	defer fresh.Close()
	if !equalPolicyRecords(d.policies, fresh.policies) || !rawJSONEqual(d.original["data"], fresh.original["data"]) || !rawJSONEqual(d.original["enabled"], fresh.original["enabled"]) {
		return ErrConflict
	}
	if isolate == nil || s.checkpointLocked(isolate) != nil {
		return ErrCheckpoint
	}
	s.pendingPolicyMutations = append(s.pendingPolicyMutations, d.PendingMutation())
	encoded, _ := json.Marshal(body)
	status, response, err := s.authenticatedGuardedLocked(ctx, http.MethodPut, "/api/organizations/"+org.ID+"/policies/"+strconv.Itoa(d.kind), "application/json", string(encoded), persist, s.organizationManagementGuardLocked(s.authorizationRevision))
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &MutationUncertainError{Cause: cipherUpdateStatusError(status, response)}
	}
	var saved policyRecord
	if strictJSON(response) != nil || json.Unmarshal(response, &saved) != nil || !validPolicyRecord(saved, org.ID) || *saved.Type != d.kind || *saved.Enabled != d.Enabled || !rawJSONEqual(saved.Data, body["policy"].(map[string]any)["data"].(json.RawMessage)) {
		return &MutationUncertainError{Cause: ErrIdentity}
	}
	if ctx.Err() != nil {
		return &MutationUncertainError{Cause: ErrCancelled}
	}
	return nil
}
