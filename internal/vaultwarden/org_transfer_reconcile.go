// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"net/http"
	"reflect"
	"sort"
)

// OrganizationImportObservation records a fresh server observation, not a
// transactional receipt. Unknown includes cancellation, revoked access, duplicate
// source contents and concurrent writes. It never authorizes a retry.
type OrganizationImportObservation struct {
	SourceID string
	ServerID string
	Verified bool
	Reason   string
}
type OrganizationImportReconciliation struct {
	ReadCompleted bool
	BeforeIDs     []string
	AfterIDs      []string
	AddedIDs      []string
	Items         []OrganizationImportObservation
}

// A new authenticated read is required here: operationPoliciesLocked caches the
// first sync for a write operation and cannot observe that operation's effects.
func (s *Session) freshOrganizationImportPoliciesLocked(ctx context.Context, orgID string, persist func(SessionCheckpoint) error) (*operationPolicies, error) {
	guard := s.orgOperationGuardLocked()
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, "/api/sync", "", "", persist, guard)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if status != http.StatusOK {
		return nil, statusError(status)
	}
	policies, err := parseOperationPolicies(body, Scope{Server: s.client.base.String(), Account: s.account}, s.email, s.wrapped)
	if err != nil {
		return nil, err
	}
	applyPendingPolicies(policies, s.pendingPolicyMutations)
	policies.revision, policies.epoch = s.authorizationRevision, s.authorizationEpoch
	if err := s.checkOperationPoliciesLocked(ctx, policies); err != nil {
		return nil, err
	}
	member, ok := policies.memberships[orgID]
	if !ok || member.Status == nil || *member.Status != 2 || member.Enabled == nil || !*member.Enabled {
		return nil, ErrPermission
	}
	return policies, nil
}

func organizationCipherIDs(raws []json.RawMessage, orgID string) []string {
	ids := []string{}
	for _, raw := range raws {
		var m struct{ ID, OrganizationID string }
		if json.Unmarshal(raw, &m) == nil && m.OrganizationID == orgID && validObjectID(m.ID) {
			ids = append(ids, m.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func (s *Session) reconcileOrganizationImportLocked(ctx context.Context, orgID string, before []string, expected []json.RawMessage, plan *OrganizationImportPlan, mappings map[string]string, persist func(SessionCheckpoint) error) OrganizationImportReconciliation {
	r := OrganizationImportReconciliation{BeforeIDs: before}
	for _, item := range plan.file.Items {
		r.Items = append(r.Items, OrganizationImportObservation{SourceID: item["id"].(string), Reason: i18n.T("server.transfer.err_fresh_read_incomplete")})
	}
	// This policy read does not accept a snapshot, issue an offline receipt, clear
	// isolation or discard pending policies.
	fresh, err := s.freshOrganizationImportPoliciesLocked(ctx, orgID, persist)
	if err != nil {
		return r
	}
	r.ReadCompleted = true
	r.AfterIDs = organizationCipherIDs(fresh.ciphers, orgID)
	old := map[string]bool{}
	for _, id := range before {
		old[id] = true
	}
	for _, id := range r.AfterIDs {
		if !old[id] {
			r.AddedIDs = append(r.AddedIDs, id)
		}
	}
	fingerprints := map[string]int{}
	sourceFingerprint := func(item map[string]any) string {
		clone := map[string]any{}
		for k, v := range item {
			clone[k] = v
		}
		for _, k := range []string{"id", "creationDate", "revisionDate"} {
			delete(clone, k)
		}
		b, _ := json.Marshal(clone)
		return string(b)
	}
	for _, item := range plan.file.Items {
		fingerprints[sourceFingerprint(item)]++
	}
	for i, raw := range expected {
		row := &r.Items[i]
		row.Reason = i18n.T("server.transfer.err_new_item_unmatched")
		if fingerprints[sourceFingerprint(plan.file.Items[i])] != 1 {
			row.Reason = i18n.T("server.transfer.err_duplicate_source_content")
			continue
		}
		want, err := documentObject(CipherDocument{JSON: raw})
		if err != nil {
			continue
		}
		key, ok := want["key"].(string)
		if !ok || key == "" {
			continue
		}
		normalizeResponseLoginAlias(want)
		wantFields, err := decodeCipherFields(want)
		if err != nil {
			continue
		}
		expectedCollections := []string{}
		complete := true
		for _, source := range plan.file.Items[i]["collectionIds"].([]any) {
			target := mappings[source.(string)]
			if target == "" {
				complete = false
				break
			}
			expectedCollections = append(expectedCollections, target)
		}
		if !complete {
			row.Reason = i18n.T("server.transfer.err_collection_receipt_missing")
			continue
		}
		sort.Strings(expectedCollections)
		matches := []string{}
		for _, actualRaw := range fresh.ciphers {
			actual, err := documentObject(CipherDocument{JSON: actualRaw})
			if err != nil {
				continue
			}
			id, _ := actual["id"].(string)
			if old[id] || actual["organizationId"] != orgID || actual["key"] != key {
				continue
			}
			normalizeResponseLoginAlias(actual)
			gotFields, err := decodeCipherFields(actual)
			if err != nil || !gotFields.ViewPassword || !gotFields.Edit || fresh.restricts(&orgID, gotFields.Type) {
				continue
			}
			// IDs/revisions and effective permissions are server-owned. All imported
			// content fields, including encrypted secrets and reprompt, must agree.
			wantFields.ID, gotFields.ID = "", ""
			wantFields.RevisionDate, gotFields.RevisionDate = "", ""
			wantFields.Edit, gotFields.Edit = false, false
			wantFields.ViewPassword, gotFields.ViewPassword = false, false
			relations := []string{}
			if list, ok := actual["collectionIds"].([]any); ok {
				for _, v := range list {
					if id, ok := v.(string); ok {
						relations = append(relations, id)
					}
				}
			}
			sort.Strings(relations)
			if reflect.DeepEqual(wantFields, gotFields) && reflect.DeepEqual(expectedCollections, relations) {
				matches = append(matches, id)
			}
		}
		if len(matches) == 1 {
			row.Verified = true
			row.ServerID = matches[0]
			row.Reason = i18n.T("server.transfer.status_item_verified")
		}
	}
	return r
}
