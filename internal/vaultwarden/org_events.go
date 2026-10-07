// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// OrganizationEvent separates membership IDs from global user IDs. Event type
// is intentionally an integer: future server event types remain displayable.
type OrganizationEvent struct {
	Type               int     `json:"type"`
	UserID             *string `json:"userId"`
	OrganizationID     *string `json:"organizationId"`
	CipherID           *string `json:"cipherId"`
	CollectionID       *string `json:"collectionId"`
	GroupID            *string `json:"groupId"`
	OrganizationUserID *string `json:"organizationUserId"`
	ActingUserID       *string `json:"actingUserId"`
	Date               string  `json:"date"`
	DeviceType         *int    `json:"deviceType"`
	IPAddress          *string `json:"ipAddress"`
	PolicyID           *string `json:"policyId"`
}

type OrganizationEventPage struct {
	Data              []OrganizationEvent `json:"data"`
	ContinuationToken *string             `json:"continuationToken"`
}

// Exactly one optional filter can be supplied. MemberID is an organization
// membership ID, never the global account ID. Paging is caller-driven so cancel
// and rate limits never result in an unbounded automatic crawl.
type OrganizationEventQuery struct {
	OrganizationID, MemberID, CipherID string
	Start, End                         time.Time
	ContinuationToken                  string
}

func organizationEventPath(q OrganizationEventQuery) (string, error) {
	if !validObjectID(q.OrganizationID) || (q.MemberID != "" && !validObjectID(q.MemberID)) || (q.CipherID != "" && !validObjectID(q.CipherID)) || (q.MemberID != "" && q.CipherID != "") || q.Start.IsZero() || q.End.IsZero() || q.Start.After(q.End) {
		return "", ErrValidation
	}
	values := url.Values{"start": {q.Start.UTC().Format(time.RFC3339Nano)}, "end": {q.End.UTC().Format(time.RFC3339Nano)}}
	if q.ContinuationToken != "" {
		token, err := time.Parse(time.RFC3339Nano, q.ContinuationToken)
		if err != nil || token.Before(q.Start) || token.After(q.End) {
			return "", ErrValidation
		}
		values.Set("continuationToken", q.ContinuationToken)
	}
	path := "/api/organizations/" + q.OrganizationID + "/events"
	if q.MemberID != "" {
		path = "/api/organizations/" + q.OrganizationID + "/users/" + q.MemberID + "/events"
	}
	if q.CipherID != "" {
		path = "/api/ciphers/" + q.CipherID + "/events"
	}
	return path + "?" + values.Encode(), nil
}

func (s *Session) OrganizationEvents(ctx context.Context, vault *VaultData, query OrganizationEventQuery, persist func(SessionCheckpoint) error) (OrganizationEventPage, error) {
	var page OrganizationEventPage
	path, err := organizationEventPath(query)
	if err != nil {
		return page, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, finish, err := s.beginOperationLocked(ctx)
	if err != nil {
		return page, err
	}
	defer finish()
	data, err := s.organizationVaultLocked(vault)
	if err != nil {
		return page, err
	}
	defer data.close()
	admin := false
	for _, org := range data.organizations {
		if org.ID == query.OrganizationID && (org.Type == 0 || org.Type == 1) {
			admin = true
		}
	}
	if !admin {
		return page, ErrPermission
	}
	if query.CipherID != "" {
		doc, ok := data.documents[query.CipherID]
		var m struct{ OrganizationID *string }
		if !ok || json.Unmarshal(doc.JSON, &m) != nil || m.OrganizationID == nil || *m.OrganizationID != query.OrganizationID {
			return page, ErrPermission
		}
	}
	status, body, err := s.authenticatedGuardedLocked(ctx, http.MethodGet, path, "", "", persist, s.orgOperationGuardLocked())
	if err != nil {
		return page, err
	}
	if status != http.StatusOK {
		return page, cipherUpdateStatusError(status, body)
	}
	var envelope struct {
		Object            string
		Data              json.RawMessage
		ContinuationToken *string
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Object != "list" || len(envelope.Data) == 0 || string(envelope.Data) == "null" || json.Unmarshal(envelope.Data, &page.Data) != nil {
		return OrganizationEventPage{}, ErrProtocol
	}
	page.ContinuationToken = envelope.ContinuationToken
	for _, event := range page.Data {
		if event.OrganizationID == nil || *event.OrganizationID != query.OrganizationID {
			return OrganizationEventPage{}, ErrIdentity
		}
		if query.CipherID != "" && (event.CipherID == nil || *event.CipherID != query.CipherID) {
			return OrganizationEventPage{}, ErrIdentity
		}
		date, err := time.Parse(time.RFC3339Nano, event.Date)
		if err != nil || date.Before(query.Start) || date.After(query.End) {
			return OrganizationEventPage{}, ErrProtocol
		}
	}
	if page.ContinuationToken != nil {
		next := query
		next.ContinuationToken = *page.ContinuationToken
		if next.ContinuationToken == "" || next.ContinuationToken == query.ContinuationToken {
			return OrganizationEventPage{}, ErrProtocol
		}
		if _, err := organizationEventPath(next); err != nil {
			return OrganizationEventPage{}, ErrProtocol
		}
	}
	if ctx.Err() != nil {
		return OrganizationEventPage{}, ErrCancelled
	}
	return page, nil
}
