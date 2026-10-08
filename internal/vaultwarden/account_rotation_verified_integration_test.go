// SPDX-License-Identifier: GPL-3.0-only
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLiveVerifiedRotationEvidence(t *testing.T) {
	if os.Getenv("MYGO_VERIFIED_ROTATION_TEST") != "1" {
		t.Skip("opt-in owned 1.37.4 complete rotation witness fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	base, dir, _ := recoveryLiveFixture(t, ctx)
	password := []byte("Public-member-fixture-password!")
	for _, mode := range []string{"success", "lost-response", "ea-failure", "recovery-failure", "cipher-failure", "not-dispatched"} {
		t.Run(mode, func(t *testing.T) {
			syncVault := func(s *Session) *VaultData {
				r, e := s.Sync(ctx)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.AcceptAuthenticatedSnapshot(r.Vault, fixtureUUID()); e != nil {
					t.Fatal(e)
				}
				clear(r.Session)
				if r.PasswordUnlock != nil {
					clear(r.PasswordUnlock.Key)
				}
				return r.Vault
			}
			commitRecovery := func(s *Session, p *RecoveryPlan) {
				defer p.Close()
				r, e := s.CommitRecoveryOperation(ctx, p, p.ConfirmationText(), nil, func(RecoveryDispatch) error { return nil })
				if e != nil || !r.Confirmed {
					t.Fatal("fixture recovery mutation", e)
				}
			}
			actor, _ := liveOrganizationMember(t, ctx, base)
			defer actor.Close()
			grantee, public := liveOrganizationMember(t, ctx, base)
			defer grantee.Close()
			owner, _ := liveOrganizationMember(t, ctx, base)
			defer owner.Close()
			av, gv, ov := syncVault(actor), syncVault(grantee), syncVault(owner)
			prepare := func(s *Session, v *VaultData, r EmergencyRequest) *RecoveryPlan {
				p, e := s.PrepareEmergencyOperation(ctx, v, r, nil)
				if e != nil {
					t.Fatal(e)
				}
				return p
			}
			commitRecovery(actor, prepare(actor, av, EmergencyRequest{Action: "invite", Email: grantee.email, Type: 0, WaitTimeDays: 0}))
			eaID, token := emergencyCapturedToken(t, dir, grantee.email)
			commitRecovery(grantee, prepare(grantee, gv, EmergencyRequest{Action: "accept", ID: eaID, Token: token}))
			der, _ := x509.MarshalPKIXPublicKey(public)
			trusted := base64.StdEncoding.EncodeToString(der)
			commitRecovery(actor, prepare(actor, av, EmergencyRequest{Action: "confirm", ID: eaID, Trusted: true, TrustedPublicKey: trusted}))
			org, e := owner.SaveOrganization(ctx, ov, "", OrganizationSettings{Name: "verified rotation", BillingEmail: owner.email, CollectionName: "fixture"}, nil)
			if e != nil {
				t.Fatal(e)
			}
			ov = syncVault(owner)
			status, _, e := owner.client.request(ctx, "PUT", "/api/organizations/"+org.ID+"/policies/8", "application/json", `{"policy":{"enabled":true,"data":{"autoEnrollEnabled":false}}}`, owner.access)
			if e != nil || status != 200 {
				t.Fatal("policy", status, e)
			}
			directory, e := owner.OrganizationMembers(ctx, ov, org.ID, nil)
			if e != nil {
				t.Fatal(e)
			}
			e = owner.InviteOrganizationMember(ctx, ov, directory, actor.email, 2, nil)
			directory.Close()
			if e != nil {
				t.Fatal(e)
			}
			links := capturedInvitationLinks(t, dir, actor.email)
			if len(links) == 0 {
				t.Fatal("invite")
			}
			av = syncVault(actor)
			if e = actor.AcceptOrganizationInvitation(ctx, av, links[len(links)-1], nil); e != nil {
				t.Fatal(e)
			}
			directory, e = owner.OrganizationMembers(ctx, ov, org.ID, nil)
			if e != nil {
				t.Fatal(e)
			}
			memberID := ""
			for _, member := range directory.Members() {
				if member.UserID == actor.account {
					memberID = member.ID
				}
			}
			confirmation, e := owner.PrepareMemberConfirmation(ctx, ov, directory, memberID, nil)
			directory.Close()
			if e != nil {
				t.Fatal(e)
			}
			memberPublic, e := owner.memberPublicKeyLocked(ctx, OrganizationMember{UserID: actor.account}, nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = owner.ConfirmOrganizationMember(ctx, ov, confirmation, memberPublic, nil); e != nil {
				t.Fatal(e)
			}
			av = syncVault(actor)
			orgPublic, e := owner.OrganizationRecoveryPublicKey(ctx, ov, org.ID, false, nil)
			if e != nil {
				t.Fatal(e)
			}
			enrollment, e := actor.PrepareRecoveryEnrollment(ctx, av, org.ID, true, orgPublic, AccountSensitiveInput{Password: password}, nil)
			if e != nil {
				t.Fatal(e)
			}
			commitRecovery(actor, enrollment)
			av = syncVault(actor)
			if _, e = actor.CreatePersonalCipher(ctx, av.Scope, CipherFields{Type: 1, Name: "combined rotation", Login: map[string]any{"username": "fixture", "password": "retained-secret"}}, nil); e != nil {
				t.Fatal(e)
			}
			av = syncVault(actor)
			if _, e = actor.SaveFolder(ctx, av.Scope, "", "retained folder", nil); e != nil {
				t.Fatal(e)
			}
			av = syncVault(actor)
			for _, kind := range []int{0, 1} {
				draft, e := actor.NewSend(av, kind)
				if e != nil {
					t.Fatal(e)
				}
				draft.Fields.Name = "combined Send"
				draft.Fields.Text = "retained text"
				draft.Fields.FileName = "fixture.bin"
				var created *SendDraft
				if kind == 0 {
					created, e = actor.SaveSend(ctx, draft, nil, 0, nil)
				} else {
					created, e = actor.SaveSend(ctx, draft, bytes.NewReader([]byte("binary fixture")), 14, nil)
				}
				draft.Close()
				if e != nil {
					t.Fatal(e)
				}
				created.Close()
				av = syncVault(actor)
			}
			trust := RecoveryRotationTrust{Users: map[string]string{grantee.account: trusted}, Organizations: map[string]string{org.ID: orgPublic}}
			plan, e := actor.PrepareVerifiedAccountRotation(ctx, av, password, trust, nil)
			if e != nil {
				t.Fatal("verified prepare", e)
			}
			defer plan.Close()
			var saved []byte
			defer func() { clear(saved) }()
			api, email := actor.client, actor.email
			underlying := api.http.Transport
			var posts atomic.Int32
			api.http.Transport = accountRoundTrip(func(r *http.Request) (*http.Response, error) {
				if !strings.HasSuffix(r.URL.Path, "/accounts/key-management/rotate-user-account-keys") {
					return underlying.RoundTrip(r)
				}
				posts.Add(1)
				raw, e := io.ReadAll(r.Body)
				if e != nil {
					return nil, e
				}
				r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var request AccountRotationRequest
				json.Unmarshal(raw, &request)
				if mode == "ea-failure" {
					status, _, e := grantee.client.request(ctx, "DELETE", "/api/emergency-access/"+eaID, "", "", grantee.access)
					if e != nil || status != 200 {
						t.Error("inject EA removal", status, e)
					}
				}
				if mode == "recovery-failure" {
					body, _ := json.Marshal(map[string]any{"resetPasswordKey": nil, "masterPasswordHash": request.OldHash})
					status, _, e := api.request(ctx, "PUT", "/api/organizations/"+org.ID+"/users/"+actor.account+"/reset-password-enrollment", "application/json", string(body), actor.access)
					if e != nil || status != 200 {
						t.Error("inject recovery withdrawal", status, e)
					}
				}
				if mode == "cipher-failure" {
					var object map[string]any
					json.Unmarshal(request.Data.Ciphers[0], &object)
					object["folderId"] = fixtureUUID()
					request.Data.Ciphers[0], _ = json.Marshal(object)
					raw, _ = json.Marshal(request)
					r.Body = io.NopCloser(bytes.NewReader(raw))
					r.ContentLength = int64(len(raw))
				}
				response, e := underlying.RoundTrip(r)
				if mode == "lost-response" && e == nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
					return nil, errors.New("fixture dropped final response")
				}
				return response, e
			})
			commitCtx, stopCommit := context.WithCancel(ctx)
			result, e := actor.CommitAccountChange(commitCtx, plan, plan.ConfirmationText(), nil, func(record AccountRecovery) error {
				saved, _ = json.Marshal(record)
				if mode == "not-dispatched" {
					stopCommit()
				}
				return nil
			})
			stopCommit()
			api.http.Transport = underlying
			wantPosts := int32(1)
			if mode == "not-dispatched" {
				wantPosts = 0
			}
			if posts.Load() != wantPosts || len(saved) == 0 {
				t.Fatal("dispatch/recovery binding")
			}
			if mode == "success" {
				if e != nil || !result.Confirmed {
					t.Fatal("success", e)
				}
			} else if mode == "not-dispatched" {
				if e == nil || result.Dispatched || result.Unknown || result.OperationID == "" {
					t.Fatal("non-dispatch not proven", e)
				}
				actor.Close()
			} else if e == nil || !result.Unknown {
				t.Fatal("unknown lost", e)
			}
			var record AccountRecovery
			if json.Unmarshal(saved, &record) != nil {
				t.Fatal("record")
			}
			defer record.Close()
			logged, e := api.LoginMFA(ctx, email, password, "", nil)
			if e != nil {
				t.Fatal("fresh login", e)
			}
			defer logged.Session.Close()
			phase := "unknown"
			if result.Confirmed {
				phase = "confirmed"
			}
			if mode == "not-dispatched" {
				phase = "not-dispatched"
				current := syncVault(logged.Session)
				entries, err := logged.Session.PersonalEntries(current)
				if err != nil || len(entries) != 1 {
					t.Fatal("original inventory", err)
				}
				doc, fields, err := logged.Session.ReadPersonalCipher(current, entries[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				fields.Name = "another client edited this"
				if _, err = logged.Session.UpdatePersonalCipher(ctx, current.Scope, doc, fields, nil); err != nil {
					t.Fatal(err)
				}
				current = syncVault(logged.Session)
				if _, err = logged.Session.CreatePersonalCipher(ctx, current.Scope, CipherFields{Type: 2, Name: "another client added this", SecureNote: map[string]any{"type": 0}}, nil); err != nil {
					t.Fatal(err)
				}
				current = syncVault(logged.Session)
				doc, _, err = logged.Session.ReadPersonalCipher(current, entries[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				if err = logged.Session.ChangePersonalCipherStateAuthorized(ctx, current.Scope, doc, CipherTrash, nil, nil); err != nil {
					t.Fatal(err)
				}
				current = syncVault(logged.Session)
				doc, _, err = logged.Session.ReadPersonalCipher(current, entries[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				if err = logged.Session.ChangePersonalCipherStateAuthorized(ctx, current.Scope, doc, CipherDeletePermanently, nil, nil); err != nil {
					t.Fatal(err)
				}
				current = syncVault(logged.Session)
				folders, err := logged.Session.PersonalFolders(current)
				if err != nil || len(folders) != 1 {
					t.Fatal("folder inventory", err)
				}
				if _, err = logged.Session.SaveFolder(ctx, current.Scope, folders[0].ID, "another client folder name", nil); err != nil {
					t.Fatal(err)
				}
			}
			fresh, proof, e := logged.Session.SyncVerifiedAccountRecovery(ctx, record, phase, nil)
			defer clear(fresh.Session)
			if fresh.PasswordUnlock != nil {
				defer clear(fresh.PasswordUnlock.Key)
			}
			if mode == "not-dispatched" {
				if e != nil || !proof.Ready || proof.Kind != RecoveryEvidenceNoDispatch || len(proof.ExternalCurrentChanges) < 2 {
					t.Fatal("current external changes trapped no-dispatch recovery", e, proof.Issues)
				}
				for _, unproven := range []string{"prepared", "unknown", ""} {
					r, p, err := logged.Session.SyncVerifiedAccountRecovery(ctx, record, unproven, nil)
					clear(r.Session)
					if r.PasswordUnlock != nil {
						clear(r.PasswordUnlock.Key)
					}
					if err == nil || p.Ready {
						t.Fatal("unproven phase borrowed nondispatch", unproven)
					}
				}
			} else if mode == "success" || mode == "lost-response" {
				if e != nil || !proof.Ready || len(proof.ResourceEvidence) != 2 || proof.SendResources.BinaryContentVerified {
					t.Fatal("missing/overstated proof", e, proof.Issues)
				}
				if !bytes.Equal(logged.Session.key, record.NewUserKey) {
					t.Fatal("wrong final key")
				}
				status, body, e := owner.client.request(ctx, "GET", "/api/organizations/"+org.ID+"/users/"+memberID+"/reset-password-details", "", "", owner.access)
				var details struct{ ResetPasswordKey string }
				json.Unmarshal(body, &details)
				var target AccountRotationRequest
				json.Unmarshal(record.Request, &target)
				if e != nil || status != 200 || details.ResetPasswordKey != target.Unlock.Recovery[0].ResetPasswordKey {
					t.Fatal("independent fixture admin readback", status, e)
				}
				// This is fixture-only grantee verification; production never asks another
				// user to initiate emergency recovery just to authorize local resolution.
				for _, step := range []struct {
					client      *Client
					token, path string
				}{{grantee.client, grantee.access, "/api/emergency-access/" + eaID + "/initiate"}, {api, logged.Session.access, "/api/emergency-access/" + eaID + "/approve"}} {
					status, _, e := step.client.request(ctx, "POST", step.path, "application/json", `{}`, step.token)
					if e != nil || status != 200 {
						t.Fatal("fixture emergency transition", status, e)
					}
				}
				status, body, e = grantee.client.request(ctx, "POST", "/api/emergency-access/"+eaID+"/view", "application/json", `{}`, grantee.access)
				var view struct{ KeyEncrypted string }
				json.Unmarshal(body, &view)
				if e != nil || status != 200 || view.KeyEncrypted != target.Unlock.Emergency[0].KeyEncrypted {
					t.Fatal("independent fixture grantee readback", status, e)
				}
			} else {
				if e == nil || proof.Ready {
					t.Fatal("partial stage cleared recovery")
				}
				status, body, e := api.request(ctx, "GET", "/api/accounts/keys", "", "", logged.Session.access)
				var keys struct{ Key, PrivateKey string }
				json.Unmarshal(body, &keys)
				var target AccountRotationRequest
				json.Unmarshal(record.Request, &target)
				if e != nil || status != 200 || keys.Key == target.Unlock.Master.Key || keys.PrivateKey == target.Keys.PrivateKey {
					t.Fatal("partial stage had final witness", status, e)
				}
			}
			t.Log("rotation POST count; journal retained; proof outcome", posts.Load(), mode, proof.Ready)
		})
	}
}
