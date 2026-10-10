// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/uitest"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

type resourceControllerFixture struct {
	t                                     *testing.T
	a                                     *app
	q                                     chan func()
	mu                                    sync.Mutex
	body                                  map[string]any
	files                                 map[string][]byte
	state                                 *snapshotStatus
	vault                                 *vaultwarden.VaultData
	serial, creates, uploads              int
	failPublish, unknownUpload            bool
	failLease, failDownload, unknownTrash bool
	trashes                               int
	device                                *runtimeDeviceFixture
	additional                            func(http.ResponseWriter, *http.Request) bool
}

func newResourceControllerFixture(t *testing.T, beforeFirstSync ...bool) *resourceControllerFixture {
	t.Helper()
	a := writableUIFixture(t)
	f := &resourceControllerFixture{t: t, a: a, q: make(chan func(), 8), files: map[string][]byte{}}
	json.Unmarshal(a.vault.Sync, &f.body)
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	a.session.Close()
	scope := *a.liveScope
	scope.Server = server.URL
	a.liveScope = &scope
	a.snapshot.Scope = &scope
	a.snapshot.SnapshotID = "initial-snapshot"
	a.vault.Scope = scope
	// Model a password-unlocked session so fresh reprompt uses a real verifier.
	var saved map[string]any
	json.Unmarshal(savedUIFixture(t, a), &saved)
	key, err := vaultwarden.DeriveSnapshotUnlockKey([]byte("fixture-master"), *a.snapshot.PasswordUnlock)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	saved["passwordUnlock"] = &vaultwarden.PasswordUnlock{Config: *a.snapshot.PasswordUnlock, Key: key}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	session, err := vaultwarden.RestoreSessionFromAuthenticatedSnapshot(data, scope, a.snapshot.PasswordUnlock, a.vault, a.sessionRevision)
	if err != nil {
		t.Fatal(err)
	}
	a.session = session
	f.state, f.vault = a.snapshot, a.vault
	// Reopened recovery starts from an authenticated online sync, including the
	// first token checkpoint of this restored Session.
	if len(beforeFirstSync) == 0 || !beforeFirstSync[0] {
		f.refresh()
		f.drain()
	}
	t.Cleanup(func() { a.stopNetwork() })
	return f
}
func (f *resourceControllerFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.additional != nil && f.additional(w, r) {
		return
	}
	if f.device != nil && f.device.serve(w, r) {
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/connect/token"):
		json.NewEncoder(w).Encode(map[string]any{"access_token": "test-access", "refresh_token": "test-refresh", "expires_in": 3600, "token_type": "Bearer"})
	case r.URL.Path == "/api/sync":
		json.NewEncoder(w).Encode(f.body)
	case r.URL.Path == "/api/ciphers" && r.Method == "POST":
		var cipher map[string]any
		if err := json.NewDecoder(r.Body).Decode(&cipher); err != nil {
			f.t.Error(err)
			w.WriteHeader(400)
			return
		}
		f.creates++
		cipher["id"], cipher["revisionDate"], cipher["edit"], cipher["viewPassword"] = fmt.Sprintf("created-%d", f.creates), "2026-01-01T00:00:00Z", true, true
		f.body["ciphers"] = append(f.body["ciphers"].([]any), cipher)
		json.NewEncoder(w).Encode(cipher)
	case strings.HasSuffix(r.URL.Path, "/attachment/v2"):
		parts := strings.Split(r.URL.Path, "/")
		cipher := f.cipher(parts[3])
		if cipher == nil {
			w.WriteHeader(404)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		id := fmt.Sprintf("file-%d", len(f.files)+1)
		f.files[id] = nil
		record := map[string]any{"id": id, "key": body["key"], "fileName": body["fileName"], "size": body["fileSize"], "url": f.a.liveScope.Server + "/download/" + id}
		records, _ := cipher["attachments"].([]any)
		cipher["attachments"] = append(records, record)
		json.NewEncoder(w).Encode(map[string]any{"attachmentId": id, "url": "/ciphers/" + parts[3] + "/attachment/" + id, "fileUploadType": 0, "cipherResponse": cipher})
	case strings.Contains(r.URL.Path, "/attachment/"):
		parts := strings.Split(r.URL.Path, "/")
		id := parts[len(parts)-1]
		if r.Method == "POST" {
			f.uploads++
			reader, err := r.MultipartReader()
			if err != nil {
				f.t.Error(err)
				w.WriteHeader(400)
				return
			}
			part, err := reader.NextPart()
			if err != nil {
				f.t.Error(err)
				w.WriteHeader(400)
				return
			}
			f.files[id], err = io.ReadAll(part)
			if err != nil {
				f.t.Error(err)
			}
			if f.unknownUpload {
				w.WriteHeader(500)
				return
			}
			w.WriteHeader(200)
			return
		}
		cipher := f.cipher(parts[3])
		if cipher != nil {
			for _, v := range cipher["attachments"].([]any) {
				if v.(map[string]any)["id"] == id {
					json.NewEncoder(w).Encode(v)
					return
				}
			}
		}
		w.WriteHeader(404)
	case strings.HasSuffix(r.URL.Path, "/delete") && r.Method == http.MethodPut:
		f.trashes++
		if f.unknownTrash {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				f.t.Error(err)
				return
			}
			conn.Close()
			return
		}
		f.cipher(strings.Split(r.URL.Path, "/")[3])["deletedDate"] = "2026-01-02T00:00:00Z"
		w.WriteHeader(http.StatusOK)
	case strings.HasPrefix(r.URL.Path, "/download/"):
		if f.failDownload {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write(f.files[strings.TrimPrefix(r.URL.Path, "/download/")])
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(404)
	}
}
func (f *resourceControllerFixture) cipher(id string) map[string]any {
	for _, v := range f.body["ciphers"].([]any) {
		c := v.(map[string]any)
		if c["id"] == id {
			return c
		}
	}
	return nil
}
func (f *resourceControllerFixture) storage(r storageRequest) storageReply {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Operation == "status" {
		if f.failLease {
			return storageReply{OK: false}
		}
		return storageReply{OK: true, State: f.state}
	}
	if r.ExpectedRevision != f.state.Revision {
		return storageReply{Code: "stale_revision", State: f.state}
	}
	if r.Operation != "saveSession" && r.Operation != "publishVault" {
		f.t.Errorf("unexpected storage %s", r.Operation)
		return storageReply{}
	}
	if r.Operation == "publishVault" && f.failPublish {
		return storageReply{Code: "write_failed", Message: "injected publication failure"}
	}
	next := *f.state
	f.serial++
	next.Revision = fmt.Sprintf("published-%d", f.serial)
	if r.Operation == "publishVault" {
		next.SnapshotID = fmt.Sprintf("snapshot-%d", f.serial)
		f.vault = r.Vault
	}
	f.state = &next
	return storageReply{OK: true, State: f.state, Vault: f.vault}
}
func (f *resourceControllerFixture) dispatch(fn func()) { f.q <- fn }
func (f *resourceControllerFixture) drain() {
	f.t.Helper()
	for f.a.pending != 0 {
		select {
		case fn := <-f.q:
			fn()
		case <-time.After(10 * time.Second):
			f.t.Fatal("controller callback timeout")
		}
	}
}
func (f *resourceControllerFixture) refresh() {
	f.t.Logf("before sync: %s", f.a.status)
	f.a.syncVaultWith(false, f.dispatch, f.storage)
}
func (f *resourceControllerFixture) plan() *vaultwarden.ResourceImportPlan {
	f.t.Helper()
	metadata, err := f.a.session.(*vaultwarden.Session).ExportPersonalBackup(context.Background(), f.a.vault, []string{"card-1"}, vaultwarden.MyGoBackup)
	if err != nil {
		f.t.Fatal(err)
	}
	content := []byte("file content\x00\xff")
	hash := sha256.Sum256(content)
	resources := []vaultwarden.BackupResource{}
	for i := 0; i < 2; i++ {
		resources = append(resources, vaultwarden.BackupResource{CipherID: "card-1", AttachmentID: fmt.Sprintf("source-%d", i), FileName: fmt.Sprintf("file-%d.bin", i), Path: fmt.Sprintf("files/%06d.bin", i), Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])})
	}
	manifest, _ := json.Marshal(map[string]any{"format": "mygo-vaultwarden-resource-backup", "version": 1, "metadata": json.RawMessage(metadata), "resources": resources})
	file, err := os.CreateTemp("", "mygo-resource-controller-*")
	if err != nil {
		f.t.Fatal(err)
	}
	name := file.Name()
	defer os.Remove(name)
	writer := zip.NewWriter(file)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"manifest.json", manifest}, {"files/000000.bin", content}, {"files/000001.bin", content}} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		header.SetMode(0600)
		out, err := writer.CreateHeader(header)
		if err != nil {
			f.t.Fatal(err)
		}
		out.Write(entry.data)
	}
	if err = writer.Close(); err != nil {
		f.t.Fatal(err)
	}
	file.Seek(0, io.SeekStart)
	plan, err := vaultwarden.ParseResourceImport(context.Background(), file)
	if err != nil {
		file.Close()
		f.t.Fatal(err)
	}
	f.t.Cleanup(plan.Clear)
	return plan
}
func (f *resourceControllerFixture) open(importing bool) {
	plan := f.plan()
	e := &backupEditor{revision: f.a.sessionRevision, format: vaultwarden.MyGoResources, importing: true, resources: resourceEditor(plan), submitted: !importing}
	if importing {
		var err error
		e.plan, err = plan.PersonalRestoreMetadata()
		if err != nil {
			f.t.Fatal(err)
		}
	} else {
		e.resources.targets["card-1"] = "card-1"
		for i := range e.resources.rows {
			e.resources.rows[i].target = "card-1"
		}
	}
	f.a.backupEditor = e
}
func (f *resourceControllerFixture) file(index int, verify bool) {
	f.a.runResourceRestoreWith(index, verify, "", f.dispatch, f.storage, f.refresh)
	f.drain()
}
func TestResourceControllerAcceptedSyncContinuesEveryFile(t *testing.T) {
	for _, mode := range []string{"import", "reopen", "copy"} {
		t.Run(mode, func(t *testing.T) {
			f := newResourceControllerFixture(t, mode == "import")
			f.open(mode == "import")
			if mode == "import" {
				f.a.importBackupWith(f.dispatch, f.storage, f.refresh)
				f.drain()
				if f.creates != 1 {
					t.Fatalf("metadata creates=%d: %s", f.creates, f.a.status)
				}
			}
			e := f.a.backupEditor
			for i := 0; i < 2; i++ {
				f.file(i, false)
				if e.resources.rows[i].attachmentID == "" || !f.a.backupCurrent(e, f.a.epoch) {
					t.Fatalf("upload/sync %d did not continue: %+v status=%s", i, e.resources.rows[i], f.a.status)
				}
				f.file(i, true)
				if e.resources.rows[i].state != "已核验" {
					t.Fatalf("verify %d: %s", i, f.a.status)
				}
			}
			if f.uploads != 2 {
				t.Fatalf("uploads=%d", f.uploads)
			}
			if mode == "copy" {
				f.a.clearBackupEditor()
				f.a.openCipherEditor("card-1", 3)
				if f.a.editor == nil {
					t.Fatal("copy source editor")
				}
				f.a.startResourceCipherCopyWith(f.a.session.(*vaultwarden.Session), f.a.editor, f.dispatch, f.storage, f.refresh)
				f.drain()
				e = f.a.backupEditor
				if e == nil || !e.resources.copyOnly || !f.a.backupCurrent(e, f.a.epoch) || f.creates != 1 {
					t.Fatalf("copy handoff failed: %s", f.a.status)
				}
				for i := 0; i < 2; i++ {
					f.file(i, false)
					f.file(i, true)
					if e.resources.rows[i].state != "已核验" {
						t.Fatalf("copied file %d: %s", i, f.a.status)
					}
				}
				if f.uploads != 4 {
					t.Fatalf("copy uploads=%d", f.uploads)
				}
			}
		})
	}
}
func TestResourceControllerUnknownUploadNeverReplays(t *testing.T) {
	f := newResourceControllerFixture(t)
	f.open(false)
	f.unknownUpload = true
	f.file(0, false)
	e := f.a.backupEditor
	row := &e.resources.rows[0]
	if row.attachmentID == "" || row.state != "待同步核对" || !f.a.backupCurrent(e, f.a.epoch) {
		t.Fatalf("unknown receipt lost: %+v %s", row, f.a.status)
	}
	f.file(0, false)
	if f.uploads != 1 {
		t.Fatal("unknown upload replayed")
	}
	id := row.attachmentID
	row.attachmentID = ""
	f.file(0, true)
	if f.a.pending != 0 || row.state != "待同步核对" {
		t.Fatal("unknown ID accepted")
	}
	row.attachmentID = id
	f.file(0, true)
	if row.state != "已核验" || f.uploads != 1 {
		t.Fatalf("explicit verification failed: %s", f.a.status)
	}
}
func TestResourceControllerRejectedContinuation(t *testing.T) {
	for _, scenario := range []string{"publish-failure", "epoch", "closed", "replaced", "session", "account", "external", "stale-plan", "cleared-plan", "lock"} {
		t.Run(scenario, func(t *testing.T) {
			f := newResourceControllerFixture(t)
			f.open(false)
			e := f.a.backupEditor
			old := e.revision
			if scenario == "publish-failure" {
				f.failPublish = true
			}
			if scenario == "stale-plan" {
				e.revision = "stale-preview"
			}
			f.refresh()
			var complete func()
			select {
			case complete = <-f.q:
			case <-time.After(10 * time.Second):
				t.Fatal("sync callback timeout")
			}
			switch scenario {
			case "epoch":
				f.a.epoch++
			case "closed":
				f.a.clearBackupEditor()
			case "replaced":
				f.a.backupEditor = &backupEditor{revision: old, resources: e.resources, submitted: true}
			case "session":
				original := f.a.session
				f.a.session = &testVaultSession{closed: make(chan struct{})}
				defer original.Close()
			case "account":
				other := *f.a.liveScope
				other.Account = "another-account"
				f.a.liveScope = &other
			case "external":
				next := *f.a.snapshot
				next.Revision, next.SnapshotID = "external-revision", "external-snapshot"
				f.a.observeSnapshot(&next)
			case "cleared-plan":
				e.resources.plan.Clear()
			case "lock":
				f.a.lockInterface()
			}
			complete()
			if e.revision != old && scenario != "stale-plan" {
				t.Fatalf("invalid continuation renewed form: %s", e.revision)
			}
			if scenario == "stale-plan" && e.revision != "stale-preview" {
				t.Fatal("stale preview revived")
			}
			if f.uploads != 0 || f.creates != 0 {
				t.Fatal("sync replayed mutations")
			}
		})
	}
}

func TestResourceControllerRechecksTargetAndReprompt(t *testing.T) {
	for _, scenario := range []string{"missing", "organization", "readonly", "hidden", "reprompt"} {
		t.Run(scenario, func(t *testing.T) {
			f := newResourceControllerFixture(t)
			f.open(false)
			e := f.a.backupEditor
			f.mu.Lock()
			cipher := f.cipher("card-1")
			switch scenario {
			case "missing":
				f.body["ciphers"] = []any{}
			case "organization":
				cipher["organizationId"] = "foreign-org"
			case "readonly":
				cipher["edit"] = false
			case "hidden":
				cipher["viewPassword"] = false
			case "reprompt":
				cipher["reprompt"] = 1
			}
			f.mu.Unlock()
			f.refresh()
			f.drain()
			if !f.a.backupCurrent(e, f.a.epoch) {
				t.Fatalf("accepted sync did not continue form: %s", f.a.status)
			}
			f.file(0, false)
			if f.uploads != 0 || e.resources.rows[0].problem == "" || e.resources.rows[0].state == "已核验" {
				t.Fatalf("target restriction bypassed/hidden: %s %+v", scenario, e.resources.rows[0])
			}
		})
	}
}

func TestResourceControllerCancelDiscardsLateFileCallback(t *testing.T) {
	f := newResourceControllerFixture(t)
	f.open(false)
	e := f.a.backupEditor
	f.a.runResourceRestoreWith(0, false, "", f.dispatch, f.storage, f.refresh)
	var complete func()
	select {
	case complete = <-f.q:
	case <-time.After(10 * time.Second):
		t.Fatal("upload callback timeout")
	}
	f.a.lockInterface()
	complete()
	if f.a.backupEditor != nil || e.resources.plan != nil || e.resources.rows[0].attachmentID != "" || f.a.pending != 0 {
		t.Fatal("late callback revived locked form or retained plan")
	}
	if f.uploads != 1 {
		t.Fatal("unexpected replay or compensation")
	}
}

func TestResourceFormContinueAndCancel(t *testing.T) {
	f := newResourceControllerFixture(t)
	f.open(true)
	e := f.a.backupEditor
	tester := ui.NewTester(func(c *ui.Context) {
		if f.a.backupEditor != nil {
			f.a.backupEditorView(c)
		}
	}, 1200, 1600)
	uitest.Click(t, tester, "仅继续附件恢复，使用已存在的明确目标编号（不创建项目）")
	if e.plan != nil || !e.submitted || e.resources.plan == nil || f.creates != 0 {
		t.Fatal("native continue action created metadata or dropped resources")
	}
	e.resources.rows[0].problem = "目标权限已变化，请核对"
	tester.Frame()
	if !tester.HasText(e.resources.rows[0].problem) {
		t.Fatal("file error hidden by global sync status")
	}
	uitest.Click(t, tester, "取消并关闭导入导出")
	if f.a.backupEditor != nil || len(e.resources.plan.Resources()) != 0 {
		t.Fatal("native cancellation retained resource plan")
	}
}

func TestResourceControllerBareReconcileCannotRenew(t *testing.T) {
	f := newResourceControllerFixture(t)
	f.open(false)
	e := f.a.backupEditor
	next := *f.a.snapshot
	next.Revision = "external"
	next.SnapshotID = "external-snapshot"
	f.a.snapshot = &next
	f.a.sessionRevision = next.Revision
	f.a.itemsRevision = next.Revision
	f.a.reconcileImport()
	if e.revision == next.Revision {
		t.Fatal("bare reconciliation renewed stale form")
	}
	f.file(0, false)
	if f.uploads != 0 {
		t.Fatal("stale form dispatched")
	}
}
