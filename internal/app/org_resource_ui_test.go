// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/vfasky/mygo-vaultwarden/internal/vaultwarden"
)

func orgResourceUIFixture(t *testing.T) *vaultwarden.ResourceImportPlan {
	t.Helper()
	metadata := json.RawMessage(`{"format":"mygo-organization-backup","version":1,"organizationId":"source-org","collections":[{"id":"source-col","organizationId":"source-org","name":"Source","type":0}],"items":[{"id":"source-item","organizationId":"source-org","collectionIds":["source-col"],"type":2,"name":"Note","favorite":false,"reprompt":0,"secureNote":{"type":0},"folderId":"source-folder","archivedDate":"2026-01-01T00:00:00Z","deletedDate":"2026-01-02T00:00:00Z"}]}`)
	content := []byte("resource body")
	hash := sha256.Sum256(content)
	manifest, err := json.Marshal(map[string]any{"format": "mygo-vaultwarden-resource-backup", "version": 1, "organizationId": "source-org", "metadata": metadata, "resources": []vaultwarden.BackupResource{{CipherID: "source-item", AttachmentID: "source-file", FileName: "test.bin", Path: "files/000000.bin", Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"manifest.json", manifest}, {"files/000000.bin", content}} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		header.SetMode(0600)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		file.Write(entry.data)
	}
	writer.Close()
	file, err := os.CreateTemp("", "mygo-org-resource-ui-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())
	file.Write(buffer.Bytes())
	file.Seek(0, io.SeekStart)
	plan, err := vaultwarden.ParseResourceImport(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plan.Clear)
	return plan
}
func TestOrgResourceExportRequiresExplicitFormatAndConfirmation(t *testing.T) {
	q := make(chan func(), 2)
	normal, resources := 0, 0
	panel := newOrgExportPanelWithResources("Org", true, func(context.Context, string, bool) error { normal++; return nil }, func(context.Context, string) error { resources++; return nil }, func(f func()) { q <- f })
	panel.path = "/tmp/not-written-by-test.mygoresources"
	tester := ui.NewTester(panel.View, 1000, 700)
	clickUI(t, tester, "MyGo 完整组织资源备份（附件与通行密钥，非官方格式）")
	panel.start()
	if panel.flow.running || normal != 0 || resources != 0 {
		t.Fatal("unconfirmed export")
	}
	panel.flow.confirm = true
	panel.start()
	orgUIComplete(t, q)
	if resources != 1 || normal != 0 || !panel.flow.terminal {
		t.Fatal("resource format not routed")
	}
	panel.flow.confirm = true
	panel.start()
	if resources != 1 {
		t.Fatal("automatic repeat")
	}
	panel.Close()
}
func TestOrgResourceImportDefersStateAndTransfersOwnedPlan(t *testing.T) {
	plan := orgResourceUIFixture(t)
	q := make(chan func(), 4)
	var handed *vaultwarden.ResourceImportPlan
	panel, err := newOrgResourceImportPanel(plan, []orgCollectionChoice{{ID: "target-col", Writable: true}}, false, func(_ context.Context, metadata *vaultwarden.OrganizationImportPlan, mappings map[string]string) (vaultwarden.OrganizationOperationResult, error) {
		preview := metadata.PreviewItems()
		if len(preview) != 1 || preview[0].Archived || preview[0].Deleted || mappings["source-col"] != "target-col" {
			t.Error("metadata not explicitly deferred")
		}
		return vaultwarden.OrganizationOperationResult{ImportReconciliation: &vaultwarden.OrganizationImportReconciliation{Items: []vaultwarden.OrganizationImportObservation{{SourceID: "source-item", ServerID: "target-item", Verified: true}}}}, nil
	}, func(resources *vaultwarden.ResourceImportPlan, result vaultwarden.OrganizationOperationResult, err error) {
		handed = resources
		if err != nil || result.ImportReconciliation.Items[0].ServerID != "target-item" {
			t.Error("handoff result")
		}
	}, func(f func()) { q <- f })
	if err != nil {
		t.Fatal(err)
	}
	if panel.ready() || len(panel.resourcePreview) != 1 || !panel.resourceStates[0].Deleted || panel.resourceStates[0].FolderID == nil {
		t.Fatal("source state/preview lost")
	}
	panel.mappings["source-col"] = "target-col"
	panel.flow.confirm = true
	panel.start()
	orgUIComplete(t, q)
	orgUIComplete(t, q)
	panel.Close()
	if handed != plan || len(plan.Resources()) != 1 {
		t.Fatal("plan lost between metadata and resources")
	}
	restore := newOrgResourceRestorePanel(handed, map[string]string{"source-item": "target-item"}, false, orgResourceCallbacks{})
	if len(restore.states) != 1 || restore.states[0].folder != "source-folder" {
		t.Fatal("deferred state not visible")
	}
	restore.Close()
	if len(plan.Resources()) != 0 {
		t.Fatal("close retained archive")
	}
}
func TestOrgResourceRestoreUnknownUploadSyncAndVerify(t *testing.T) {
	plan := orgResourceUIFixture(t)
	q := make(chan func(), 4)
	uploads, verifications, syncs := 0, 0, 0
	panel := newOrgResourceRestorePanel(plan, map[string]string{"source-item": "target-item"}, false, orgResourceCallbacks{
		file: func(_ context.Context, owned *vaultwarden.ResourceImportPlan, index int, target, id string, verify bool) (vaultwarden.AttachmentUploadResult, error) {
			if len(owned.Resources()) != 1 || index != 0 || target != "target-item" {
				t.Error("wrong resource scope")
			}
			if verify {
				verifications++
				if id != "server-file" {
					t.Error("unknown ID not retained")
				}
				return vaultwarden.AttachmentUploadResult{}, nil
			}
			uploads++
			return vaultwarden.AttachmentUploadResult{AttachmentID: "server-file", MetadataCreated: true}, vaultwarden.ErrNetwork
		}, refresh: func(context.Context) error { syncs++; return nil }, dispatch: func(f func()) { q <- f },
	})
	tester := ui.NewTester(panel.View, 1100, 1000)
	clickUI(t, tester, "确认向目标上传一次（保留源文件）")
	orgUIComplete(t, q)
	tester.Frame()
	if uploads != 1 || panel.rows[0].attachmentID != "server-file" || panel.rows[0].state != "待核对" || !panel.needsRefresh {
		t.Fatal("partial upload not retained")
	}
	clickUI(t, tester, "同步并刷新权限后继续")
	orgUIComplete(t, q)
	tester.Frame()
	if syncs != 1 || panel.needsRefresh {
		t.Fatal("refresh gate")
	}
	clickUI(t, tester, "下载并核验所选附件")
	orgUIComplete(t, q)
	tester.Frame()
	if verifications != 1 || uploads != 1 || panel.rows[0].state != "已核验" || !panel.filesVerified("source-item", "target-item") {
		t.Fatal("independent verification missing")
	}
	panel.Close()
}
func TestOrgResourceCloseDuringOperationKeepsPlanUntilWorkerSettles(t *testing.T) {
	plan := orgResourceUIFixture(t)
	q := make(chan func(), 2)
	started := make(chan struct{})
	panel := newOrgResourceRestorePanel(plan, nil, true, orgResourceCallbacks{dispatch: func(f func()) { q <- f }})
	panel.run(func(ctx context.Context) (func(), error) {
		close(started)
		<-ctx.Done()
		if len(plan.Resources()) != 1 {
			t.Error("plan cleared while borrowed")
		}
		return func() { t.Error("late apply") }, vaultwarden.ErrCancelled
	})
	<-started
	panel.Close()
	orgUIComplete(t, q)
	if len(plan.Resources()) != 0 || panel.status != "" {
		t.Fatal("late resource state")
	}
}
