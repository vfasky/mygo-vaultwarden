// SPDX-License-Identifier: GPL-3.0-only
package app

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
)

func preparedResourceTrash(t *testing.T) *resourceControllerFixture {
	t.Helper()
	f := newResourceControllerFixture(t)
	f.open(false)
	m := f.a.backupEditor.resources
	m.trash = []string{"card-1"}
	for i := range m.rows {
		f.file(i, false)
		f.file(i, true)
		if m.rows[i].State != "已核验" {
			t.Fatal(f.a.status)
		}
	}
	return f
}
func (f *resourceControllerFixture) trashResource(refresh func()) {
	f.a.runResourceRestoreWith(0, false, "card-1", f.dispatch, f.storage, refresh)
	f.drain()
}
func resourceTrashForm(f *resourceControllerFixture) *ui.Tester {
	return ui.NewTester(func(c *ui.Context) { f.a.backupResourceRestoreView(c, f.a.backupEditor) }, 1200, 1600)
}
func TestResourceControllerTrashPreflightCanBeExplicitlyRetried(t *testing.T) {
	for _, scenario := range []string{"reprompt", "lease", "download"} {
		t.Run(scenario, func(t *testing.T) {
			f := preparedResourceTrash(t)
			m := f.a.backupEditor.resources
			f.mu.Lock()
			switch scenario {
			case "reprompt":
				f.cipher("card-1")["reprompt"] = 1
			case "lease":
				f.failLease = true
			case "download":
				f.failDownload = true
			}
			f.mu.Unlock()
			if scenario == "reprompt" {
				f.refresh()
				f.drain()
			}
			refreshes := 0
			f.trashResource(func() { refreshes++ })
			if f.trashes != 0 || m.trashPending["card-1"] || m.finalized["card-1"] || m.rows[0].Problem == "" || refreshes != 0 {
				t.Fatalf("preflight became mutation: trashes=%d pending=%v error=%s refreshes=%d", f.trashes, m.trashPending, m.rows[0].Problem, refreshes)
			}
			if !strings.Contains(f.a.status, "尚未提交") {
				t.Fatal(f.a.status)
			}
			form := resourceTrashForm(f)
			form.Frame()
			if !form.HasText("全部文件核验后，确认将目标移入原计划的回收站：card-1") || !form.HasText(m.rows[0].Problem) {
				t.Fatal("confirmation/error hidden")
			}
			f.mu.Lock()
			f.failLease, f.failDownload = false, false
			f.mu.Unlock()
			m.password = "fixture-master"
			f.trashResource(func() { refreshes++ })
			if f.trashes != 1 || !m.trashPending["card-1"] || m.finalized["card-1"] || refreshes != 1 || m.rows[0].Problem != "" {
				t.Fatalf("explicit retry did not dispatch exactly once: trashes=%d status=%s", f.trashes, f.a.status)
			}
			// A normal receipt alone never finalizes; the newly accepted sync does.
			form.Frame()
			if m.finalized["card-1"] {
				t.Fatal("receipt finalized without sync")
			}
			f.trashResource(f.refresh)
			if f.trashes != 1 {
				t.Fatal("receipt replayed")
			}
			f.refresh()
			f.drain()
			form.Frame()
			if !m.finalized["card-1"] {
				t.Fatal("accepted deleted state not reconciled")
			}
			for _, row := range m.rows {
				if row.Target != "card-1" || row.AttachmentID == "" || row.State != "已核验" || row.Resource.CipherID != "card-1" {
					t.Fatalf("lost recovery evidence: %+v", row)
				}
			}
		})
	}
}
func TestResourceControllerTrashUnknownNeverReplays(t *testing.T) {
	f := preparedResourceTrash(t)
	m := f.a.backupEditor.resources
	f.mu.Lock()
	f.unknownTrash = true
	f.mu.Unlock()
	f.trashResource(f.refresh)
	if f.trashes != 1 || !m.trashPending["card-1"] || m.rows[0].Problem == "" {
		t.Fatalf("unknown not preserved: %s", f.a.status)
	}
	form := resourceTrashForm(f)
	for i := 0; i < 3; i++ {
		f.refresh()
		f.drain()
		form.Frame()
		m.password = "fixture-master"
		f.trashResource(f.refresh)
		if f.trashes != 1 || !m.trashPending["card-1"] || m.finalized["card-1"] {
			t.Fatal("active sync incorrectly reopened unknown mutation")
		}
		if form.HasText("全部文件核验后，确认将目标移入原计划的回收站：card-1") {
			t.Fatal("unknown exposed retry")
		}
	}
}
