// SPDX-License-Identifier: GPL-3.0-only
//go:build darwin && sandboxprobe

// Command sandboxprobe exercises real native panels and the production fileio
// primitives without any account or network. Build and sign as described in
// docs/sandbox-file-access.md; an unsigned run is not sandbox evidence.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/egoist/mygo"
	"github.com/vfasky/mygo-vaultwarden/internal/fileio"
	"github.com/vfasky/mygo-vaultwarden/internal/i18n"
	"github.com/vfasky/mygo-vaultwarden/internal/ui/send"
)

const fixture = "sandbox probe fixture\n"

func main() {
	result := make(chan error, 1)
	mygo.App.WhenReady(func() {
		go func() {
			err := probe()
			if err != nil {
				fmt.Fprintln(os.Stderr, "FAIL:", err)
			} else {
				fmt.Println("PASS: selected-file read, directory-granted staging, no-replace publication, attachment stream")
			}
			result <- err
			mygo.App.Quit()
		}()
	})
	if err := mygo.App.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	select {
	case err := <-result:
		if err != nil {
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "FAIL: probe interrupted")
		os.Exit(1)
	}
}

func probe() error {
	ctx := context.Background()
	paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Title: i18n.T("选择 Send 文件")})
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		return fmt.Errorf("fixture selection cancelled")
	}
	data, err := fileio.ReadBackupFile(ctx, paths[0])
	if err != nil {
		return err
	}
	defer clear(data)
	if !bytes.Equal(data, []byte(fixture)) {
		return fmt.Errorf("select only the documented synthetic fixture")
	}
	input, err := fileio.OpenAttachmentInput(paths[0])
	if err != nil {
		return err
	}
	defer input.Close()
	path, err := send.ChooseExportPath(ctx, mygo.SaveDialogOptions{Title: i18n.T("保存 Send 文件"), DefaultPath: "sandbox-probe-output.txt"})
	if err != nil {
		return err
	}
	stage, err := fileio.StageBackupFile(ctx, path, data)
	if err != nil {
		return err
	}
	defer stage.Close()
	if err = stage.Commit(); err != nil {
		return err
	}
	if duplicate, err := fileio.StageBackupFile(ctx, path, data); err == nil {
		duplicate.Close()
		return fmt.Errorf("no-replace check failed")
	}
	attachment, err := fileio.StageAttachmentFile(ctx, path+".attachment", input, int64(len(fixture)))
	if err != nil {
		return err
	}
	defer attachment.Close()
	return attachment.Commit()
}
