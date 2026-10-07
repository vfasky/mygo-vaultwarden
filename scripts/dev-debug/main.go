// SPDX-License-Identifier: GPL-3.0-only
// Full signed macOS Debug builds with automatic rebuild/restart.
package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const appName = "MyGo Vaultwarden.app"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	if err := run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Print(err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	watch := len(os.Args) == 1 || os.Args[1] == "--watch"
	if len(os.Args) > 2 || (!watch && os.Args[1] != "--once") {
		return errors.New("用法：bash scripts/dev-debug.sh [--watch|--once]")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	exe := filepath.Join(home, "Applications", appName, "Contents", "MacOS", "MyGo Vaultwarden")
	// One installation is shared even when multiple checkouts exist. flock is
	// released by the kernel on exit, so interruption cannot leave a stale lock.
	lockDir := filepath.Join(home, "Library", "Caches", "mygo-vaultwarden")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(lockDir, "dev-debug.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("已有完整 Debug 构建或监听进程，请复用它，或先在其终端按 Ctrl+C")
	}
	if err := requireStopped(exe); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "build", "debug"), 0o755); err != nil {
		return err
	}
	logPath := filepath.Join(root, "build", "debug", "dev-debug.log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	output := io.MultiWriter(os.Stdout, file)
	logger := log.New(output, "[dev-debug] ", log.Ltime)
	build := func(ctx context.Context) error {
		return command(ctx, root, output, "bash", "scripts/build-macos.sh", "debug")
	}
	install := func(ctx context.Context, launch bool) error {
		args := []string{"scripts/install-macos.sh", "debug"}
		if !launch {
			args = append(args, "--no-launch")
		}
		return command(ctx, root, output, "bash", args...)
	}
	logger.Printf("日志：%s", logPath)
	if !watch {
		if err := build(ctx); err != nil {
			return fmt.Errorf("构建失败：%w；日志：%s", err, logPath)
		}
		if err := install(ctx, true); err != nil {
			return fmt.Errorf("安装与启动失败：%w", err)
		}
		logger.Print("完整 Debug 应用已安装，启动请求已发送。")
		return nil
	}
	logger.Print("监听 Go、Swift、资源和构建配置；保存后自动构建并重启。关闭应用或 Ctrl+C 结束。")
	logger.Print("重启会清除内存中的登录状态；已有加密快照可通过系统认证解锁。")
	return watchLoop(ctx, root, exe, output, logger, build, install)
}

// Refuse to take over an app launched outside this watcher. Never kill by name.
func requireStopped(exe string) error {
	out, err := exec.Command("ps", "-axo", "comm=").Output()
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == exe {
			return fmt.Errorf("请先退出完整应用，再启动监听：%s", exe)
		}
	}
	return nil
}

// Cancel the whole build process group, including xcodebuild and its children,
// and wait for it before releasing the installation lock.
func command(ctx context.Context, root string, output io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = root, output, output
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func sourceFile(path string) bool {
	path = filepath.ToSlash(path)
	if path == "go.mod" || path == "go.sum" || path == "mygo.json" || path == "mygo.config.ts" {
		return true
	}
	if strings.HasPrefix(path, "resources/") || strings.HasPrefix(path, "macos/") {
		return true
	}
	if strings.HasPrefix(path, "scripts/dev-debug/") {
		return false // the watcher itself must be restarted when edited
	}
	switch filepath.Ext(path) {
	case ".go":
		return true
	case ".sh":
		return strings.HasPrefix(path, "scripts/")
	}
	return false
}

// Content fingerprints catch renames/deletions and edits during a build,
// while ignoring timestamps and generated outputs (no rebuild loops).
func fingerprint(root string) ([32]byte, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "build", "node_modules", "xcuserdata":
				return filepath.SkipDir
			}
			if strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceFile(rel) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%x\n", filepath.ToSlash(rel), sha256.Sum256(data))
		return nil
	})
	// Configuration may contain credentials; hash its contents, never log them.
	if err == nil {
		data, readErr := os.ReadFile(filepath.Join(root, ".local", "signing.env"))
		if readErr != nil && !os.IsNotExist(readErr) {
			err = readErr
		}
		fmt.Fprintf(h, "signing\x00%t\x00%x", readErr == nil, sha256.Sum256(data))
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, err
}

func watchLoop(ctx context.Context, root, exe string, output io.Writer, logger *log.Logger,
	build func(context.Context) error, install func(context.Context, bool) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	observed, err := fingerprint(root)
	if err != nil {
		return err
	}
	var attempted [32]byte
	var app *liveApp
	var appDone <-chan struct{}
	var building <-chan error
	defer func() {
		cancel()
		if building != nil {
			<-building
		}
		if app != nil {
			app.stop()
		}
	}()
	lastChange := time.Now()
	start := func() {
		attempted = observed
		logger.Print("开始完整 Debug 构建…")
		result := make(chan error, 1)
		building = result
		go func() { result <- build(ctx) }()
	}
	start()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Print("停止监听。")
			return ctx.Err()
		case <-appDone:
			logger.Print("应用已退出，结束监听。")
			return app.err
		case err := <-building:
			building = nil
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				logger.Printf("构建失败，当前应用保持运行；保存修改后重试：%v", err)
				continue
			}
			// Recheck before stopping the app: a build may have read mixed versions.
			current, err := fingerprint(root)
			if err != nil {
				return err
			}
			observed = current
			if observed != attempted {
				logger.Print("构建期间源码又有变化，继续构建最新版本，当前应用保持运行。")
				start()
				continue
			}
			logger.Print("构建及签名验证通过，准备重启。")
			if app != nil {
				select {
				case <-app.done:
					logger.Print("应用已退出，结束监听。")
					return app.err
				default:
				}
				app.stop()
				app, appDone = nil, nil
			}
			if err := requireStopped(exe); err != nil {
				return err
			}
			if err := install(ctx, false); err != nil {
				return fmt.Errorf("安装失败：%w", err)
			}
			app, err = launch(ctx, root, exe, output)
			if err != nil {
				return err
			}
			appDone = app.done
			logger.Printf("应用进程已启动，PID=%d；等待源码变化。", app.cmd.Process.Pid)
		case <-ticker.C:
			current, err := fingerprint(root)
			if err != nil {
				logger.Printf("暂时无法读取源码，等待下一次扫描：%v", err)
				continue
			}
			if current != observed {
				observed, lastChange = current, time.Now()
			}
			if building == nil && observed != attempted && time.Since(lastChange) >= 750*time.Millisecond {
				start()
			}
		}
	}
}

type liveApp struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error // read only after done closes
}

func (app *liveApp) stop() {
	select {
	case <-app.done:
		return
	default:
	}
	_ = app.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-app.done:
	case <-time.After(10 * time.Second):
		_ = app.cmd.Process.Kill()
		<-app.done
	}
}

func launch(ctx context.Context, root, exe string, output io.Writer) (*liveApp, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The full app is sandboxed. Track the owned process directly instead of
	// MyGo's development ready socket in an external temporary directory.
	// Starting the process does not attest that its window or storage is ready.
	cmd := exec.Command(exe)
	cmd.Dir, cmd.Stdout, cmd.Stderr = root, output, output
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	app := &liveApp{cmd: cmd, done: make(chan struct{})}
	go func() {
		app.err = cmd.Wait()
		close(app.done)
	}()
	return app, nil
}
