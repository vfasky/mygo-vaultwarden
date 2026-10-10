#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Full signed Debug app with rebuild/restart on source changes.
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ $# -gt 1 ]]; then
  printf '用法：bash scripts/dev-debug.sh [--watch|--once|--help]\n' >&2
  exit 2
fi
case "${1:---watch}" in
  -h|--help)
    printf '用法：bash scripts/dev-debug.sh [--watch|--once]\n\n默认监听源码变化，完整构建、签名、安装并重启 Debug 应用。\n--once 仅构建、安装并启动一次。\n签名配置：.local/signing.env（MYGO_SIGNING_IDENTITY、MYGO_TEAM_ID）。\n首次运行前请退出已安装的完整应用；原有 mygo dev 预览不受影响。\n热重载会重启进程；主密码或系统认证解锁后，可恢复已保存的登录凭据并继续同步。\n编译失败会保留当前应用。关闭应用或 Ctrl+C 结束监听。\n日志：build/debug/dev-debug.log\n'
    exit 0
    ;;
  --watch|--once) ;;
  *) printf '未知参数：%s\n用法：bash scripts/dev-debug.sh [--watch|--once|--help]\n' "$1" >&2; exit 2 ;;
esac
cd "$project_root"
if [[ "$(uname -s)" != Darwin ]]; then
  printf '完整 Debug 应用需要 macOS 和完整 Xcode。\n' >&2
  exit 1
fi
if ! xcrun --find xcodebuild >/dev/null 2>&1 || ! xcodebuild -version >/dev/null 2>&1; then
  printf '未找到可用的完整 Xcode，请安装并使用 xcode-select 选择 Xcode。\n' >&2
  exit 1
fi
export GO_BIN="$(bash scripts/resolve-go.sh)"
runner_dir="$(mktemp -d "${TMPDIR:-/tmp}/vaultwarden-watch.XXXXXX")"
runner_pid=''
cleanup() {
  if [[ -n "$runner_pid" ]]; then
    kill -TERM "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true
  fi
  rm -rf "$runner_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
"$GO_BIN" build -o "$runner_dir/dev-debug" ./tools/dev-debug
"$runner_dir/dev-debug" "${1:---watch}" &
runner_pid=$!
result=0
wait "$runner_pid" || result=$?
runner_pid=''
exit "$result"
