#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
if [[ -n "${GO_BIN:-}" ]]; then
  [[ -x "$GO_BIN" ]] || { echo "GO_BIN is not executable: $GO_BIN" >&2; exit 1; }
  printf '%s\n' "$GO_BIN"
elif command -v go >/dev/null 2>&1; then
  command -v go
elif [[ -x /opt/homebrew/bin/go ]]; then
  printf '%s\n' /opt/homebrew/bin/go
elif [[ -x /usr/local/bin/go ]]; then
  printf '%s\n' /usr/local/bin/go
elif [[ -x "$HOME/Library/Caches/mygo-vaultwarden/toolchains/go1.27.1/bin/go" ]]; then
  printf '%s\n' "$HOME/Library/Caches/mygo-vaultwarden/toolchains/go1.27.1/bin/go"
else
  echo "Go 1.27.1+ is required. Install Go or set GO_BIN to its absolute executable path." >&2
  exit 1
fi
