#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Run after build-macos.sh release --notarize. Never signs or uploads.
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
app="build/release/MyGo Vaultwarden.app"
args=("$@")
# Validate exactly the bundle passed to the Go tool, including -app=value.
while [[ $# -gt 0 ]]; do
  case "$1" in
    -app|--app)
      if [[ $# -lt 2 ]]; then echo "Missing -app value." >&2; exit 2; fi
      app="$2"; shift 2 ;;
    -app=*|--app=*) app="${1#*=}"; shift ;;
    *) shift ;;
  esac
done
codesign --verify --deep --strict "$app"
xcrun stapler validate "$app"
go_bin="$(bash scripts/resolve-go.sh)"
"$go_bin" run ./tools/release-update "${args[@]}"
