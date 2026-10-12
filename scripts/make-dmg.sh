#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Package a signed, notarized app into a disk image whose window shows the app
# next to an Applications link to drag it onto. Needs create-dmg
# (brew install create-dmg) and a Mac with a login session for the Finder layout.
# Usage: scripts/make-dmg.sh <app> <output.dmg> [--notarize]
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
[[ $# -ge 2 ]] || { echo "Usage: $0 <app> <output.dmg> [--notarize]" >&2; exit 2; }
app="$1" dmg="$2" notarize="${3:-}"
[[ -d "$app" ]] || { echo "Missing app: $app" >&2; exit 1; }
if [[ -n "$notarize" && "$notarize" != --notarize ]]; then echo "Unknown option: $notarize" >&2; exit 2; fi
command -v create-dmg > /dev/null || { echo "Install create-dmg: brew install create-dmg" >&2; exit 1; }
if [[ -f "$project_root/.local/signing.env" ]]; then source "$project_root/.local/signing.env"; fi
identity="${MYGO_SIGNING_IDENTITY:-}"
profile="${MYGO_NOTARY_PROFILE:-}"
[[ -n "$identity" ]] || { echo "Set MYGO_SIGNING_IDENTITY in .local/signing.env or the environment." >&2; exit 1; }
if [[ "$notarize" == --notarize && -z "$profile" ]]; then
  echo "Set MYGO_NOTARY_PROFILE for notarization." >&2; exit 1
fi

name="$(basename "$app")"
stage="$(mktemp -d "${TMPDIR:-/tmp}/mygo-dmg.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
ditto --noclone "$app" "$stage/$name"
rm -f "$dmg"
arguments=(
  --volname "MyGo Vaultwarden"
  --volicon "$app/Contents/Resources/AppIcon.icns"
  --window-pos 200 160 --window-size 560 360
  --icon-size 112 --text-size 13
  --icon "$name" 150 170 --hide-extension "$name"
  --app-drop-link 410 170
  --format ULMO --codesign "$identity"
)
if [[ "$notarize" == --notarize ]]; then arguments+=(--notarize "$profile"); fi
create-dmg "${arguments[@]}" "$dmg" "$stage"
echo "Created $dmg"
