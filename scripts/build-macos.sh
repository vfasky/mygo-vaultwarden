#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Signing settings come from the environment or ignored local configuration.
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
mode="${1:-debug}"
case "$mode" in
  debug) configuration=Debug ;;
  release) configuration=Release ;;
  *) echo "Usage: $0 [debug|release] [--notarize] [--arch arm64|x86_64]" >&2; exit 2 ;;
esac
shift || true
notarize="" arch=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --notarize) notarize=--notarize; shift ;;
    --arch)
      [[ $# -ge 2 ]] || { echo "Missing --arch value." >&2; exit 2; }
      arch="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
case "$arch" in
  ""|arm64|x86_64) ;;
  *) echo "Unsupported architecture: $arch (arm64 or x86_64)" >&2; exit 2 ;;
esac
if [[ "$notarize" == --notarize && "$mode" != release ]]; then
  echo "Notarization requires release mode." >&2; exit 2
fi
if [[ -f "$project_root/.local/signing.env" ]]; then
  source "$project_root/.local/signing.env"
fi
identity="${MYGO_SIGNING_IDENTITY:-${WAKU_CODESIGN_IDENTITY:-${WAKU_SIGNING_IDENTITY:-}}}"
team="${MYGO_TEAM_ID:-}"
profile="${MYGO_NOTARY_PROFILE:-${WAKU_NOTARY_PROFILE:-}}"
if [[ -z "$identity" || -z "$team" ]]; then
  echo "Set MYGO_SIGNING_IDENTITY and MYGO_TEAM_ID in .local/signing.env or the environment." >&2; exit 1
fi
if [[ "$notarize" == --notarize && -z "$profile" ]]; then
  echo "Set MYGO_NOTARY_PROFILE in .local/signing.env or the environment for notarization." >&2; exit 1
fi
if [[ "$identity" == "-" ]]; then
  echo "AutoFill requires a real identity and provisioning profiles, not ad-hoc signing." >&2; exit 1
fi
identity_hash="$(security find-identity -v -p codesigning | awk -v identity="$identity" 'index($0, "\"" identity "\"") || $2 == identity { if (!/CSSMERR/) { print $2; exit } }')"
if [[ -z "$identity_hash" ]]; then
  echo "Missing signing identity: $identity" >&2; exit 1
fi
export GO_BIN="$(bash scripts/resolve-go.sh)"
# One architecture per build: build/release-arm64, build/release-x86_64.
# Without --arch Xcode builds the default (universal) app into build/<mode>.
output="$project_root/build/$mode${arch:+-$arch}"
arch_settings=()
if [[ -n "$arch" ]]; then arch_settings=("ARCHS=$arch" ONLY_ACTIVE_ARCH=NO); fi
mkdir -p "$output"
staging="$(mktemp -d "$output/.staging.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
archive="$project_root/build/MyGoVaultwarden-$mode${arch:+-$arch}.xcarchive"

# Both targets carry restricted AutoFill entitlements. Xcode first provisions
# the app IDs for development, then issues/reuses Developer ID profiles during
# export. A direct codesign without profiles passes static verification but
# macOS refuses to launch it (AMFI -413); never silently fall back to that.
xcodebuild -project macos/MyGoVaultwarden.xcodeproj -scheme MyGoVaultwarden \
  -configuration "$configuration" -derivedDataPath build/ArchiveDerivedData \
  -archivePath "$archive" -destination 'generic/platform=macOS' \
  "DEVELOPMENT_TEAM=$team" ${arch_settings[@]+"${arch_settings[@]}"} -allowProvisioningUpdates archive
cp macos/ExportOptions.plist "$staging/ExportOptions.plist"
plutil -replace teamID -string "$team" "$staging/ExportOptions.plist"
plutil -replace signingCertificate -string "$identity_hash" "$staging/ExportOptions.plist"
xcodebuild -exportArchive -archivePath "$archive" -exportPath "$staging/export" \
  -exportOptionsPlist "$staging/ExportOptions.plist" -allowProvisioningUpdates
app="$staging/export/MyGo Vaultwarden.app"
extension="$app/Contents/PlugIns/AutoFill.appex"
if [[ ! -f "$app/Contents/Frameworks/libSnapshotBridge.dylib" ]]; then
  echo "Missing secure snapshot bridge." >&2; exit 1
fi
for bundle in "$app" "$extension"; do
  if [[ ! -f "$bundle/Contents/embedded.provisionprofile" ]]; then
    echo "Missing required provisioning profile: $bundle" >&2; exit 1
  fi
  codesign --verify --strict --verbose=2 "$bundle"
done
codesign --verify --deep --strict --verbose=2 "$app"

if [[ "$notarize" == --notarize ]]; then
  ditto -c -k --keepParent "$app" "$staging/notarization.zip"
  xcrun notarytool submit "$staging/notarization.zip" --keychain-profile "$profile" --wait
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
fi

# Publish only a completely exported, profile-bearing, verified app.
final="$output/MyGo Vaultwarden.app"
previous="$output/.previous.app"
if [[ -e "$previous" ]]; then
  echo "An interrupted publish left $previous; inspect it before rebuilding." >&2
  exit 1
fi
if [[ -e "$final" ]]; then mv "$final" "$previous"; fi
if ! mv "$app" "$final"; then
  if [[ -e "$previous" ]]; then mv "$previous" "$final"; fi
  exit 1
fi
rm -rf "$previous"
printf '\nDeveloper ID application: %s\n' "$final"
printf 'Profiles embedded; signature verification passed. System enablement and Safari filling require separate validation.\n'
