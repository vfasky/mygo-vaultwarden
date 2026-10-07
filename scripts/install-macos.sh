#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
mode="${1:-debug}"
case "$mode" in debug|release) ;; *) echo "Usage: $0 [debug|release] [--no-launch]" >&2; exit 2 ;; esac
launch="${2:-}"
if [[ $# -gt 2 || ( -n "$launch" && "$launch" != --no-launch ) ]]; then
  echo "Usage: $0 [debug|release] [--no-launch]" >&2; exit 2
fi
source_app="$project_root/build/$mode/MyGo Vaultwarden.app"
destination="$HOME/Applications/MyGo Vaultwarden.app"
if [[ ! -d "$source_app" ]]; then
  echo "Build first: bash scripts/build-macos.sh $mode" >&2; exit 1
fi
# Do not replace code while this installation is running.
if ps -axo command= | /usr/bin/grep -Fqx "$destination/Contents/MacOS/MyGo Vaultwarden"; then
  echo "Quit MyGo Vaultwarden before installing an update." >&2; exit 1
fi
codesign --verify --deep --strict "$source_app"
mkdir -p "$HOME/Applications"
staging="$(mktemp -d "$HOME/Applications/.mygo-vaultwarden.XXXXXX")"
cleanup() {
  if [[ -d "$staging/previous.app" && ! -e "$destination" ]]; then
    mv "$staging/previous.app" "$destination" || return
  fi
  rm -rf "$staging"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
ditto "$source_app" "$staging/MyGo Vaultwarden.app"
if [[ -e "$destination" ]]; then
  identifier="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$destination/Contents/Info.plist")"
  if [[ "$identifier" != yz.sh.mygo-vaultwarden ]]; then
    echo "Refusing to replace an unrelated application: $destination" >&2; exit 1
  fi
  mv "$destination" "$staging/previous.app"
fi
if ! mv "$staging/MyGo Vaultwarden.app" "$destination"; then
  if [[ -e "$staging/previous.app" ]]; then mv "$staging/previous.app" "$destination"; fi
  exit 1
fi
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$destination"
/usr/bin/pluginkit -a "$destination/Contents/PlugIns/AutoFill.appex"
if [[ "$launch" != --no-launch ]]; then open "$destination"; fi
printf '\n已安装：%s\n系统自动填充需在“系统设置 > 自动填充与密码”中启用 MyGo Vaultwarden。\n' "$destination"
