#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"
destination="${1:?Usage: collect-licenses.sh destination}"
go_bin="$(bash scripts/resolve-go.sh)"
mkdir -p "$destination"
cp LICENSE "$destination/MyGoVaultwarden-GPL-3.0.txt"
cp THIRD_PARTY_NOTICES.md "$destination/THIRD_PARTY_NOTICES.md"
# The estimator is embedded from the source tree rather than a Go module.
# Preserve the notice's relative paths and all bundled runtime license copies.
strength_licenses="$destination/third_party"
mkdir -p "$strength_licenses/zxcvbn" "$strength_licenses/licenses"
cp third_party/zxcvbn/LICENSE.txt "$strength_licenses/zxcvbn/LICENSE.txt"
cp third_party/licenses/*.txt "$strength_licenses/licenses/"
cp "$("$go_bin" env GOROOT)/LICENSE" "$destination/Go-LICENSE.txt"
# Collect modules actually linked into the app, not unrelated dependency tests.
modules="$("$go_bin" list -deps -f '{{if .Module}}{{.Module.Path}}|{{.Module.Dir}}{{end}}' . | LC_ALL=C sort -u)"
while IFS='|' read -r module directory; do
  [[ "$module" == github.com/vfasky/mygo-vaultwarden || -z "$directory" ]] && continue
  module_name="${module//\//_}"
  while IFS= read -r -d '' license; do
    relative="${license#"$directory/"}"
    target="$destination/$module_name/$relative"
    mkdir -p "$(dirname "$target")"
    cp "$license" "$target"
  done < <(find "$directory" -type f \( -iname 'license*' -o -iname 'copying*' -o -iname 'notice*' \) -print0)
done <<< "$modules"
