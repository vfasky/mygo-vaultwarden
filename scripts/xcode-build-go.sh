#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Xcode shell phase: Go produces the application's actual Mach-O executable.
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
go_bin="$(bash "$project_root/scripts/resolve-go.sh")"
export PATH="$(dirname "$go_bin"):$PATH"
cd "$project_root"
mkdir -p "$TARGET_BUILD_DIR/$(dirname "$EXECUTABLE_PATH")" "$DERIVED_FILE_DIR/go"
ldflags="-X 'github.com/egoist/mygo.packageName=MyGo Vaultwarden' -X github.com/egoist/mygo.packageIdentifier=$PRODUCT_BUNDLE_IDENTIFIER -X github.com/egoist/mygo.packageVersion=$MARKETING_VERSION"
if [[ "$CONFIGURATION" == Release ]]; then
  ldflags="$ldflags -s -w -X github.com/egoist/mygo.production=1"
fi
binaries=()
for architecture in $ARCHS; do
  case "$architecture" in
    arm64) go_arch=arm64 ;;
    x86_64) go_arch=amd64 ;;
    *) echo "Unsupported architecture: $architecture" >&2; exit 1 ;;
  esac
  output="$DERIVED_FILE_DIR/go/MyGoVaultwarden-$architecture"
  GOOS=darwin GOARCH="$go_arch" CGO_ENABLED=0 "$go_bin" build -trimpath -ldflags "$ldflags" -o "$output" .
  binaries+=("$output")
done
if [[ ${#binaries[@]} -eq 1 ]]; then
  cp "${binaries[0]}" "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"
else
  xcrun lipo -create "${binaries[@]}" -output "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"
fi
bash "$project_root/scripts/xcode-build-bridge.sh"
bash "$project_root/scripts/collect-licenses.sh" "$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Resources/ThirdPartyLicenses"
