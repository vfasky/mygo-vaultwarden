#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
output="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Frameworks"
mkdir -p "$output" "$DERIVED_FILE_DIR/swift-bridge"
binaries=()
for architecture in $ARCHS; do
  binary="$DERIVED_FILE_DIR/swift-bridge/libSnapshotBridge-$architecture.dylib"
  xcrun swiftc -emit-library -O -swift-version 5 -module-name SnapshotBridge \
    -module-cache-path "$DERIVED_FILE_DIR/swift-bridge/modules" \
    -target "$architecture-apple-macos$MACOSX_DEPLOYMENT_TARGET" \
    -Xlinker -install_name -Xlinker @rpath/libSnapshotBridge.dylib \
    -framework AuthenticationServices \
    "$project_root"/macos/Shared/*.swift "$project_root"/macos/Bridge/*.swift \
    "$project_root"/macos/UpdateHelper/UpdateHelperProtocol.swift \
    "$project_root"/macos/Authentication/VaultAuthentication.swift \
    "$project_root"/macos/Authentication/AuthenticationBridge.swift -o "$binary"
  binaries+=("$binary")
done
if [[ ${#binaries[@]} -eq 1 ]]; then
  cp "${binaries[0]}" "$output/libSnapshotBridge.dylib"
else
  xcrun lipo -create "${binaries[@]}" -output "$output/libSnapshotBridge.dylib"
fi
if [[ "${CODE_SIGNING_ALLOWED:-YES}" != NO ]]; then
  [[ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]] || { echo "Missing bridge signing identity" >&2; exit 1; }
  codesign --force --options runtime --timestamp=none --sign "$EXPANDED_CODE_SIGN_IDENTITY" "$output/libSnapshotBridge.dylib"
fi
