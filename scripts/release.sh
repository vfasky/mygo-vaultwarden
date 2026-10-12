#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# Release the version of mygo.json from this Mac: test, build, sign and
# notarize with the local Developer ID (.local/signing.env), sign the update
# with the local update key, then upload a draft GitHub release. See
# docs/updates.md.
set -euo pipefail
project_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_root"

usage() {
  cat >&2 <<'EOF'
Usage: bash scripts/release.sh [--publish] [--skip-tests] [--no-upload] [--yes]
  --publish     publish the release after uploading (default: leave a draft)
  --skip-tests  skip go vet and go test
  --no-upload   build and write the release files only; no tag, no upload
  --yes         do not ask before pushing the tag and uploading
EOF
  exit 2
}
publish=false skip_tests=false upload=true assume_yes=false
for argument in "$@"; do
  case "$argument" in
    --publish) publish=true ;;
    --skip-tests) skip_tests=true ;;
    --no-upload) upload=false ;;
    --yes) assume_yes=true ;;
    *) usage ;;
  esac
done
if [[ "$publish" == true && "$upload" == false ]]; then
  echo "--publish needs the upload." >&2; exit 2
fi
fail() { echo "release: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

step "Checking the release"
version="$(plutil -extract version raw -o - mygo.json)"
tag="v$version"
repo="$(plutil -extract updates.github raw -o - mygo.json 2> /dev/null)" ||
  fail "mygo.json has no updates.github; see docs/updates.md."
project="$(grep -o 'MARKETING_VERSION = [^;]*' macos/MyGoVaultwarden.xcodeproj/project.pbxproj | awk '{print $3}' | sort -u)"
[[ "$project" == "$version" ]] || fail "MARKETING_VERSION is $project, mygo.json version is $version; change both."
grep -Eq "^## \[?v?${version//./\\.}([] ]|$)" CHANGELOG.md || fail "CHANGELOG.md has no \"## $version\" section."
prerelease=false
if [[ "$version" == *-* ]]; then prerelease=true; fi
# The release is built from the commit that the tag names.
[[ -z "$(git status --porcelain)" ]] || fail "Commit or stash the changes in the working tree first."
if [[ "$upload" == true ]]; then
  [[ "$(git branch --show-current)" == main ]] || fail "Release from main."
  command -v gh > /dev/null || fail "Install the GitHub CLI (gh) and run gh auth login."
  gh auth status > /dev/null 2>&1 || fail "Run gh auth login first."
  if state="$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft 2> /dev/null)" && [[ "$state" != true ]]; then
    fail "Release $tag is already published; raise the version."
  fi
fi
if git rev-parse -q --verify "refs/tags/$tag" > /dev/null; then
  [[ "$(git rev-parse "$tag^{commit}")" == "$(git rev-parse HEAD)" ]] || fail "Tag $tag exists on another commit."
fi
# The update key: the environment, the keychain backup, or mygo keygen's file.
if [[ -z "${MYGO_UPDATER_PRIVATE_KEY:-}" ]]; then
  key_file="$HOME/Library/Application Support/mygo/update-keys/mygo-update.key"
  if MYGO_UPDATER_PRIVATE_KEY="$(security find-generic-password -s "MyGo Vaultwarden update signing key" -a mygo-update.key -w 2> /dev/null)"; then
    echo "Update key: login keychain"
  elif [[ -f "$key_file" ]]; then
    MYGO_UPDATER_PRIVATE_KEY="$(< "$key_file")"
    echo "Update key: $key_file"
  else
    fail "No update signing key: set MYGO_UPDATER_PRIVATE_KEY; see docs/updates.md."
  fi
fi
export MYGO_UPDATER_PRIVATE_KEY
echo "Version $version ($tag), repository $repo, publish=$publish"

if [[ "$skip_tests" == false ]]; then
  step "Testing"
  go_bin="$(bash scripts/resolve-go.sh)"
  "$go_bin" vet -tags headless ./...
  "$go_bin" test -tags headless -count=1 ./...
fi

step "Building, signing and notarizing"
bash scripts/build-macos.sh release --notarize
app="build/release/MyGo Vaultwarden.app"

step "Writing the update and download files"
dist="build/updates/$version"
# Files of an earlier attempt at this version are written again.
rm -rf "$dist"
bash scripts/release-update.sh -version "$version" -out "$dist" > /dev/null
download="MyGo-Vaultwarden-$version-macOS.dmg"
bash scripts/make-dmg.sh "$app" "$dist/$download" --notarize
manifest="$(ls "$dist"/update-*.json)"
archive="$(ls "$dist"/*-"$version"-*.tar.gz)"
(cd "$dist" && shasum -a 256 "$download" "$(basename "$archive")" > SHA256SUMS.txt)
plutil -extract notes raw -o "$dist/notes.md" "$manifest"
ls -l "$dist"
if [[ "$upload" == false ]]; then
  printf '\nRelease files are in %s; nothing was uploaded.\n' "$dist"
  exit 0
fi

if [[ "$assume_yes" == false ]]; then
  printf '\nPush tag %s and upload these files to a draft release of %s? [y/N] ' "$tag" "$repo"
  read -r answer
  [[ "$answer" == y || "$answer" == Y ]] || { echo "Stopped; the files stay in $dist."; exit 1; }
fi

step "Pushing $tag"
if ! git rev-parse -q --verify "refs/tags/$tag" > /dev/null; then
  git tag -a "$tag" -m "MyGo Vaultwarden $version"
fi
git push origin "refs/tags/$tag"

step "Uploading the release"
if ! gh release view "$tag" --repo "$repo" > /dev/null 2>&1; then
  arguments=(--repo "$repo" --draft --verify-tag --title "MyGo Vaultwarden $version" --notes-file "$dist/notes.md")
  if [[ "$prerelease" == true ]]; then arguments+=(--prerelease); fi
  gh release create "$tag" "${arguments[@]}"
fi
# The manifest goes last, so it never names an archive that is missing.
gh release upload "$tag" --repo "$repo" --clobber "$dist/$download" "$archive" "$dist/SHA256SUMS.txt"
gh release upload "$tag" --repo "$repo" --clobber "$manifest"
if [[ "$publish" == true ]]; then
  if [[ "$prerelease" == true ]]; then
    gh release edit "$tag" --repo "$repo" --draft=false
  else
    gh release edit "$tag" --repo "$repo" --draft=false --latest
  fi
  printf '\nPublished %s: https://github.com/%s/releases/tag/%s\n' "$tag" "$repo" "$tag"
else
  printf '\nDraft %s uploaded. Review it on GitHub, then publish:\n  gh release edit %s --repo %s --draft=false --latest\n' "$tag" "$tag" "$repo"
fi
