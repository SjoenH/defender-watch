#!/usr/bin/env bash
# Build the universal macOS binary from a clean checkout of HEAD, sign it, wrap it in a
# disk image that is notarized and stapled, and publish both as a GitHub Release tagged
# v<version from Cargo.toml>. The download page (GitHub Pages) links to the latest release.
#
#   scripts/release.sh
#
# Needs: a Developer ID Application certificate in the keychain, a notarytool keychain
# profile (default "notary", override with NOTARY_PROFILE; create it once per Mac with
# `xcrun notarytool store-credentials notary --apple-id … --team-id …`, which prompts for
# the app-specific password so it never lands in argv), and `gh` signed in.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
identity="${SIGN_IDENTITY:-Developer ID Application: Henry Skorpe Sjoen (QVCR9867RW)}"
profile="${NOTARY_PROFILE:-notary}"
target_dir="$repo/target-dist"
work="$(mktemp -d)"
trap 'rm -rf "$work"; git -C "$repo" worktree remove --force "$work/src" 2>/dev/null || true' EXIT

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)"
tag="v$version"
[ -z "$(git -C "$repo" status --porcelain)" ] || { echo "Commit or stash your changes first." >&2; exit 1; }
git -C "$repo" fetch -q origin
[ "$(git -C "$repo" rev-parse HEAD)" = "$(git -C "$repo" rev-parse origin/main)" ] \
  || { echo "HEAD is not origin/main; push first so the release matches public code." >&2; exit 1; }
if gh release view "$tag" >/dev/null 2>&1; then
  echo "$tag is already released; bump the version in Cargo.toml." >&2
  exit 1
fi
xcrun notarytool history --keychain-profile "$profile" >/dev/null 2>&1 \
  || { echo "No '$profile' notarytool profile on this Mac (see the comment at the top)." >&2; exit 1; }

git -C "$repo" worktree add --detach "$work/src" HEAD >/dev/null
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  (cd "$work/src" && CARGO_TARGET_DIR="$target_dir" cargo build --release --locked --target "$t")
done
lipo -create -output "$work/defender-watch" \
  "$target_dir/aarch64-apple-darwin/release/defender-watch" \
  "$target_dir/x86_64-apple-darwin/release/defender-watch"
codesign --force --options runtime --timestamp --sign "$identity" "$work/defender-watch"
codesign --verify --strict "$work/defender-watch"

# The disk image is what gets notarized; that also covers the binary inside, so the tar.gz
# (used by install.sh) passes Gatekeeper online, and the stapled DMG opens offline too.
mkdir -p "$work/dmg" "$work/out"
cp "$work/defender-watch" "$work/dmg/"
dmg="$work/out/defender-watch-macos.dmg"
hdiutil create -quiet -volname "Defender Watch" -srcfolder "$work/dmg" -fs HFS+ -format UDZO "$dmg"
codesign --force --timestamp --sign "$identity" "$dmg"
xcrun notarytool submit "$dmg" --keychain-profile "$profile" --wait | tee "$work/notary.log"
grep -q 'status: Accepted' "$work/notary.log" || { echo "Notarization failed" >&2; exit 1; }
xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"

tar -czf "$work/out/defender-watch-macos.tar.gz" -C "$work" defender-watch
(cd "$work/out" && shasum -a 256 defender-watch-macos.dmg defender-watch-macos.tar.gz > SHA256SUMS)

gh release create "$tag" --target "$(git -C "$repo" rev-parse HEAD)" --title "Defender Watch $version" \
  --notes "Universal macOS build (Apple Silicon and Intel), signed with Developer ID and notarized by Apple. Built from $(git -C "$repo" rev-parse --short HEAD) by scripts/release.sh.

- \`defender-watch-macos.dmg\`: open it and run \`defender-watch\`, or copy it to \`~/.local/bin\`.
- \`defender-watch-macos.tar.gz\`: the same binary, used by install.sh.
- \`SHA256SUMS\`: checksums for both." \
  "$work/out/defender-watch-macos.dmg" "$work/out/defender-watch-macos.tar.gz" "$work/out/SHA256SUMS"
echo "Released $tag. The download page picks it up when the Pages workflow reruns."
