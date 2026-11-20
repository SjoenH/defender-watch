#!/bin/sh
# Installerer Defender Watch i ~/.local/bin (eller $DEFENDER_WATCH_DIR).
set -eu

base="https://github.com/SjoenH/defender-watch/releases/latest/download"
dir="${DEFENDER_WATCH_DIR:-$HOME/.local/bin}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "Defender Watch kjører bare på macOS." >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Laster ned Defender Watch ..."
curl -fsSL -o "$tmp/defender-watch-macos.tar.gz" "$base/defender-watch-macos.tar.gz"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
(cd "$tmp" && grep ' defender-watch-macos.tar.gz$' SHA256SUMS | shasum -a 256 -c - >/dev/null) \
  || { echo "Sjekksummen stemmer ikke. Avbryter." >&2; exit 1; }

mkdir -p "$dir"
tar -xzf "$tmp/defender-watch-macos.tar.gz" -C "$tmp"
install -m 755 "$tmp/defender-watch" "$dir/defender-watch"

echo "Installert: $dir/defender-watch"
case ":$PATH:" in
  *":$dir:"*) echo "Start med: defender-watch" ;;
  *) echo "Legg $dir i PATH, eller start med: $dir/defender-watch" ;;
esac
