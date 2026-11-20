#!/usr/bin/env bash
# Render the download page's pictures from demo data (never from this Mac) into site/.
#
#   scripts/screenshots.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
cargo build --release --locked
for shot in explore-day:screenshot demo:overview explore-zoomed:timeline-zoomed management:management protection:protection; do
  ./target/release/defender-watch --scene "${shot%%:*}" --snap "site/${shot##*:}.png" --demo
done
echo "Updated site/*.png; commit them to publish."
