#!/usr/bin/env bash
set -euo pipefail

# Sync pocindex data files for the CVE search engine.
# Downloads compiled JSON from pocindex.io.
#
# Usage:
#   ./sync-pocindex.sh          # writes to static/data/ (for local hugo server)
#   ./sync-pocindex.sh docs     # writes to docs/data/   (for CI — served by GitHub Pages)

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ "${1:-}" = "docs" ]; then
  DATA_DIR="$REPO_ROOT/docs/data"
else
  DATA_DIR="$REPO_ROOT/static/data"
fi

SOURCE="https://pocindex.io"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

FILES=(
  "trending_poc.json"
  "CVE_list.json"
  "kev.json"
  "cvss.json"
  "nuclei.json"
  "epss.json"
  "repo_meta.json"
  "advisories.json"
)

mkdir -p "$DATA_DIR"

echo "==> Syncing pocindex data from $SOURCE → $DATA_DIR"

FAILED=0
for f in "${FILES[@]}"; do
  echo "  Downloading $f..."
  if curl -fsSL --retry 3 --retry-delay 5 \
    -o "$TMPDIR/$f" \
    "$SOURCE/$f"; then
    if python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$TMPDIR/$f" 2>/dev/null; then
      mv "$TMPDIR/$f" "$DATA_DIR/$f"
      SIZE=$(du -h "$DATA_DIR/$f" | cut -f1)
      echo "    ✓ $f ($SIZE)"
    else
      echo "    ✗ $f — invalid JSON, skipped"
      FAILED=$((FAILED + 1))
    fi
  else
    echo "    ✗ $f — download failed"
    FAILED=$((FAILED + 1))
  fi
done

# Generate stats.json from trending_poc.json metadata + kev.json count
if [ -f "$DATA_DIR/trending_poc.json" ]; then
  python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    meta = json.load(f)
kev_count = 0
try:
    with open(sys.argv[3]) as f:
        kev_count = len(json.load(f))
except Exception:
    kev_count = meta.get('kev', 0)
stats = {
    'total_cves': meta.get('total_cves', 0),
    'with_pocs': meta.get('with_pocs', 0),
    'kev': kev_count,
    'generated': meta.get('generated', ''),
    'synced': '$(date -u +%Y-%m-%dT%H:%M:%SZ)'
}
with open(sys.argv[2], 'w') as f:
    json.dump(stats, f)
" "$DATA_DIR/trending_poc.json" "$DATA_DIR/stats.json" "$DATA_DIR/kev.json"
  echo "  ✓ stats.json (derived)"
fi

if [ "$FAILED" -gt 0 ]; then
  echo "==> WARNING: $FAILED file(s) failed to sync"
  if [ -f "$DATA_DIR/CVE_list.json" ] && [ -f "$DATA_DIR/kev.json" ]; then
    echo "==> Core files present, continuing"
  else
    echo "==> FATAL: Core data files missing"
    exit 1
  fi
fi

echo "==> Sync complete"
ls -lh "$DATA_DIR"/*.json | awk '{print "  " $5 "  " $NF}'
