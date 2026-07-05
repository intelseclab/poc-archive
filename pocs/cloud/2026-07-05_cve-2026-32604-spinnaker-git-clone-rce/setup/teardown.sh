#!/usr/bin/env bash
# Teardown script for Core Spinnaker verification cluster
# Cluster: 7601c925-b260-44f4-b6da-01ed07641423
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# SRC_DIR must match the value used for setup.sh — docker compose reads it
# to resolve the source-tree bind mounts when tearing containers down. If unset,
# default to the same bundled clone path setup.sh uses.
DEFAULT_SRC_DIR="$SCRIPT_DIR/spinnaker_src"
if [ -z "${SRC_DIR:-}" ]; then
  SRC_DIR="$DEFAULT_SRC_DIR"
fi
if [ ! -d "$SRC_DIR" ]; then
  echo "ERROR: SRC_DIR='$SRC_DIR' is not a directory." >&2
  echo "Set SRC_DIR to the Spinnaker checkout used for setup.sh, or run ./setup.sh first." >&2
  exit 1
fi
SRC_DIR="$(cd "$SRC_DIR" && pwd)"
export SRC_DIR

cd "$SCRIPT_DIR"

echo "=== Tearing down Core Spinnaker cluster ==="

# Stop and remove all containers, networks
echo "Stopping containers..."
docker compose down 2>/dev/null || true

# Remove persistent volumes (MySQL data)
echo "Removing volumes..."
docker compose down -v 2>/dev/null || true

# Note: We do NOT remove the spinnaker-gradle-cache volume or
# spinnaker-base:local image — those are reusable across runs.
# To fully clean up build artifacts:
#   docker volume rm spinnaker-gradle-cache
#   docker rmi spinnaker-base:local

echo ""
echo "=== Teardown complete ==="
echo "Build artifacts in src/ are preserved (re-run setup.sh without rebuilding)."
echo "To also clean builds: cd $SRC_DIR && ./gradlew clean"
