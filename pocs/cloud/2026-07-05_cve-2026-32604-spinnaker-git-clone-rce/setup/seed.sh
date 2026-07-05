#!/usr/bin/env bash
# Seed data for Core Spinnaker verification cluster
set -euo pipefail

GATE_URL="${GATE_URL:-http://localhost:8084}"
FRONT50_URL="${FRONT50_URL:-http://localhost:8080}"
FIAT_URL="${FIAT_URL:-http://localhost:7003}"
CLOUDDRIVER_URL="${CLOUDDRIVER_URL:-http://localhost:7002}"

echo "=== Seeding Spinnaker test data ==="

# --- Create applications via Front50 (direct, no auth needed) ---
echo "Creating test applications..."

curl -sf -X POST "$FRONT50_URL/v2/applications" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "testapp",
    "email": "test@example.com",
    "description": "Test application for vulnerability verification",
    "cloudProviders": "aws",
    "instancePort": 80
  }'

curl -sf -X POST "$FRONT50_URL/v2/applications" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "targetapp",
    "email": "target@example.com",
    "description": "Target application (victim) for authorization testing",
    "cloudProviders": "aws",
    "instancePort": 80
  }'

# --- Create application permissions (for Fiat testing) ---
echo "Creating application permissions..."

curl -sf -X POST "$FRONT50_URL/permissions/applications" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "targetapp",
    "permissions": {
      "READ": ["target-team"],
      "WRITE": ["target-team"],
      "EXECUTE": ["target-team"]
    }
  }'

# --- Create a service account ---
echo "Creating service account..."

curl -sf -X POST "$FRONT50_URL/serviceAccounts" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-svc-account@managed-service-account",
    "memberOf": ["target-team"]
  }'

# --- Sync Fiat permissions (picks up LDAP users + roles) ---
echo "Syncing Fiat permissions..."
curl -sf -X POST "$FIAT_URL/roles/sync"

# Wait a moment for sync
sleep 3

# --- Create a pipeline template ---
echo "Creating pipeline template..."

curl -sf -X POST "$FRONT50_URL/v2/pipelineTemplates" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test-template",
    "schema": "v2",
    "metadata": {
      "name": "Test Pipeline Template",
      "description": "Template for verification testing",
      "owner": "test@example.com",
      "scopes": ["global"]
    },
    "pipeline": {
      "type": "templatedPipeline",
      "name": "Template: Test",
      "application": "testapp",
      "stages": [
        {
          "type": "wait",
          "name": "Wait",
          "waitTime": 5
        }
      ]
    }
  }'

# --- Create a pipeline with expectedArtifacts (for CVE-2026-32613) ---
echo "Creating test pipeline with expectedArtifacts..."

curl -sf -X POST "$FRONT50_URL/pipelines" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "spel-test-pipeline",
    "application": "testapp",
    "expectedArtifacts": [
      {
        "id": "test-artifact-1",
        "displayName": "test-artifact",
        "matchArtifact": {
          "type": "embedded/base64",
          "name": "test"
        },
        "defaultArtifact": {
          "type": "embedded/base64",
          "name": "default",
          "reference": "dGVzdA=="
        },
        "useDefaultArtifact": true,
        "usePriorArtifact": false
      }
    ],
    "triggers": [
      {
        "type": "webhook",
        "enabled": true,
        "source": "spel-test"
      }
    ],
    "stages": [
      {
        "type": "wait",
        "name": "Wait",
        "waitTime": 5
      }
    ]
  }'

# --- Create a simple pipeline for Orca execution testing ---
echo "Creating basic test pipeline..."

curl -sf -X POST "$FRONT50_URL/pipelines" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "basic-test-pipeline",
    "application": "testapp",
    "stages": [
      {
        "type": "wait",
        "name": "Wait Stage",
        "waitTime": 5
      }
    ]
  }'

echo ""
echo "=== Seed data created ==="
echo "  Applications: testapp, targetapp"
echo "  Service account: test-svc-account@managed-service-account"
echo "  Pipeline template: test-template"
echo "  Pipelines: spel-test-pipeline, basic-test-pipeline"
echo "  Permissions: targetapp restricted to target-team role"
