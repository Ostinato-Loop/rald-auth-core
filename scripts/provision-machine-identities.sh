#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RALD Machine Identity Provisioning Script
# Sprint: Operator Platform Phase 9 · 2026-06-12
# Purpose: Registers all 10 RALD services as machine identities in rald-auth-core.
#          Run once per environment (dev / staging / prod).
#          Output: machine_key for each service — store immediately in Wrangler secrets.
#
# Usage:
#   export RALD_ADMIN_SECRET="<your-admin-secret>"
#   export RALD_AUTH_URL="https://auth.rald.cloud"  # or https://auth-dev.rald.cloud
#   bash scripts/provision-machine-identities.sh [environment]
#
# Requirements: curl, jq
# LILCKY STUDIO LIMITED
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

ENV="${1:-development}"
AUTH_URL="${RALD_AUTH_URL:-https://auth.rald.cloud}"
ADMIN_SECRET="${RALD_ADMIN_SECRET:?RALD_ADMIN_SECRET is required}"
OUTPUT_FILE="./machine-keys-${ENV}-$(date +%Y%m%d%H%M%S).env"

log()  { echo "[$(date -u +%H:%M:%S)] $*"; }
warn() { echo "[$(date -u +%H:%M:%S)] ⚠️  $*" >&2; }
die()  { echo "[$(date -u +%H:%M:%S)] ❌ $*" >&2; exit 1; }

command -v curl >/dev/null || die "curl is required"
command -v jq   >/dev/null || die "jq is required"

log "═══ RALD Machine Identity Provisioning ════════════════════════"
log "Environment : $ENV"
log "Auth URL    : $AUTH_URL"
log "Output      : $OUTPUT_FILE"
log "═════════════════════════════════════════════════════════════════"

echo "# RALD Machine Identity Keys — ${ENV} — $(date -u)" > "$OUTPUT_FILE"
echo "# NEVER commit this file. Add to .gitignore immediately." >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# ── Service registry ─────────────────────────────────────────────────────────
# Format: "service_name|description|scopes (comma-separated)"
SERVICES=(
  "rald-auth-core|RALD Identity & Auth Core|identity:read,identity:write,session:read,session:write,machine:issue"
  "rald-event-bus|RALD Event Bus|events:write,events:read,audit:write,audit:read"
  "rald-config|RALD Config Service|flags:read,flags:write,kill-switch:read,kill-switch:write,country:read,country:write"
  "rald-notify|RALD Notification Service|notify:publish,notify:read,events:read"
  "rald-loop-api|Loop Audio & Community API|events:write,notify:publish,flags:read,identity:read"
  "rald-messenger|RALD Messenger Service|events:write,notify:publish,flags:read,identity:read"
  "rald-mail|RALD Mail Service|events:write,notify:publish,flags:read,identity:read"
  "rald-search|RALD Search Service|events:read,flags:read,identity:read"
  "rald-ai|RALD AI (Sekani)|events:write,notify:publish,flags:read,identity:read"
  "rald-control|RALD Control Center|flags:write,kill-switch:write,country:write,audit:read,identity:read,machine:issue"
)

PROVISIONED=0
FAILED=0

for SVC in "${SERVICES[@]}"; do
  IFS='|' read -r SERVICE_NAME DESCRIPTION SCOPES <<< "$SVC"
  IFS=',' read -ra SCOPE_ARRAY <<< "$SCOPES"

  log "Provisioning: $SERVICE_NAME"

  SCOPE_JSON=$(printf '%s\n' "${SCOPE_ARRAY[@]}" | jq -R . | jq -sc .)

  PAYLOAD=$(jq -n \
    --arg sn "$SERVICE_NAME" \
    --arg desc "$DESCRIPTION" \
    --argjson scopes "$SCOPE_JSON" \
    --arg env "$ENV" \
    '{
      service_name: $sn,
      description:  $desc,
      scopes:       $scopes,
      environment:  $env,
      key_ttl_days: 90
    }')

  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -H "X-Admin-Secret: ${ADMIN_SECRET}" \
    -d "$PAYLOAD" \
    "${AUTH_URL}/machine/identities" 2>/dev/null)

  HTTP_BODY=$(echo "$RESPONSE" | head -n -1)
  HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)

  if [[ "$HTTP_CODE" == "201" ]]; then
    MACHINE_KEY=$(echo "$HTTP_BODY" | jq -r '.machine_key')
    MACHINE_ID=$(echo "$HTTP_BODY" | jq -r '.machine_id')
    log "  ✅ $SERVICE_NAME — machine_id: $MACHINE_ID"
    {
      echo "# $SERVICE_NAME (machine_id: $MACHINE_ID)"
      echo "MACHINE_KEY_$(echo "$SERVICE_NAME" | tr '[:lower:]-' '[:upper:]_')=${MACHINE_KEY}"
      echo ""
    } >> "$OUTPUT_FILE"
    PROVISIONED=$((PROVISIONED + 1))
  else
    warn "$SERVICE_NAME — HTTP $HTTP_CODE: $(echo "$HTTP_BODY" | jq -r '.error // .message // "unknown"')"
    FAILED=$((FAILED + 1))
  fi

  sleep 0.3  # avoid rate limiting
done

log "═════════════════════════════════════════════════════════════════"
log "Provisioned : $PROVISIONED / ${#SERVICES[@]}"
[[ $FAILED -gt 0 ]] && warn "Failed      : $FAILED (re-run for failed services)"
log ""
log "Next steps:"
log "  1. Keys saved to: $OUTPUT_FILE"
log "  2. Set Wrangler secrets for each service:"
log "       wrangler secret put MACHINE_KEY --env $ENV"
log "  3. Delete $OUTPUT_FILE immediately after setting secrets"
log "  4. Add $OUTPUT_FILE to .gitignore if not already present"
log ""
log "Rotate keys every 90 days. See: POST /machine/identities/:id/rotate"
