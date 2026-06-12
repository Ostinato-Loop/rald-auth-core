#!/usr/bin/env bash
# =============================================================================
# RALD — Machine Identity Provisioning Script
# Sprint: Public Beta Hardening · C-CERT-001
# Updated: 2026-06-15 — aligned with seed migration 20260615000000
# =============================================================================
#
# PURPOSE:
#   After running migration 20260615000000_machine_identity_seed.sql,
#   call POST /machine/identities/rotate for each seeded service to replace
#   the placeholder secret_hash with a real cryptographic secret.
#   Outputs `wrangler secret put` commands for each affected worker.
#
# PREREQUISITES:
#   1. Migration 20260615000000_machine_identity_seed.sql applied to prod DB.
#   2. Admin RALD JWT — obtain via:
#        curl -X POST https://auth.rald.cloud/auth/login \
#          -H 'Content-Type: application/json' \
#          -d '{"phone":"ADMIN_PHONE","password":"ADMIN_PASSWORD"}'
#      Then: export RALD_ADMIN_JWT="eyJ..."
#   3. wrangler CLI available in PATH.
#
# USAGE:
#   export RALD_ADMIN_JWT="eyJ..."
#   bash scripts/provision-machine-identities.sh
#
# ROTATION (every 90 days):
#   Re-run this script — it calls /rotate which re-issues the secret.
#   Then re-push the new secret to each worker via wrangler.
#
# SECURITY:
#   Output contains live secrets. Do NOT commit output to Git.
#   Store secrets in a password manager, then push via wrangler secret put.
# =============================================================================

set -euo pipefail

AUTH_URL="https://auth.rald.cloud"
ADMIN_JWT="${RALD_ADMIN_JWT:-}"

if [ -z "$ADMIN_JWT" ]; then
  echo "ERROR: RALD_ADMIN_JWT is not set."
  echo "  export RALD_ADMIN_JWT=\$(curl -s -X POST $AUTH_URL/auth/login \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -d '{\"phone\":\"YOUR_PHONE\",\"password\":\"YOUR_PASS\"}' | jq -r .access_token)"
  exit 1
fi

echo "=================================================================="
echo "  RALD Machine Identity Provisioning"
echo "  C-CERT-001 · $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=================================================================="
echo ""

# key_id values seeded by 20260615000000_machine_identity_seed.sql
# Maps key_id → the repo directory name for wrangler context
declare -A KEY_TO_REPO=(
  ["mid_loop_api_prod_001"]="loop"
  ["mid_messenger_prod_001"]="messenger"
  ["mid_event_bus_prod_001"]="rald-event-bus"
  ["mid_config_prod_001"]="rald-config"
  ["mid_search_prod_001"]="rald-search"
  ["mid_notify_prod_001"]="rald-notify"
  ["mid_realtime_prod_001"]="rald-realtime"
  ["mid_auth_prod_001"]="rald-auth-core"
)

declare -a WRANGLER_COMMANDS=()
FAIL_COUNT=0

for KEY_ID in "${!KEY_TO_REPO[@]}"; do
  REPO="${KEY_TO_REPO[$KEY_ID]}"
  echo "  Rotating: $KEY_ID (repo: $REPO) ..."

  RESPONSE=$(curl -s -X POST "$AUTH_URL/machine/identities/rotate" \
    -H "Authorization: Bearer $ADMIN_JWT" \
    -H "Content-Type: application/json" \
    -d "{\"key_id\": \"$KEY_ID\"}" \
  )

  # Portable JSON extraction via node (available in all CF/Node environments)
  if command -v node &>/dev/null; then
    SECRET=$(echo "$RESPONSE" | node -e "
      let d=''; process.stdin.on('data',c=>d+=c).on('end',()=>{
        try { const r=JSON.parse(d); process.stdout.write(r.secret||''); }
        catch { process.stdout.write(''); }
      })")
    ERR=$(echo "$RESPONSE" | node -e "
      let d=''; process.stdin.on('data',c=>d+=c).on('end',()=>{
        try { const r=JSON.parse(d); process.stdout.write(r.error||''); }
        catch { process.stdout.write('parse_error'); }
      })")
  elif command -v python3 &>/dev/null; then
    SECRET=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('secret',''),end='')" 2>/dev/null || true)
    ERR=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''),end='')" 2>/dev/null || true)
  else
    echo "    ERROR: neither node nor python3 available for JSON parsing"
    echo "    Raw response: $RESPONSE"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    continue
  fi

  if [ -n "$ERR" ]; then
    echo "    ❌ FAILED: $ERR"
    echo "    Raw: $RESPONSE"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  elif [ -z "$SECRET" ]; then
    echo "    ❌ FAILED: empty secret in response"
    echo "    Raw: $RESPONSE"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    echo "    ✅ Rotated: $KEY_ID → secret ready"
    WRANGLER_COMMANDS+=("$KEY_ID|$REPO|$SECRET")
  fi

  sleep 0.3
done

echo ""
echo "=================================================================="
echo "  SECRETS — COPY AND RUN IN EACH REPO DIRECTORY"
echo "  These are live credentials. Treat as passwords."
echo "=================================================================="
echo ""

for ENTRY in "${WRANGLER_COMMANDS[@]}"; do
  IFS='|' read -r KEY_ID REPO SECRET <<< "$ENTRY"
  echo "# ── $REPO ────────────────────────────────────────"
  echo "# cd /path/to/$REPO"
  echo "printf '%s' '$KEY_ID'  | wrangler secret put MACHINE_KEY_ID"
  echo "printf '%s' '$SECRET' | wrangler secret put MACHINE_KEY_SECRET"
  echo ""
done

echo "=================================================================="
echo "  GITHUB ACTIONS — add these to each repo's encrypted secrets:"
echo "    MACHINE_KEY_ID     = <key_id above>"
echo "    MACHINE_KEY_SECRET = <secret above>"
echo ""
echo "  Then in each repo's deploy.yml:"
echo "    - run: |"
echo "        printf '%s' \"\${{ secrets.MACHINE_KEY_ID }}\" \\"
echo "          | wrangler secret put MACHINE_KEY_ID"
echo "        printf '%s' \"\${{ secrets.MACHINE_KEY_SECRET }}\" \\"
echo "          | wrangler secret put MACHINE_KEY_SECRET"
echo "=================================================================="
echo ""
echo "  VERIFICATION (run per-service after secrets are set):"
echo "    curl -X POST https://auth.rald.cloud/machine/auth \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"key_id\":\"<KEY_ID>\",\"secret\":\"<SECRET>\"}'"
echo "    Expected: { ok:true, token:'...', scopes:[...] }"
echo ""
echo "=================================================================="
echo "  NEXT ROTATION DUE: 90 days from today"
echo "  $(date -u -d '+90 days' +%Y-%m-%d 2>/dev/null || date -u -v+90d +%Y-%m-%d 2>/dev/null || echo '(calculate manually)')"
echo "=================================================================="
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "WARNING: $FAIL_COUNT service(s) failed to provision. See errors above."
  exit 1
fi

echo "Provisioning complete. $(date -u +%Y-%m-%dT%H:%M:%SZ)"
