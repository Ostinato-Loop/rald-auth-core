#!/usr/bin/env bash
# =============================================================================
# RALD — Machine Identity Provisioning Script
# Phase 1 — Public Beta Blocker C-CERT-001
# =============================================================================
#
# PURPOSE:
#   Provisions a machine identity for each RALD service at auth.rald.cloud.
#   Each identity gets a unique key_id + secret that the service uses to
#   exchange for a scoped 1-hour JWT via POST /machine/auth.
#
# PREREQUISITES:
#   1. You must have an admin RALD JWT. Get one:
#      curl -X POST https://auth.rald.cloud/auth/login \
#        -d '{"phone":"YOUR_ADMIN_PHONE","password":"YOUR_ADMIN_PASSWORD"}'
#      Then: export RALD_ADMIN_JWT="<token from response>"
#
#   2. Set your admin JWT:
#      export RALD_ADMIN_JWT="eyJ..."
#
#   3. Run this script:
#      bash scripts/provision-machine-identities.sh
#
# OUTPUT:
#   This script outputs wrangler secret put commands for each service.
#   You MUST run those commands in each service's repo directory.
#   The secret is shown ONCE and cannot be retrieved again.
#
# ROTATION:
#   Machine identities auto-rotate every 90 days. You will receive an
#   email alert 7 days before rotation is due. When rotating:
#     curl -X POST https://auth.rald.cloud/machine/identities/<id>/rotate \
#       -H "Authorization: Bearer $RALD_ADMIN_JWT"
#   Then re-run the wrangler secret put command with the new secret.
# =============================================================================

set -euo pipefail

AUTH_URL="https://auth.rald.cloud"
ADMIN_JWT="${RALD_ADMIN_JWT:-}"

if [ -z "$ADMIN_JWT" ]; then
  echo "ERROR: RALD_ADMIN_JWT is not set."
  echo "  Get your admin JWT:"
  echo "  curl -X POST $AUTH_URL/auth/login -d '{\"phone\":\"YOUR_PHONE\",\"password\":\"YOUR_PASSWORD\"}'"
  echo "  Then: export RALD_ADMIN_JWT=<token>"
  exit 1
fi

echo "============================================================"
echo "  RALD Machine Identity Provisioning"
echo "  Phase 1 — C-CERT-001"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"
echo ""

# Service definitions: name | display | scopes (comma-separated) | allowed services
SERVICES=(
  "loop|Loop API Worker|notify:publish,search:index,inbox:write,realtime:coordinate|messenger,notify,search,inbox,realtime"
  "messenger|Loop Messenger API|notify:publish,search:index,inbox:write|loop,notify,search,inbox"
  "rald-notify|RALD Notify Service|notify:internal|auth,loop,messenger,inbox"
  "rald-search|RALD Search Service|search:internal|auth,loop,messenger"
  "rald-inbox|RALD Inbox Service|inbox:internal,notify:publish|auth,loop,messenger,notify"
  "rald-realtime|RALD Realtime Service|realtime:internal,notify:publish|auth,loop"
  "rald-event-bus|RALD Event Bus|events:publish,events:subscribe|auth,loop,messenger,notify,search,inbox,realtime"
)

echo "Provisioning ${#SERVICES[@]} machine identities..."
echo ""

# Store secrets for operator output
declare -a WRANGLER_COMMANDS

for svc_def in "${SERVICES[@]}"; do
  IFS='|' read -r service_name display_name scopes_csv allowed_csv <<< "$svc_def"

  # Build scopes JSON array
  scopes_json=$(echo "$scopes_csv" | tr ',' '\n' | sed 's/^/"/;s/$/"/' | tr '\n' ',' | sed 's/,$//' | sed 's/^/[/;s/$/]/')
  allowed_json=$(echo "$allowed_csv" | tr ',' '\n' | sed 's/^/"/;s/$/"/' | tr '\n' ',' | sed 's/,$//' | sed 's/^/[/;s/$/]/')

  echo "  Provisioning: $service_name ($display_name)..."

  response=$(curl -s -X POST "$AUTH_URL/machine/identities" \
    -H "Authorization: Bearer $ADMIN_JWT" \
    -H "Content-Type: application/json" \
    -d "{
      \"service_name\": \"$service_name\",
      \"display_name\": \"$display_name\",
      \"description\": \"Machine identity for $display_name — provisioned by Phase 1 script\",
      \"scopes\": $scopes_json,
      \"allowed_services\": $allowed_json,
      \"environment\": \"production\"
    }")

  # Parse response
  ok=$(echo "$response" | node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>{const r=JSON.parse(d.join(''));console.log(r.id ? 'ok' : 'error')})" 2>/dev/null || echo "error")

  if [ "$ok" = "ok" ]; then
    secret=$(echo "$response" | node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>{const r=JSON.parse(d.join(''));console.log(r.secret||'')})") 
    id=$(echo "$response" | node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>{const r=JSON.parse(d.join(''));console.log(r.id||'')})")
    rotation=$(echo "$response" | node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>{const r=JSON.parse(d.join(''));console.log(r.rotation_due_at||'')})")
    echo "    ✅ Provisioned: $service_name (ID: $id, rotation due: $rotation)"
    WRANGLER_COMMANDS+=("$service_name|$secret")
  else
    echo "    ❌ Failed: $service_name"
    echo "    Response: $response"
    echo ""
    echo "  If you got 409 Conflict, this identity already exists."
    echo "  To rotate it, run:"
    echo "    curl -X POST $AUTH_URL/machine/identities/<id>/rotate -H 'Authorization: Bearer \$RALD_ADMIN_JWT'"
  fi

  # Small delay to avoid rate limiting
  sleep 0.5
done

echo ""
echo "============================================================"
echo "  SECRETS — RUN THESE IN EACH SERVICE REPO DIRECTORY"
echo "  (secrets shown ONCE — store in a password manager!)"
echo "============================================================"
echo ""

for entry in "${WRANGLER_COMMANDS[@]}"; do
  IFS='|' read -r svc_name secret <<< "$entry"
  echo "# $svc_name"
  echo "# Run this in the ${svc_name} repo directory:"
  echo "echo '${secret}' | npx wrangler secret put MACHINE_IDENTITY_SECRET --name ${svc_name//-/_}"
  echo ""
done

echo "============================================================"
echo "  ALSO ADD THESE ORG SECRETS TO GITHUB"
echo "  (Settings → Secrets → Actions → New organization secret)"
echo "============================================================"
echo ""
echo "  For each service, add to its GitHub repo secrets:"
echo "  MACHINE_IDENTITY_SECRET = <the secret shown above>"
echo ""
echo "  Then update each service's deploy.yml to include:"
echo '  - run: echo "${{ secrets.MACHINE_IDENTITY_SECRET }}" | npx wrangler secret put MACHINE_IDENTITY_SECRET'
echo ""
echo "============================================================"
echo "  VERIFICATION"
echo "============================================================"
echo ""
echo "  After pushing each secret, verify it works:"
echo ""
echo "  curl -X POST https://auth.rald.cloud/machine/auth \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"key_id\":\"mid_<id>\",\"secret\":\"mid_<id>:<secret>\"}'"
echo ""
echo "  Expected: { ok: true, token: '...', service: '...', scopes: [...] }"
echo ""
echo "Provisioning complete. $(date -u +%Y-%m-%dT%H:%M:%SZ)"
