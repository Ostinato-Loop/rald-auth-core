#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RALD Machine Identity — End-to-End Integration Test
# Sprint: Operator Platform Phase 9 · 2026-06-12
# Purpose: Proves C-CERT-001 is satisfied. Provisions a test machine identity,
#          exchanges it for a JWT, validates the token claims, then smoke-tests
#          every protected route across rald-event-bus, rald-config, rald-notify.
#
# Usage:
#   export RALD_ADMIN_SECRET="<admin-secret>"
#   bash scripts/test-machine-identity-e2e.sh [environment]
#
# Environment variables (with defaults):
#   RALD_AUTH_URL     — default: https://auth.rald.cloud
#   RALD_EVENTS_URL   — default: https://events.rald.cloud
#   RALD_CONFIG_URL   — default: https://config.rald.cloud
#   RALD_NOTIFY_URL   — default: https://notification.rald.cloud
#
# Exit codes: 0 = all checks passed · 1 = one or more failures
# Requirements: curl, jq
# LILCKY STUDIO LIMITED
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
ENV="${1:-production}"
AUTH_URL="${RALD_AUTH_URL:-https://auth.rald.cloud}"
EVENTS_URL="${RALD_EVENTS_URL:-https://events.rald.cloud}"
CONFIG_URL="${RALD_CONFIG_URL:-https://config.rald.cloud}"
NOTIFY_URL="${RALD_NOTIFY_URL:-https://notification.rald.cloud}"
ADMIN_SECRET="${RALD_ADMIN_SECRET:?RALD_ADMIN_SECRET is required}"

# ── Helpers ───────────────────────────────────────────────────────────────────
PASS=0; FAIL=0; IDENTITY_ID=""; TOKEN=""

log()  { echo "[$(date -u +%H:%M:%S)] $*"; }
ok()   { echo "  ✅ $*"; ((PASS++)) || true; }
fail() { echo "  ❌ $*"; ((FAIL++)) || true; }
info() { echo "  ℹ️  $*"; }

command -v curl >/dev/null || { echo "❌ curl required"; exit 1; }
command -v jq   >/dev/null || { echo "❌ jq required";   exit 1; }

# Decode a JWT payload (base64url → JSON) — no crypto, just inspection
jwt_payload() {
  local token="$1"
  local body
  body=$(echo "$token" | cut -d. -f2)
  # Pad base64url to base64
  local padded="${body}$(printf '=%.0s' {1..$(( (4 - ${#body} % 4) % 4 ))})"
  echo "$padded" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r . 2>/dev/null || echo "{}"
}

# HTTP probe: returns status code
http_status() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

header_auth()  { echo "-H" "X-Machine-Token: $TOKEN"; }

separator() { echo ""; echo "────────────────────────────────────────────────────"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════"
echo "  RALD Machine Identity E2E Integration Test"
echo "  Environment : $ENV"
echo "  Auth        : $AUTH_URL"
echo "  Events      : $EVENTS_URL"
echo "  Config      : $CONFIG_URL"
echo "  Notify      : $NOTIFY_URL"
echo "══════════════════════════════════════════════════════════"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — Health checks
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 1 — Service health checks"

for SVC in \
  "rald-auth-core:$AUTH_URL/health" \
  "rald-event-bus:$EVENTS_URL/health" \
  "rald-config:$CONFIG_URL/health" \
  "rald-notify:$NOTIFY_URL/health"; do
  NAME="${SVC%%:*}"; URL="${SVC#*:}"
  STATUS=$(http_status "$URL")
  [[ "$STATUS" == "200" ]] && ok "$NAME → $STATUS" || fail "$NAME → $STATUS (expected 200)"
done

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — Provision test machine identity
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 2 — Provision test machine identity"

TEST_SERVICE="rald-e2e-test-runner-$(date +%s)"
PROVISION=$(curl -s -X POST "$AUTH_URL/machine/identities" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -d "$(jq -n \
    --arg sn "$TEST_SERVICE" \
    '{
      service_name:     $sn,
      display_name:     "E2E Test Runner (ephemeral)",
      description:      "Automated integration test — safe to delete",
      scopes:           ["audit:write","audit:read","kill-switch:write","notify:publish","events:write","events:read","flags:read"],
      allowed_services: ["rald-event-bus","rald-config","rald-notify"],
      environment:      "production"
    }')")

PROVISION_OK=$(echo "$PROVISION" | jq -r '.service_name // ""')
if [[ -z "$PROVISION_OK" || "$PROVISION_OK" == "null" ]]; then
  fail "Provision failed: $(echo "$PROVISION" | jq -r '.error // .')"
  echo ""; echo "❌ Cannot continue — auth service unreachable or admin secret wrong"; exit 1
fi

ok "Provisioned identity: $PROVISION_OK"
IDENTITY_ID=$(echo "$PROVISION" | jq -r '.id')
KEY_ID=$(echo "$PROVISION" | jq -r '.key_id')
SECRET_RAW=$(echo "$PROVISION" | jq -r '.secret')  # format: "mid_xxx:actualSecret"
ROTATION_DUE=$(echo "$PROVISION" | jq -r '.rotation_due_at')
info "Identity ID   : $IDENTITY_ID"
info "Key ID        : $KEY_ID"
info "Rotation due  : $ROTATION_DUE"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — Exchange key for machine JWT
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 3 — Exchange machine key for JWT"

EXCHANGE=$(curl -s -X POST "$AUTH_URL/machine/auth" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg kid "$KEY_ID" \
    --arg sec "$SECRET_RAW" \
    '{"key_id": $kid, "secret": $sec}')")

TOKEN=$(echo "$EXCHANGE" | jq -r '.token // ""')
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  fail "Token exchange failed: $(echo "$EXCHANGE" | jq -r '.error // .')"
  echo ""; echo "❌ Cannot continue — token exchange failed"; exit 1
fi

ok "Token exchange successful"
info "Service  : $(echo "$EXCHANGE" | jq -r '.service')"
info "Scopes   : $(echo "$EXCHANGE" | jq -r '.scopes | join(", ")')"
info "Expires  : in $(echo "$EXCHANGE" | jq -r '.expires_in')s (1h)"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — Validate JWT claims (no crypto lib needed — decode and inspect)
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 4 — Validate JWT payload claims"

PAYLOAD=$(jwt_payload "$TOKEN")
info "Decoded payload:"
echo "$PAYLOAD" | jq -r '.' | sed 's/^/             /'

CLAIM_TYPE=$(echo "$PAYLOAD"  | jq -r '.type // ""')
CLAIM_SVC=$(echo "$PAYLOAD"   | jq -r '.service // .sub // ""')
CLAIM_EXP=$(echo "$PAYLOAD"   | jq -r '.exp // 0')
NOW=$(date +%s)
TTL=$(( CLAIM_EXP - NOW ))

[[ "$CLAIM_TYPE"  == "machine" ]]          && ok 'claim: type = "machine"'  || fail "claim: type = \"$CLAIM_TYPE\" (expected machine)"
[[ "$CLAIM_SVC"   == "$TEST_SERVICE" ]]    && ok "claim: service = $TEST_SERVICE" || fail "claim: service = \"$CLAIM_SVC\" (expected $TEST_SERVICE)"
[[ "$CLAIM_EXP"   -gt "$NOW" ]]            && ok "claim: not expired (TTL ${TTL}s)" || fail "claim: token is expired"
[[ "$TTL"         -lt 3700 ]]              && ok "claim: TTL ≤ 3700s (short-lived)" || fail "claim: TTL ${TTL}s exceeds 1h — tokens must be short-lived"

SCOPES_OK=$(echo "$PAYLOAD" | jq -r '.scopes | map(select(. == "audit:write")) | length')
[[ "$SCOPES_OK" -gt 0 ]] && ok "claim: scopes include audit:write" || fail "claim: audit:write missing from scopes"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — Protected route smoke tests — rald-event-bus
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 5 — rald-event-bus protected routes"

# 5a. POST /audit — with valid token → expect 200 or 422 (valid body needed)
AUDIT_STATUS=$(http_status -X POST "$EVENTS_URL/audit" \
  -H "Content-Type: application/json" \
  -H "X-Machine-Token: $TOKEN" \
  -d '{"action":"e2e.test","status":"success","metadata":{"source":"integration-test"}}')
[[ "$AUDIT_STATUS" == "200" || "$AUDIT_STATUS" == "201" || "$AUDIT_STATUS" == "422" ]] \
  && ok "POST /audit with token → $AUDIT_STATUS (auth passed)" \
  || fail "POST /audit with token → $AUDIT_STATUS (expected 200/201/422)"

# 5b. POST /audit — without token → expect 401
NO_AUTH_STATUS=$(http_status -X POST "$EVENTS_URL/audit" \
  -H "Content-Type: application/json" \
  -d '{"action":"e2e.test"}')
[[ "$NO_AUTH_STATUS" == "401" ]] \
  && ok "POST /audit without token → 401 ✓" \
  || fail "POST /audit without token → $NO_AUTH_STATUS (expected 401)"

# 5c. GET /audit — with valid token → expect 200
GET_AUDIT_STATUS=$(http_status -X GET "$EVENTS_URL/audit" \
  -H "X-Machine-Token: $TOKEN")
[[ "$GET_AUDIT_STATUS" == "200" ]] \
  && ok "GET /audit with token → 200 ✓" \
  || fail "GET /audit with token → $GET_AUDIT_STATUS (expected 200)"

# 5d. GET /audit — without token → expect 401
GET_AUDIT_UNAUTH=$(http_status "$EVENTS_URL/audit")
[[ "$GET_AUDIT_UNAUTH" == "401" ]] \
  && ok "GET /audit without token → 401 ✓" \
  || fail "GET /audit without token → $GET_AUDIT_UNAUTH (expected 401)"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — Protected route smoke tests — rald-config
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 6 — rald-config protected routes"

# 6a. GET /kill-switches — public read → expect 200 (no auth required)
KS_LIST_STATUS=$(http_status "$CONFIG_URL/kill-switches")
[[ "$KS_LIST_STATUS" == "200" ]] \
  && ok "GET /kill-switches (public) → 200 ✓" \
  || fail "GET /kill-switches → $KS_LIST_STATUS (expected 200)"

# 6b. POST /kill-switches/e2e-test/activate — with valid token → 200 or 404
KS_ACTIVATE=$(http_status -X POST "$CONFIG_URL/kill-switches/e2e-test-switch/activate" \
  -H "Content-Type: application/json" \
  -H "X-Machine-Token: $TOKEN")
[[ "$KS_ACTIVATE" == "200" || "$KS_ACTIVATE" == "201" || "$KS_ACTIVATE" == "404" ]] \
  && ok "POST /kill-switches/activate with token → $KS_ACTIVATE (auth passed)" \
  || fail "POST /kill-switches/activate with token → $KS_ACTIVATE (expected 200/404)"

# 6c. POST /kill-switches/e2e-test/activate — without token → 401
KS_UNAUTH=$(http_status -X POST "$CONFIG_URL/kill-switches/e2e-test-switch/activate" \
  -H "Content-Type: application/json")
[[ "$KS_UNAUTH" == "401" ]] \
  && ok "POST /kill-switches/activate without token → 401 ✓" \
  || fail "POST /kill-switches/activate without token → $KS_UNAUTH (expected 401)"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — Protected route smoke tests — rald-notify
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 7 — rald-notify protected routes"

# 7a. POST /center/publish — with valid token → 200 or 422
PUBLISH_STATUS=$(http_status -X POST "$NOTIFY_URL/center/publish" \
  -H "Content-Type: application/json" \
  -H "X-Machine-Token: $TOKEN" \
  -d '{"recipient_id":"00000000-0000-0000-0000-000000000000","type":"e2e.test","title":"E2E Test","body":"Integration test notification — safe to ignore"}')
[[ "$PUBLISH_STATUS" == "200" || "$PUBLISH_STATUS" == "201" || "$PUBLISH_STATUS" == "422" || "$PUBLISH_STATUS" == "404" ]] \
  && ok "POST /center/publish with token → $PUBLISH_STATUS (auth passed)" \
  || fail "POST /center/publish with token → $PUBLISH_STATUS (expected 200/201/422/404)"

# 7b. POST /center/publish — without token → 401
PUBLISH_UNAUTH=$(http_status -X POST "$NOTIFY_URL/center/publish" \
  -H "Content-Type: application/json" \
  -d '{"type":"test"}')
[[ "$PUBLISH_UNAUTH" == "401" ]] \
  && ok "POST /center/publish without token → 401 ✓" \
  || fail "POST /center/publish without token → $PUBLISH_UNAUTH (expected 401)"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 8 — Key rotation test
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 8 — Key rotation"

ROTATE=$(curl -s -X POST "$AUTH_URL/machine/identities/$IDENTITY_ID/rotate" \
  -H "X-Admin-Secret: $ADMIN_SECRET")
NEW_KEY_ID=$(echo "$ROTATE" | jq -r '.key_id // ""')
if [[ -n "$NEW_KEY_ID" && "$NEW_KEY_ID" != "null" && "$NEW_KEY_ID" != "$KEY_ID" ]]; then
  ok "Key rotated: $KEY_ID → $NEW_KEY_ID"
  info "New rotation due: $(echo "$ROTATE" | jq -r '.rotation_due_at')"
else
  fail "Key rotation failed: $(echo "$ROTATE" | jq -r '.error // .')"
fi

# Verify new key also exchanges for a valid token
NEW_SECRET=$(echo "$ROTATE" | jq -r '.secret // ""')
if [[ -n "$NEW_SECRET" && "$NEW_SECRET" != "null" ]]; then
  NEW_EXCHANGE=$(curl -s -X POST "$AUTH_URL/machine/auth" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg kid "$NEW_KEY_ID" --arg sec "$NEW_SECRET" '{"key_id":$kid,"secret":$sec}')")
  NEW_TOKEN=$(echo "$NEW_EXCHANGE" | jq -r '.token // ""')
  [[ -n "$NEW_TOKEN" && "$NEW_TOKEN" != "null" ]] \
    && ok "New key exchanges for JWT ✓" \
    || fail "New key token exchange failed: $(echo "$NEW_EXCHANGE" | jq -r '.error // .')"
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 9 — Cleanup: revoke test identity
# ─────────────────────────────────────────────────────────────────────────────
separator; log "PHASE 9 — Cleanup: revoke test identity"

REVOKE=$(curl -s -X DELETE "$AUTH_URL/machine/identities/$IDENTITY_ID" \
  -H "X-Admin-Secret: $ADMIN_SECRET")
REVOKED=$(echo "$REVOKE" | jq -r '.revoked // false')
[[ "$REVOKED" == "true" ]] \
  && ok "Identity $IDENTITY_ID revoked ✓" \
  || fail "Revoke failed: $(echo "$REVOKE" | jq -r '.error // .')"

# Verify revoked identity cannot exchange for token
REVOKED_EXCHANGE=$(curl -s -X POST "$AUTH_URL/machine/auth" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg kid "$NEW_KEY_ID" --arg sec "$NEW_SECRET" '{"key_id":$kid,"secret":$sec}')")
REVOKE_STATUS=$(echo "$REVOKED_EXCHANGE" | jq -r '.error // ""')
[[ -n "$REVOKE_STATUS" ]] \
  && ok "Revoked identity rejected on token exchange ✓ (error: $REVOKE_STATUS)" \
  || fail "Revoked identity still able to exchange token — revocation not enforced"

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
separator
echo ""
echo "══════════════════════════════════════════════════════════"
echo "  RALD Machine Identity E2E — Results"
echo "══════════════════════════════════════════════════════════"
echo "  Passed  : $PASS"
echo "  Failed  : $FAIL"
echo "══════════════════════════════════════════════════════════"

if [[ "$FAIL" -eq 0 ]]; then
  echo ""
  echo "  ✅ ALL CHECKS PASSED — C-CERT-001 SATISFIED"
  echo "  Machine identity loop is end-to-end operational."
  echo "  Safe to proceed to public beta."
else
  echo ""
  echo "  ❌ $FAIL CHECK(S) FAILED — review output above"
  echo "  C-CERT-001 NOT yet satisfied."
  exit 1
fi
echo ""
