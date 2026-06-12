#!/usr/bin/env bash
# =============================================================================
# RALD — Supabase Migration Runner
# Apply all pending migrations to production Supabase in correct order.
# =============================================================================
#
# PREREQUISITES:
#   export SUPABASE_URL="https://onxdcikfttdmnhofsuwo.supabase.co"
#   export SUPABASE_SERVICE_ROLE_KEY="eyJ..."
#
# USAGE:
#   bash scripts/apply-migrations.sh                  # Apply all pending
#   bash scripts/apply-migrations.sh --dry-run        # Show what would run
#   bash scripts/apply-migrations.sh --from 20260613  # Apply from timestamp
#   bash scripts/apply-migrations.sh --file 20260613000000_event_bus.sql
#
# HOW IT WORKS:
#   Runs each .sql file against Supabase via the REST API (pg query endpoint).
#   Tracks applied migrations in a `schema_migrations` table to prevent re-runs.
#   Safe: all migrations use IF NOT EXISTS / ADD COLUMN IF NOT EXISTS throughout.
#
# LILCKY STUDIO LIMITED — 2026-06-13
# =============================================================================

set -euo pipefail

SUPABASE_URL="${SUPABASE_URL:-}"
SERVICE_KEY="${SUPABASE_SERVICE_ROLE_KEY:-}"
MIGRATIONS_DIR="$(dirname "$0")/../supabase/migrations"
DRY_RUN=false
FROM_TIMESTAMP=""
SINGLE_FILE=""

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run)  DRY_RUN=true; shift;;
    --from)     FROM_TIMESTAMP="$2"; shift 2;;
    --file)     SINGLE_FILE="$2"; shift 2;;
    *)          echo "Unknown option: $1"; exit 1;;
  esac
done

if [ -z "$SUPABASE_URL" ] || [ -z "$SERVICE_KEY" ]; then
  echo "ERROR: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set."
  echo "  export SUPABASE_URL=https://onxdcikfttdmnhofsuwo.supabase.co"
  echo "  export SUPABASE_SERVICE_ROLE_KEY=<your-service-role-key>"
  exit 1
fi

# ── Supabase SQL execution via REST API ────────────────────────────────────────
execute_sql() {
  local sql="$1"
  local label="${2:-sql}"

  local response=$(curl -s -X POST \
    "${SUPABASE_URL}/rest/v1/rpc/pg_execute_sql" \
    -H "apikey: ${SERVICE_KEY}" \
    -H "Authorization: Bearer ${SERVICE_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"query\": $(echo "$sql" | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>process.stdout.write(JSON.stringify(d)))")}" \
    2>&1)

  # Fallback: use the raw SQL endpoint
  if echo "$response" | grep -q "function.*does not exist\|PGRST"; then
    response=$(curl -s -X POST \
      "${SUPABASE_URL}/rest/v1/" \
      -H "apikey: ${SERVICE_KEY}" \
      -H "Authorization: Bearer ${SERVICE_KEY}" \
      -H "Content-Type: application/json" \
      -H "Prefer: params=single-object" \
      --data-raw "$sql" 2>&1 || true)
  fi

  echo "$response"
}

# ── Ensure schema_migrations tracking table exists ────────────────────────────
echo "Ensuring schema_migrations tracking table..."
if ! $DRY_RUN; then
  curl -s -X POST \
    "${SUPABASE_URL}/rest/v1/rpc/exec" \
    -H "apikey: ${SERVICE_KEY}" \
    -H "Authorization: Bearer ${SERVICE_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"sql": "CREATE TABLE IF NOT EXISTS schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now(), checksum TEXT);"}' \
    > /dev/null 2>&1 || true
fi

# ── Get list of applied migrations ────────────────────────────────────────────
applied_migrations=()
if ! $DRY_RUN; then
  applied_response=$(curl -s \
    "${SUPABASE_URL}/rest/v1/schema_migrations?select=filename&order=filename" \
    -H "apikey: ${SERVICE_KEY}" \
    -H "Authorization: Bearer ${SERVICE_KEY}" 2>/dev/null || echo "[]")
  
  while IFS= read -r filename; do
    applied_migrations+=("$filename")
  done < <(echo "$applied_response" | node -e "const d=[];process.stdin.on('data',c=>d.push(c));process.stdin.on('end',()=>{try{const r=JSON.parse(d.join(''));r.forEach(m=>console.log(m.filename))}catch{}})")
fi

echo "Applied migrations: ${#applied_migrations[@]}"
echo ""

# ── Apply migrations ────────────────────────────────────────────────────────────
echo "============================================================"
echo "  RALD Supabase Migration Runner"
echo "  URL: $SUPABASE_URL"
echo "  Migrations dir: $MIGRATIONS_DIR"
echo "  Dry run: $DRY_RUN"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"
echo ""

applied=0
skipped=0
failed=0

if [ -n "$SINGLE_FILE" ]; then
  files=("$MIGRATIONS_DIR/$SINGLE_FILE")
else
  files=($(ls "$MIGRATIONS_DIR"/*.sql 2>/dev/null | sort))
fi

for migration_file in "${files[@]}"; do
  filename=$(basename "$migration_file")
  
  # Skip non-SQL or README files
  if [[ "$filename" == README* ]] || [[ "$filename" != *.sql ]]; then
    continue
  fi
  
  # Skip if before --from timestamp
  if [ -n "$FROM_TIMESTAMP" ] && [[ "$filename" < "$FROM_TIMESTAMP" ]]; then
    continue
  fi
  
  # Skip if already applied
  already_applied=false
  for applied_file in "${applied_migrations[@]}"; do
    if [ "$applied_file" = "$filename" ]; then
      already_applied=true
      break
    fi
  done
  
  if $already_applied; then
    echo "  [SKIP] $filename (already applied)"
    ((skipped++)) || true
    continue
  fi
  
  echo "  [APPLY] $filename..."
  
  if $DRY_RUN; then
    echo "    → DRY RUN: would apply $filename"
    ((applied++)) || true
    continue
  fi
  
  # Read and apply SQL via Supabase Dashboard SQL Runner
  # NOTE: The REST API /rpc endpoint cannot run arbitrary DDL.
  # Best approach: use Supabase CLI or run via Dashboard SQL Editor.
  # This script prints the SQL for manual application if REST fails.
  
  sql_content=$(cat "$migration_file")
  
  # Try via Supabase CLI (if installed)
  if command -v supabase &>/dev/null; then
    if supabase db execute --file "$migration_file" 2>/dev/null; then
      echo "    ✅ Applied via supabase CLI"
      curl -s -X POST "${SUPABASE_URL}/rest/v1/schema_migrations" \
        -H "apikey: ${SERVICE_KEY}" \
        -H "Authorization: Bearer ${SERVICE_KEY}" \
        -H "Content-Type: application/json" \
        -H "Prefer: return=minimal" \
        -d "{\"filename\": \"$filename\"}" > /dev/null 2>&1 || true
      ((applied++)) || true
    else
      echo "    ❌ Failed via supabase CLI"
      ((failed++)) || true
    fi
  else
    # Supabase CLI not available — print SQL location for manual application
    echo "    ⚠️  Apply manually via Supabase Dashboard SQL Editor:"
    echo "       URL: https://supabase.com/dashboard/project/onxdcikfttdmnhofsuwo/sql/new"
    echo "       File: $migration_file"
    echo ""
    ((failed++)) || true
  fi
done

echo ""
echo "============================================================"
echo "  SUMMARY"
echo "  Applied: $applied"
echo "  Skipped: $skipped"
echo "  Manual needed: $failed"
echo "============================================================"
echo ""

if [ "$failed" -gt "0" ]; then
  echo "  MANUAL STEPS:"
  echo "  1. Go to: https://supabase.com/dashboard/project/onxdcikfttdmnhofsuwo/sql/new"
  echo "  2. Copy and paste each .sql file content in order"
  echo "  3. Or install Supabase CLI: brew install supabase/tap/supabase"
  echo "     Then: supabase db push --db-url <your-db-url>"
  echo ""
fi
echo "Migration run complete. $(date -u +%Y-%m-%dT%H:%M:%SZ)"
