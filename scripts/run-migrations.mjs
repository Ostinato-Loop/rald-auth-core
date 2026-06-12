#!/usr/bin/env node
// RALD Auth Core — DDL + DML Migration Runner
// Uses Supabase Management API for DDL (CREATE TABLE, CREATE FUNCTION, ALTER TABLE, etc.)
// Uses PostgREST REST API for DML seeding (INSERT ON CONFLICT DO NOTHING)
// Requires: SUPABASE_ACCESS_TOKEN (Management API personal access token)
//           SUPABASE_SERVICE_ROLE_KEY (PostgREST DML operations)
//           SUPABASE_URL (project URL)

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const SUPABASE_URL   = process.env.SUPABASE_URL   || "https://onxdcikfttdmnhofsuwo.supabase.co";
const SERVICE_KEY    = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ACCESS_TOKEN   = process.env.SUPABASE_ACCESS_TOKEN;
const DRY_RUN        = process.env.DRY_RUN === "true";
const PROJECT_REF    = "onxdcikfttdmnhofsuwo";
const MGMT_BASE      = "https://api.supabase.com";

if (!SERVICE_KEY) { console.error("SUPABASE_SERVICE_ROLE_KEY required"); process.exit(1); }

const restH = {
  apikey: SERVICE_KEY,
  Authorization: "Bearer " + SERVICE_KEY,
  "Content-Type": "application/json",
};

// ── 1. Verify REST connection ─────────────────────────────────────────
const ping = await fetch(SUPABASE_URL + "/rest/v1/auth_users?limit=0", { headers: restH });
console.log("Supabase REST connection: HTTP", ping.status, ping.ok ? "✓" : "✗");
if (!ping.ok) { console.error("Cannot reach Supabase REST API"); process.exit(1); }

if (DRY_RUN) { console.log("DRY RUN: skipping all changes."); process.exit(0); }

// ── 2. Apply DDL migrations via Management API ────────────────────────
const MIGRATIONS_DIR = "supabase/migrations";

if (!ACCESS_TOKEN) {
  console.warn("WARNING: SUPABASE_ACCESS_TOKEN not set — skipping DDL migrations.");
  console.warn("Add SUPABASE_ACCESS_TOKEN (your Supabase personal access token) to GitHub org secrets.");
  console.warn("Get it from: https://supabase.com/dashboard/account/tokens");
} else {
  const mgmtH = {
    Authorization: "Bearer " + ACCESS_TOKEN,
    "Content-Type": "application/json",
  };

  let migrationFiles = [];
  if (existsSync(MIGRATIONS_DIR)) {
    migrationFiles = readdirSync(MIGRATIONS_DIR)
      .filter(f => f.endsWith(".sql"))
      .sort();
  }

  console.log(`\n=== Applying DDL migrations (${migrationFiles.length} files) ===`);

  for (const file of migrationFiles) {
    const sql = readFileSync(join(MIGRATIONS_DIR, file), "utf8");
    const res = await fetch(`${MGMT_BASE}/v1/projects/${PROJECT_REF}/database/query`, {
      method: "POST",
      headers: mgmtH,
      body: JSON.stringify({ query: sql }),
    });
    const body = await res.json().catch(() => ({ error: "non-JSON response" }));
    if (!res.ok) {
      const msg = JSON.stringify(body);
      const isIdempotentError = msg.includes("already exists") || msg.includes("does not exist");
      if (isIdempotentError) {
        console.log(`  [WARN idempotent] ${file}: ${msg.slice(0, 120)}`);
      } else {
        console.error(`  [FAIL] ${file}: HTTP ${res.status} — ${msg.slice(0, 200)}`);
      }
    } else {
      console.log(`  [OK] ${file}`);
    }
  }
}

// ── 3. DML seeding (country_registry — idempotent) ──────────────────
console.log("\n=== DML seeding ===");

const tableCheck = await fetch(SUPABASE_URL + "/rest/v1/country_registry?limit=0", { headers: restH });
if (!tableCheck.ok) {
  console.warn("country_registry table not found — DDL migration not yet applied. Skipping seed.");
} else {
  const PREF_H = { ...restH, "Prefer": "resolution=ignore-duplicates,return=minimal" };
  const seed = await fetch(SUPABASE_URL + "/rest/v1/country_registry", {
    method: "POST", headers: PREF_H,
    body: JSON.stringify([
      { country_code: "NG", country_name: "Nigeria",      status: "ACTIVE",   demand_score: 100, legal_score: 90,  compliance_score: 85, moderation_score: 90, infrastructure_score: 95, support_score: 90, launch_date: "2026-06-11", legal_notes: "NITDA guidelines reviewed. NCC compliance confirmed. NDPA data protection in place.", compliance_notes: "FCCPC compliance confirmed. Identity requirements met. KYC framework active." },
      { country_code: "KE", country_name: "Kenya",        status: "WAITLIST", demand_score: 72 },
      { country_code: "TZ", country_name: "Tanzania",     status: "WAITLIST", demand_score: 58 },
      { country_code: "GH", country_name: "Ghana",        status: "WAITLIST", demand_score: 68 },
      { country_code: "ZA", country_name: "South Africa", status: "WAITLIST", demand_score: 65 },
      { country_code: "IN", country_name: "India",        status: "WAITLIST", demand_score: 80 },
      { country_code: "ID", country_name: "Indonesia",    status: "WAITLIST", demand_score: 74 },
    ]),
  });
  console.log("Country registry seed: HTTP", seed.status, seed.ok ? "✓" : "✗ (may already exist)");
}

console.log("\n=== Migration run complete ===");
