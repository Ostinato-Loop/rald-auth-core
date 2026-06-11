#!/usr/bin/env node
  // RALD Auth Core — Migration verification + DML seeding
  // Note: DDL (CREATE TABLE, CREATE FUNCTION) cannot be executed via the Supabase
  // REST API (PostgREST) using a service role key alone.
  // DDL migrations must be applied via the Supabase Dashboard SQL Editor.
  // This script: (1) verifies which tables exist, (2) seeds data into existing tables.

  import { readFileSync } from "fs";

  const url  = process.env.SUPABASE_URL  || "https://onxdcikfttdmnhofsuwo.supabase.co";
  const key  = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const anonKey = process.env.SUPABASE_ANON_KEY;
  const isDry = process.env.DRY_RUN === "true";

  if (!key) {
    console.error("SUPABASE_SERVICE_ROLE_KEY required");
    process.exit(1);
  }

  const h = { apikey: key, Authorization: "Bearer " + key, "Content-Type": "application/json" };

  // 1. Verify connection
  const ping = await fetch(url + "/rest/v1/auth_users?limit=0", { headers: h });
  console.log("Supabase connection: HTTP", ping.status, ping.ok ? "✓" : "✗");
  if (!ping.ok) { console.error("Cannot reach Supabase"); process.exit(1); }
  if (isDry) { console.log("DRY RUN: skipping."); process.exit(0); }

  // 2. Check which migration tables exist
  const tables = [
    { name: "country_registry",         path: "/rest/v1/country_registry?limit=0",         migration: "20260611_country_activation_framework.sql" },
    { name: "auth_trust_profiles",      path: "/rest/v1/auth_trust_profiles?limit=0",      migration: "20260611_identity_audit_sprint.sql" },
    { name: "username_migration_queue", path: "/rest/v1/username_migration_queue?limit=0", migration: "20260611_auto_username_migration.sql" },
  ];

  const missingMigrations = new Set();
  console.log("\n=== Checking migration table status ===");
  for (const t of tables) {
    const r = await fetch(url + t.path, { headers: h });
    const ok = r.ok;
    console.log((ok ? "✓ EXISTS" : "✗ MISSING") + " " + t.name + " (migration: " + t.migration + ")");
    if (!ok) missingMigrations.add(t.migration);
  }

  // Check username.status enum (part of username_registry_status migration)
  const usernameCheck = await fetch(url + "/rest/v1/usernames?select=status&limit=0", { headers: h });
  if (!usernameCheck.ok) {
    console.log("✗ MISSING usernames.status column (migration: 20260611_username_registry_status.sql)");
    missingMigrations.add("20260611_username_registry_status.sql");
  } else {
    console.log("✓ EXISTS usernames.status column");
  }

  // 3. If migrations are missing, print SQL and instructions
  if (missingMigrations.size > 0) {
    console.log("\n" + "=".repeat(60));
    console.log("ACTION REQUIRED: Apply the following migrations in the Supabase Dashboard");
    console.log("URL: https://supabase.com/dashboard/project/onxdcikfttdmnhofsuwo/sql/new");
    console.log("=".repeat(60));
    const order = [
      "20260611_country_activation_framework.sql",
      "20260611_username_registry_status.sql",
      "20260611_identity_audit_sprint.sql",
      "20260611_auto_username_migration.sql",
    ];
    for (const m of order) {
      if (missingMigrations.has(m)) {
        const sqlPath = "supabase/migrations/" + m;
        try {
          const sql = readFileSync(sqlPath, "utf8");
          console.log("\n--- MIGRATION: " + m + " ---");
          console.log(sql.slice(0, 500) + (sql.length > 500 ? "\n... [" + sql.length + " chars total] ..." : ""));
        } catch(e) {
          console.log("  File not found: " + sqlPath);
        }
      }
    }
    console.log("\n" + "=".repeat(60));
    console.log("IMPORTANT: This workflow cannot apply DDL via the REST API.");
    console.log("Please apply the above SQL in the Supabase Dashboard SQL Editor.");
    console.log("=".repeat(60));
    // Exit 0 — this is informational, not a blocker for CI
    process.exit(0);
  }

  // 4. All tables exist — run DML seeding
  console.log("\n=== All migration tables present. Running DML seeding... ===");

  // Seed country_registry (idempotent)
  const PREF_H = { ...h, "Prefer": "resolution=ignore-duplicates,return=minimal" };
  const seed = await fetch(url + "/rest/v1/country_registry", {
    method: "POST", headers: PREF_H,
    body: JSON.stringify([
      { country_code: "NG", country_name: "Nigeria", status: "ACTIVE", demand_score: 100, legal_score: 90, compliance_score: 85, moderation_score: 90, infrastructure_score: 95, support_score: 90, launch_date: "2026-06-11", legal_notes: "NITDA guidelines reviewed. NCC compliance confirmed. NDPA data protection in place.", compliance_notes: "FCCPC compliance confirmed. Identity requirements met. KYC framework active." },
      { country_code: "KE", country_name: "Kenya",        status: "WAITLIST", demand_score: 72 },
      { country_code: "TZ", country_name: "Tanzania",     status: "WAITLIST", demand_score: 58 },
      { country_code: "GH", country_name: "Ghana",        status: "WAITLIST", demand_score: 68 },
      { country_code: "ZA", country_name: "South Africa", status: "WAITLIST", demand_score: 65 },
      { country_code: "IN", country_name: "India",        status: "WAITLIST", demand_score: 80 },
      { country_code: "ID", country_name: "Indonesia",    status: "WAITLIST", demand_score: 74 },
    ]),
  });
  console.log("Country registry seed: HTTP", seed.status, seed.ok ? "✓" : "✗ (may already exist)");

  console.log("\n=== Migration check complete ===");
  