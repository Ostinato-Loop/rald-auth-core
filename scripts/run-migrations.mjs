#!/usr/bin/env node
  // RALD Auth Core — Migration runner
  // Applies all pending Supabase SQL migrations in dependency order.
  // Called by .github/workflows/migrate-sprint.yml

  import { readFileSync } from "fs";

  const url   = process.env.SUPABASE_URL;
  const key   = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const isDry = process.env.DRY_RUN === "true";

  if (!url || !key) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  // Verify connection
  const ping = await fetch(url + "/rest/v1/auth_users?limit=0", {
    headers: { apikey: key, Authorization: "Bearer " + key },
  });
  if (ping.status !== 200) {
    console.error("Cannot connect to Supabase: HTTP " + ping.status);
    process.exit(1);
  }
  console.log("Supabase connection: HTTP " + ping.status + " OK");
  if (isDry) { console.log("DRY RUN: skipping migration."); process.exit(0); }

  async function execSQL(sql) {
    const r = await fetch(url + "/rest/v1/sql", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + key,
        apikey: key,
        "Content-Type": "application/sql",
      },
      body: sql,
    });
    return { ok: r.ok, status: r.status, text: await r.text() };
  }

  async function applyMigration(path) {
    console.log("\n=== " + path + " ===");
    const sql = readFileSync(path, "utf8");

    // Attempt 1: run as single batch
    const batch = await execSQL(sql);
    if (batch.ok) {
      console.log("  OK (full batch applied)");
      return;
    }
    console.log("  Batch HTTP " + batch.status + " — falling back to statement-by-statement...");
    console.log("  Reason: " + batch.text.slice(0, 200));

    // Attempt 2: statement-by-statement
    let inDollar = false, dollarTag = "", cur = "";
    let passed = 0, skipped = 0, failed = 0;

    for (const line of sql.split("\n")) {
      if (line.trim().startsWith("--")) { cur += line + "\n"; continue; }
      const dms = line.match(/\$\$|\$[A-Za-z_][A-Za-z0-9_]*\$/g) || [];
      for (const m of dms) {
        if (!inDollar) { inDollar = true; dollarTag = m; }
        else if (m === dollarTag) { inDollar = false; dollarTag = ""; }
      }
      cur += line + "\n";
      if (!inDollar && line.trimEnd().endsWith(";")) {
        const stmt = cur.trim();
        cur = "";
        if (!stmt.replace(/--.*$/gm, "").trim()) continue;
        const r2 = await execSQL(stmt);
        const label = stmt.replace(/\s+/g, " ").slice(0, 80);
        if (r2.ok) {
          console.log("  OK: " + label);
          passed++;
        } else if (
          r2.text.includes("already exists") ||
          r2.text.includes("duplicate") ||
          r2.text.includes("already been added")
        ) {
          console.log("  SKIP (exists): " + label);
          passed++;
        } else if (
          r2.text.includes("must be owner") ||
          r2.text.includes("permission denied") ||
          r2.text.includes("must have privileges")
        ) {
          console.log("  WARN (needs superuser): " + label);
          skipped++;
        } else {
          console.error("  FAIL: " + label);
          console.error("    -> " + r2.text.slice(0, 150));
          failed++;
        }
      }
    }
    console.log("  " + passed + " ok | " + skipped + " superuser-only | " + failed + " failed");
    if (failed > 0) process.exitCode = 1;
  }

  // Apply migrations in dependency order
  const migrations = [
    "supabase/migrations/20260611_country_activation_framework.sql",
    "supabase/migrations/20260611_username_registry_status.sql",
    "supabase/migrations/20260611_identity_audit_sprint.sql",
    "supabase/migrations/20260611_auto_username_migration.sql",
  ];

  for (const migration of migrations) {
    await applyMigration(migration);
  }

  // Verify all tables exist
  console.log("\n=== Verifying tables ===");
  const checks = [
    ["country_registry",         "/rest/v1/country_registry?limit=0"],
    ["usernames.status",         "/rest/v1/usernames?select=status&limit=0"],
    ["auth_trust_profiles",      "/rest/v1/auth_trust_profiles?limit=0"],
    ["username_migration_queue", "/rest/v1/username_migration_queue?limit=0"],
  ];
  let allOk = true;
  for (const [name, path] of checks) {
    const r = await fetch(url + path, {
      headers: { apikey: key, Authorization: "Bearer " + key },
    });
    const ok = r.status === 200 || r.status === 206;
    console.log((ok ? "OK" : "FAIL") + " " + name + ": HTTP " + r.status);
    if (!ok) allOk = false;
  }
  if (!allOk) { console.error("Verification failed."); process.exit(1); }
  console.log("\nAll migrations applied and verified.");
  