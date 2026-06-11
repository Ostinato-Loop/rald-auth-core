#!/usr/bin/env node
  // RALD Auth Core — Migration runner
  // Applies all pending Supabase SQL migrations using the PostgREST /rest/v1/sql endpoint.
  // Content-Type: text/plain (required by PostgREST — not application/sql)

  import { readFileSync } from "fs";

  const url   = process.env.SUPABASE_URL;
  const key   = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const isDry = process.env.DRY_RUN === "true";

  if (!url || !key) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  const baseHeaders = {
    apikey: key,
    Authorization: "Bearer " + key,
  };

  // Verify connection
  const ping = await fetch(url + "/rest/v1/auth_users?limit=0", { headers: baseHeaders });
  if (ping.status !== 200) {
    console.error("Cannot connect to Supabase: HTTP " + ping.status + " " + await ping.text());
    process.exit(1);
  }
  console.log("Supabase connection: HTTP " + ping.status + " OK");
  if (isDry) { console.log("DRY RUN: skipping migration."); process.exit(0); }

  // Execute SQL via PostgREST — Content-Type must be text/plain
  async function execSQL(sql) {
    // Try /rest/v1/sql with text/plain first
    const r = await fetch(url + "/rest/v1/sql", {
      method: "POST",
      headers: { ...baseHeaders, "Content-Type": "text/plain" },
      body: sql,
    });
    return { ok: r.ok, status: r.status, text: await r.text() };
  }

  // Also try alternative endpoint format (application/json with "query" key)
  async function execSQLJson(sql) {
    const r = await fetch(url + "/rest/v1/sql", {
      method: "POST",
      headers: { ...baseHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ query: sql }),
    });
    return { ok: r.ok, status: r.status, text: await r.text() };
  }

  // Probe which endpoint works
  console.log("Probing SQL endpoint...");
  const probe1 = await execSQL("SELECT 1 AS probe;");
  const probe2 = probe1.ok ? null : await execSQLJson("SELECT 1 AS probe;");
  const workingExec = probe1.ok ? execSQL : (probe2?.ok ? execSQLJson : null);

  if (!workingExec) {
    console.error("SQL endpoint probe failed.");
    console.error("text/plain:", probe1.status, probe1.text.slice(0, 150));
    if (probe2) console.error("application/json:", probe2.status, probe2.text.slice(0, 150));
    
    // Final fallback: try /query endpoint
    const probe3 = await fetch(url + "/query", {
      method: "POST",
      headers: { ...baseHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ query: "SELECT 1 AS probe;" }),
    });
    console.error("/query endpoint:", probe3.status, (await probe3.text()).slice(0, 150));
    process.exit(1);
  }
  console.log("SQL endpoint working: " + (probe1.ok ? "text/plain" : "application/json"));

  async function applyMigration(path) {
    console.log("\n=== " + path + " ===");
    const sql = readFileSync(path, "utf8");

    // Attempt 1: run as single batch
    const batch = await workingExec(sql);
    if (batch.ok) {
      console.log("  OK (full batch applied)");
      return;
    }
    console.log("  Batch HTTP " + batch.status + " — statement-by-statement...");
    console.log("  Reason: " + batch.text.slice(0, 200));

    // Attempt 2: statement-by-statement (handles PL/pgSQL dollar-quoting)
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
        const stripped = stmt.replace(/--.*$/gm, "").trim();
        if (!stripped) continue;
        const r2 = await workingExec(stmt);
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
          console.error("    -> " + r2.text.slice(0, 200));
          failed++;
        }
      }
    }
    console.log("  " + passed + " ok | " + skipped + " superuser-only | " + failed + " failed");
    if (failed > 0) process.exitCode = 1;
  }

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
    ["usernames",                "/rest/v1/usernames?select=status&limit=0"],
    ["auth_trust_profiles",      "/rest/v1/auth_trust_profiles?limit=0"],
    ["username_migration_queue", "/rest/v1/username_migration_queue?limit=0"],
  ];
  let allOk = true;
  for (const [name, path] of checks) {
    const r = await fetch(url + path, { headers: baseHeaders });
    const ok = [200, 206].includes(r.status);
    console.log((ok ? "OK" : "FAIL") + " " + name + ": HTTP " + r.status);
    if (!ok) allOk = false;
  }
  if (!allOk) { console.error("Verification failed."); process.exit(1); }
  console.log("\nAll migrations applied and verified.");
  