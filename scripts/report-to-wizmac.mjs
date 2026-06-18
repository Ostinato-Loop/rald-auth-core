#!/usr/bin/env node
// WIZMAC Mandatory Post-Fix Report
// CI: Runs after every successful deploy/fix. Reports back to WIZMAC API.
// LILCKY STUDIO LIMITED
//
// Usage (in CI):
//   WIZMAC_API_URL=https://sekani.rald.cloud \
//   WIZMAC_SERVICE=${{ github.event.repository.name }} \
//   WIZMAC_ACTION="deployed" \
//   WIZMAC_ACTOR=${{ github.actor }} \
//   node scripts/report-to-wizmac.mjs

const WIZMAC_API_URL = process.env.WIZMAC_API_URL ?? "https://sekani.rald.cloud";
const SERVICE       = process.env.WIZMAC_SERVICE ?? process.env.GITHUB_REPOSITORY?.split("/")[1] ?? "unknown";
const ACTION        = process.env.WIZMAC_ACTION ?? "deployed";
const ACTOR         = process.env.WIZMAC_ACTOR ?? process.env.GITHUB_ACTOR ?? "ci";
const SHA           = process.env.GITHUB_SHA?.slice(0, 8) ?? "unknown";
const REF           = process.env.GITHUB_REF_NAME ?? "main";
const RUN_ID        = process.env.GITHUB_RUN_ID ?? "";
const WORKFLOW      = process.env.GITHUB_WORKFLOW ?? "";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║         WIZMAC MANDATORY POST-FIX REPORT                    ║");
console.log("║  Rule: Report to WIZMAC after every fix. Always.            ║");
console.log("╚══════════════════════════════════════════════════════════════╝\n");

const payload = {
  eventType: "agent_action",
  title: `[${SERVICE}] ${ACTION} — ${SHA}@${REF}`,
  description: `Mandatory WIZMAC report: ${SERVICE} ${ACTION} successfully completed.`,
  actor: ACTOR,
  payload: {
    service: SERVICE,
    action: ACTION,
    sha: SHA,
    branch: REF,
    workflow: WORKFLOW,
    run_id: RUN_ID,
    timestamp: new Date().toISOString(),
  },
  tags: ["mandatory-report", "ci", SERVICE, ACTION],
};

try {
  const res = await fetch(`${WIZMAC_API_URL}/api/wizmac/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (res.ok) {
    const data = await res.json();
    console.log(`✅ WIZMAC report accepted: ${data.event?.id ?? "ok"}`);
    console.log(`   Service: ${SERVICE}`);
    console.log(`   Action:  ${ACTION}`);
    console.log(`   SHA:     ${SHA}@${REF}\n`);
  } else {
    const text = await res.text();
    console.warn(`⚠️  WIZMAC report returned ${res.status}: ${text}`);
    console.warn("   (Non-blocking — operation succeeded regardless)");
  }
} catch (err) {
  console.warn(`⚠️  WIZMAC report failed: ${err.message}`);
  console.warn("   (Non-blocking — WIZMAC API may be temporarily unavailable)");
}
