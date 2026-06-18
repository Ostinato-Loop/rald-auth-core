#!/usr/bin/env node
// WIZMAC Mandatory Pre-Action Check
// CI: Runs before every build/deploy. Fails if WIZMAC.md is missing or incomplete.
// LILCKY STUDIO LIMITED

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = process.cwd();
const WIZMAC_PATH = resolve(ROOT, "WIZMAC.md");

const REQUIRED_SECTIONS = [
  "Product Overview",
  "Architecture",
  "Auth Flow",
  "Environment Variables",
  "Live Endpoints",
  "Incidents",
];

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║        WIZMAC MANDATORY READ — Pre-Action Check             ║");
console.log("║  Rule: Read WIZMAC before every operation. Always.          ║");
console.log("╚══════════════════════════════════════════════════════════════╝\n");

if (!existsSync(WIZMAC_PATH)) {
  console.error("❌ WIZMAC.md is MISSING from this repository root.");
  console.error("   Every RALD service MUST have a WIZMAC.md.");
  console.error("   See: https://github.com/Ostinato-Loop/wizmac-core/blob/main/docs/GOVERNANCE.md");
  process.exit(1);
}

const content = readFileSync(WIZMAC_PATH, "utf-8");
const missing = REQUIRED_SECTIONS.filter(s => !content.includes(s));

if (missing.length > 0) {
  console.warn(`⚠️  WIZMAC.md is incomplete. Missing sections:\n   ${missing.map(s => `- ${s}`).join("\n   ")}`);
  console.warn("   Update WIZMAC.md before merging. (Non-blocking for now — will become hard fail in next sprint.)");
} else {
  console.log("✅ WIZMAC.md present and complete.\n");
  const lines = content.split("\n");
  const titleLine = lines.find(l => l.startsWith("# WIZMAC")) ?? lines[0];
  console.log(`   ${titleLine.replace(/^#+\s*/, "")}`);
}

console.log("\n📖 WIZMAC read complete. Proceeding with operation.\n");
