// RALD Auth Core — Identity Brain Manifest & Capabilities
// Sprint: Public Beta Hardening · 2026-06-14
//
// The RALD Identity Brain is the canonical authority for:
//   - Username ownership, governance, and settlement
//   - Trust scoring (trust_level: none → verified → trusted → anchor → civic → guardian)
//   - Permission evaluation (who can do what, in which country)
//   - Country activation and governance (which features are live where)
//   - API provisioning (developer keys, scopes, rate limits)
//   - Machine identity management (service-to-service auth)
//   - Identity intelligence (behavior signals, abuse flags, recovery)
//
// Namespace: /identity-brain/*
// All endpoints under this namespace require machine authentication.
// The route /identity-brain/* is a semantic alias for /identity/* — both
// prefixes are honoured by the router (Rule #4 spec compliance).
//
// This file provides the manifest and capabilities introspection endpoint.
// All data operations are handled by the existing /identity/* routes.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";

const identityBrain = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /identity-brain — manifest ────────────────────────────────────────────
identityBrain.get("/", (c) =>
  c.json({
    service:     "rald-identity-brain",
    version:     "1.0.0",
    description: "The canonical identity authority for the RALD ecosystem.",
    hosted_at:   "https://auth.rald.cloud",
    namespace:   "/identity-brain",
    alias_of:    "/identity",
    authority_domains: [
      "username ownership and governance",
      "trust scoring and level assignment",
      "permission evaluation",
      "country activation and governance",
      "developer API provisioning",
      "machine identity management",
      "identity intelligence and repair",
      "rald address assignment",
      "reserved email provisioning",
    ],
    capabilities: {
      identity: {
        GET:  "/identity/:userId",
        POST: "/identity/repair",
      },
      username: {
        GET:    "/username/:username",
        POST:   "/username/claim",
        DELETE: "/username/release",
        PUT:    "/username/transfer",
      },
      trust: {
        GET:    "/trust/:userId",
        POST:   "/trust/evaluate",
        PUT:    "/trust/override",
      },
      permissions: {
        GET:  "/permissions/:userId",
        POST: "/permissions/check",
      },
      machine: {
        POST:   "/machine/auth",
        GET:    "/machine/identities",
        PUT:    "/machine/rotate/:keyId",
        DELETE: "/machine/revoke/:keyId",
      },
      developer: {
        POST:   "/developer/keys",
        GET:    "/developer/keys",
        DELETE: "/developer/keys/:keyId",
      },
      country: {
        GET:  "/country/:countryCode",
        POST: "/country/activate",
      },
      intelligence: {
        GET:  "/identity/intelligence/:userId",
        POST: "/identity/intelligence/flag",
      },
    },
    trust_levels: ["none", "verified", "trusted", "anchor", "civic", "guardian"],
    auth: "Machine JWT required (Authorization: Bearer <machine_token>). Use POST /machine/auth to issue.",
    spec_compliance: "Rule #4 — /identity-brain/* namespace aliases /identity/*",
  })
);

// ── GET /identity-brain/health ─────────────────────────────────────────────────
identityBrain.get("/health", async (c) => {
  const db = c.get("db");
  try {
    const { count } = await db
      .from("machine_identities")
      .select("id", { count: "exact", head: true });
    return c.json({
      ok:           true,
      service:      "rald-identity-brain",
      machine_keys: count ?? 0,
      checked_at:   new Date().toISOString(),
    });
  } catch (e) {
    return c.json({ ok: false, error: String(e) }, 503);
  }
});

export default identityBrain;
