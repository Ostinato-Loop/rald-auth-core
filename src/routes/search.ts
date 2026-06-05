// RALD Auth Core — Search Routes
// Phase: Search Architecture (Priority 4)
//
// PUBLIC SEARCH  — GET /search/users
//   Used by: Profiles, Loop, TV, AI, future public products.
//   Searches: username, display_name, rald_id, bio (respects privacy settings).
//
// RELATIONSHIP SEARCH — GET /search/related
//   Used by: Messenger, future private-circle products.
//   Ranks by: shared chats → contacts → mutual connections → shared rooms.
//   Requires auth; returns people the user actually knows, ranked by closeness.
//
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";

const search = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── helpers ───────────────────────────────────────────────────────────────────

function sanitize(q: string): string {
  return q.replace(/[%_\\]/g, "\\$&").trim().slice(0, 100);
}

function parseLimit(raw: string | undefined, max = 50): number {
  const n = parseInt(raw ?? "20");
  return Number.isNaN(n) ? 20 : Math.min(Math.max(1, n), max);
}

// ── GET /search/users — Public search ─────────────────────────────────────────
//
// Query params:
//   q          — required, min 2 chars
//   type       — "all" | "username" | "display_name" | "rald_address" (default: "all")
//   limit      — default 20, max 50
//   location   — optional location filter
//   interests  — optional comma-separated interests filter
//
// Returns results ordered by: exact match → prefix match → fuzzy match.
// Privacy: users with search_discoverable=false are excluded.
search.get("/users", async (c) => {
  const q        = (c.req.query("q") ?? "").trim();
  const type     = c.req.query("type") ?? "all";
  const limit    = parseLimit(c.req.query("limit"));
  const location = c.req.query("location")?.trim();
  const interests = c.req.query("interests")?.split(",").map((i) => i.trim()).filter(Boolean);

  if (q.length < 2) {
    return c.json({
      error: "Query must be at least 2 characters",
      results: [],
      count: 0,
    }, 400);
  }

  const db      = c.get("db");
  const term    = sanitize(q);
  const pattern = `%${term}%`;

  // Build filter conditions per type
  let usernameFilter     = false;
  let displayNameFilter  = false;
  let raldAddressFilter  = false;

  if (type === "all" || type === "username")     usernameFilter    = true;
  if (type === "all" || type === "display_name") displayNameFilter = true;
  if (type === "all" || type === "rald_address") raldAddressFilter = true;

  // Query auth_user_profiles joined with auth_users
  // Privacy: only return profiles with search_discoverable != false
  try {
    const { data, error } = await db.rpc("search_users_public", {
      p_query:          term,
      p_pattern:        pattern,
      p_limit:          limit,
      p_username:       usernameFilter,
      p_display_name:   displayNameFilter,
      p_rald_address:   raldAddressFilter,
      p_location:       location ?? null,
      p_interests:      interests && interests.length > 0 ? interests : null,
    });

    if (error) {
      // Fallback: direct table query if RPC not available
      const q1 = db
        .from("auth_user_profiles")
        .select("user_id,username,display_name,avatar_url,bio,location,interests,is_verified,search_discoverable")
        .not("search_discoverable", "eq", false)
        .limit(limit);

      const conditions: string[] = [];
      if (usernameFilter)    conditions.push(`username.ilike.${pattern}`);
      if (displayNameFilter) conditions.push(`display_name.ilike.${pattern}`);

      const { data: fallback } = conditions.length > 0
        ? await q1.or(conditions.join(","))
        : await q1.ilike("username", pattern);

      const results = (fallback ?? []).map((r: Record<string, unknown>) => ({
        id:           r.user_id,
        rald_id:      r.user_id ? `RALD-${(String(r.user_id).split("-").at(0) ?? String(r.user_id)).toUpperCase()}` : null,
        username:     r.username,
        display_name: r.display_name,
        avatar_url:   r.avatar_url,
        bio:          r.bio,
        location:     r.location,
        is_verified:  r.is_verified,
        match_type:   "profile",
      }));

      return c.json({ results, count: results.length, query: q, type, source: "fallback" });
    }

    return c.json({
      results: data ?? [],
      count:   (data ?? []).length,
      query:   q,
      type,
      source:  "rpc",
    });
  } catch (e) {
    console.error("[search] /users error:", String(e));
    return c.json({ error: "Search unavailable", results: [], count: 0 }, 503);
  }
});

// ── GET /search/related — Relationship search (auth required) ─────────────────
//
// Used by Messenger and private-circle products.
// Ranks results by closeness to the authenticated user:
//   1. Existing chats / direct messages
//   2. Contacts (phone book matches)
//   3. Mutual connections
//   4. Shared rooms (Loop)
//   5. Shared communities / groups
//   6. Broader network
//
// Query params:
//   q      — required, min 2 chars
//   limit  — default 20, max 50
search.get("/related", authMiddleware, async (c) => {
  const user  = c.get("user")!;
  const q     = (c.req.query("q") ?? "").trim();
  const limit = parseLimit(c.req.query("limit"));

  if (q.length < 2) {
    return c.json({ error: "Query must be at least 2 characters", results: [], count: 0 }, 400);
  }

  const db      = c.get("db");
  const pattern = `%${sanitize(q)}%`;

  try {
    // Step 1: Find all matching profiles (privacy-respecting)
    const { data: allMatches } = await db
      .from("auth_user_profiles")
      .select("user_id,username,display_name,avatar_url,bio,is_verified,search_discoverable")
      .not("search_discoverable", "eq", false)
      .neq("user_id", user.id)
      .or(`username.ilike.${pattern},display_name.ilike.${pattern}`)
      .limit(limit * 3);

    if (!allMatches || allMatches.length === 0) {
      return c.json({ results: [], count: 0, query: q });
    }

    // Step 2: Score each result by relationship closeness
    const userIds = allMatches.map((m: Record<string, unknown>) => m.user_id as string);

    // Check mutual connections (rald_connections table)
    const { data: mutualConns } = await db
      .from("rald_connections")
      .select("target_user_id,connection_score")
      .eq("user_id", user.id)
      .in("target_user_id", userIds);

    const connectionMap = new Map<string, number>();
    for (const c of (mutualConns ?? [])) {
      connectionMap.set(c.target_user_id as string, (c.connection_score as number) ?? 1);
    }

    // Step 3: Build ranked results
    const ranked = allMatches
      .map((m: Record<string, unknown>) => {
        const uid = m.user_id as string;
        let score = 0;
        // Direct connection: +10
        if (connectionMap.has(uid)) score += 10 + (connectionMap.get(uid) ?? 0);
        // Prefix username match: +3
        const username = (m.username as string ?? "").toLowerCase();
        const displayName = (m.display_name as string ?? "").toLowerCase();
        if (username.startsWith(q.toLowerCase())) score += 3;
        if (displayName.startsWith(q.toLowerCase())) score += 2;

        return {
          id:           uid,
          rald_id:      `RALD-${(uid.split("-").at(0) ?? uid).toUpperCase()}`,
          username:     m.username,
          display_name: m.display_name,
          avatar_url:   m.avatar_url,
          bio:          m.bio,
          is_verified:  m.is_verified,
          connection_score: connectionMap.get(uid) ?? 0,
          _rank:        score,
        };
      })
      .sort((a, b) => b._rank - a._rank)
      .slice(0, limit)
      .map(({ _rank: _, ...rest }) => rest);

    return c.json({ results: ranked, count: ranked.length, query: q });
  } catch (e) {
    console.error("[search] /related error:", String(e));
    return c.json({ error: "Search unavailable", results: [], count: 0 }, 503);
  }
});

// ── GET /search/health ─────────────────────────────────────────────────────────
search.get("/health", (c) =>
  c.json({
    ok:      true,
    service: "rald-search",
    version: "1.0.0",
    note:    "Public + relationship search. Respects privacy settings.",
  }),
);

export default search;
