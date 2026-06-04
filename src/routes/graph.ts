// RALD Auth Core — Identity Graph Routes
// Phase: RALD Identity Graph (Priority 3) + Mutual Connection System (Priority 5)
//
// The Identity Graph represents relationships between RALD users.
// A user is represented ONCE across the ecosystem — the graph records
// how users are connected: contacts, shared rooms, shared communities,
// shared events, shared organizations.
//
// DB Tables Required:
//   rald_connections      — (user_id, target_user_id, type, score, created_at)
//   rald_connection_edges — (user_id, target_user_id, edge_type, weight, created_at)
//
// Connection Score is computed from:
//   +2 per shared room session
//   +3 per direct message thread
//   +5 per contact match
//   +10 for mutual followers
//   +1 per shared community / group
//
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";

const graph = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── GET /graph/me — current user's connection summary ─────────────────────────
graph.get("/me", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const { data: connections, error } = await db
    .from("rald_connections")
    .select("target_user_id,type,connection_score,created_at")
    .eq("user_id", user.id)
    .order("connection_score", { ascending: false })
    .limit(100);

  if (error) {
    return c.json({ connections: [], count: 0, user_id: user.id });
  }

  return c.json({
    user_id:     user.id,
    connections: connections ?? [],
    count:       (connections ?? []).length,
    rald_id:     `RALD-${user.id.split("-")[0].toUpperCase()}`,
  });
});

// ── GET /graph/mutual/:userId — mutual connections between me and another user ─
graph.get("/mutual/:userId", authMiddleware, async (c) => {
  const user       = c.get("user")!;
  const targetId   = c.req.param("userId");
  const db         = c.get("db");

  if (!targetId || targetId === user.id) {
    return c.json({ error: "Invalid userId" }, 400);
  }

  // Get connections of the authenticated user
  const { data: myConns } = await db
    .from("rald_connections")
    .select("target_user_id")
    .eq("user_id", user.id);

  const myConnIds = new Set((myConns ?? []).map((r: Record<string, unknown>) => r["target_user_id"] as string));

  // Get connections of the target user
  const { data: theirConns } = await db
    .from("rald_connections")
    .select("target_user_id")
    .eq("user_id", targetId);

  const theirConnIds = (theirConns ?? []).map((r: Record<string, unknown>) => r["target_user_id"] as string);
  const mutualIds    = theirConnIds.filter((id) => myConnIds.has(id));

  if (mutualIds.length === 0) {
    return c.json({ mutual_connections: [], count: 0, user_id: targetId });
  }

  // Fetch profiles for mutual connections
  const { data: profiles } = await db
    .from("auth_user_profiles")
    .select("user_id,username,display_name,avatar_url,is_verified")
    .in("user_id", mutualIds);

  return c.json({
    mutual_connections: profiles ?? [],
    count:              (profiles ?? []).length,
    user_id:            targetId,
    computed_at:        new Date().toISOString(),
  });
});

// ── GET /graph/score/:userId — connection score between me and another user ────
graph.get("/score/:userId", authMiddleware, async (c) => {
  const user     = c.get("user")!;
  const targetId = c.req.param("userId");
  const db       = c.get("db");

  if (!targetId) return c.json({ error: "userId required" }, 400);

  const { data: conn } = await db
    .from("rald_connections")
    .select("connection_score,type,created_at")
    .eq("user_id", user.id)
    .eq("target_user_id", targetId)
    .maybeSingle();

  // Get edge details (what contributes to the score)
  const { data: edges } = await db
    .from("rald_connection_edges")
    .select("edge_type,weight,created_at")
    .eq("user_id", user.id)
    .eq("target_user_id", targetId)
    .order("weight", { ascending: false });

  return c.json({
    user_id:          user.id,
    target_user_id:   targetId,
    connection_score: conn?.connection_score ?? 0,
    type:             conn?.type ?? "none",
    connected_since:  conn?.created_at ?? null,
    edge_breakdown:   edges ?? [],
    computed_at:      new Date().toISOString(),
  });
});

// ── POST /graph/connect — establish or strengthen a connection ─────────────────
// Body: { target_user_id, type, edge_type, weight? }
// edge_type: "shared_room" | "direct_message" | "contact" | "mutual_follow" | "community"
graph.post("/connect", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");

  const body = await c.req.json<{
    target_user_id: string;
    edge_type: "shared_room" | "direct_message" | "contact" | "mutual_follow" | "community";
    weight?: number;
  }>().catch(() => null);

  if (!body?.target_user_id || !body?.edge_type) {
    return c.json({ error: "target_user_id and edge_type are required" }, 400);
  }

  if (body.target_user_id === user.id) {
    return c.json({ error: "Cannot connect to yourself" }, 400);
  }

  const EDGE_WEIGHTS: Record<string, number> = {
    shared_room:    2,
    direct_message: 3,
    contact:        5,
    mutual_follow:  10,
    community:      1,
  };

  const weight = body.weight ?? EDGE_WEIGHTS[body.edge_type] ?? 1;
  const now    = new Date().toISOString();

  // Record the edge
  await db.from("rald_connection_edges").insert({
    user_id:        user.id,
    target_user_id: body.target_user_id,
    edge_type:      body.edge_type,
    weight,
    created_at:     now,
  });

  // Upsert the connection with recalculated score
  const { data: existing } = await db
    .from("rald_connections")
    .select("connection_score")
    .eq("user_id", user.id)
    .eq("target_user_id", body.target_user_id)
    .maybeSingle();

  const newScore = (existing?.connection_score ?? 0) + weight;
  await db.from("rald_connections").upsert(
    {
      user_id:          user.id,
      target_user_id:   body.target_user_id,
      type:             body.edge_type === "mutual_follow" ? "follow" : "connected",
      connection_score: newScore,
      updated_at:       now,
    },
    { onConflict: "user_id,target_user_id" },
  );

  return c.json({ ok: true, connection_score: newScore, edge_type: body.edge_type, weight });
});

// ── GET /graph/suggestions — friend/connection suggestions ────────────────────
// Returns users with highest mutual connection scores who the user is NOT connected to yet.
graph.get("/suggestions", authMiddleware, async (c) => {
  const user  = c.get("user")!;
  const db    = c.get("db");
  const limit = Math.min(parseInt(c.req.query("limit") ?? "10"), 50);

  // Get existing connections
  const { data: existing } = await db
    .from("rald_connections")
    .select("target_user_id")
    .eq("user_id", user.id);

  const existingIds = new Set([
    user.id,
    ...(existing ?? []).map((r: Record<string, unknown>) => r["target_user_id"] as string),
  ]);

  // Find users connected to my connections (friends of friends)
  const myConnIds = [...existingIds].filter((id) => id !== user.id);
  if (myConnIds.length === 0) {
    return c.json({ suggestions: [], count: 0 });
  }

  const { data: friendsOfFriends } = await db
    .from("rald_connections")
    .select("target_user_id,connection_score")
    .in("user_id", myConnIds)
    .not("target_user_id", "in", `(${[...existingIds].map((id) => `"${id}"`).join(",")})`)
    .order("connection_score", { ascending: false })
    .limit(limit * 2);

  if (!friendsOfFriends || friendsOfFriends.length === 0) {
    return c.json({ suggestions: [], count: 0 });
  }

  // Score aggregation: sum connection_scores across all paths
  const scoreMap = new Map<string, number>();
  for (const r of friendsOfFriends as Array<Record<string, unknown>>) {
    const id  = r["target_user_id"] as string;
    const sc  = r["connection_score"] as number ?? 0;
    scoreMap.set(id, (scoreMap.get(id) ?? 0) + sc);
  }

  const topIds = [...scoreMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([id]) => id);

  if (topIds.length === 0) return c.json({ suggestions: [], count: 0 });

  const { data: profiles } = await db
    .from("auth_user_profiles")
    .select("user_id,username,display_name,avatar_url,is_verified")
    .in("user_id", topIds);

  const suggestions = (profiles ?? []).map((p: Record<string, unknown>) => ({
    ...p,
    mutual_score: scoreMap.get(p["user_id"] as string) ?? 0,
    rald_id: `RALD-${(p["user_id"] as string).split("-")[0].toUpperCase()}`,
  }));

  return c.json({ suggestions, count: suggestions.length });
});

// ── GET /graph/schema — DB schema needed for the identity graph ───────────────
graph.get("/schema", (c) =>
  c.json({
    tables: [
      {
        name:        "rald_connections",
        description: "Canonical connection between two RALD users",
        columns: [
          { name: "id",               type: "uuid",        note: "primary key" },
          { name: "user_id",          type: "uuid",        note: "FK → auth_users.id" },
          { name: "target_user_id",   type: "uuid",        note: "FK → auth_users.id" },
          { name: "type",             type: "text",        note: "connected | follow | blocked" },
          { name: "connection_score", type: "integer",     note: "computed sum of edge weights" },
          { name: "created_at",       type: "timestamptz", note: "first connection" },
          { name: "updated_at",       type: "timestamptz", note: "last score update" },
        ],
        indexes: ["(user_id, target_user_id) UNIQUE", "user_id", "connection_score DESC"],
      },
      {
        name:        "rald_connection_edges",
        description: "Individual events that contribute to the connection score",
        columns: [
          { name: "id",               type: "uuid",    note: "primary key" },
          { name: "user_id",          type: "uuid",    note: "FK → auth_users.id" },
          { name: "target_user_id",   type: "uuid",    note: "FK → auth_users.id" },
          { name: "edge_type",        type: "text",    note: "shared_room | direct_message | contact | mutual_follow | community" },
          { name: "weight",           type: "integer", note: "contribution to connection_score" },
          { name: "created_at",       type: "timestamptz" },
        ],
        indexes: ["(user_id, target_user_id)", "edge_type"],
      },
      {
        name:        "auth_user_profiles",
        description: "Extended profile; search_discoverable controls visibility",
        columns_to_add: [
          { name: "search_discoverable", type: "boolean", default: true, note: "Privacy: false hides from search" },
          { name: "location",            type: "text",    note: "City, Country — optional" },
          { name: "interests",           type: "text[]",  note: "Interests for search filtering" },
          { name: "is_verified",         type: "boolean", default: false },
          { name: "rald_address",        type: "text",    note: "Unique RALD-XXXXXX identifier" },
        ],
      },
    ],
    note: "Run these migrations in Supabase before enabling graph and search features.",
  }),
);

export default graph;
