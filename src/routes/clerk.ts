// RALD Auth Core — Clerk Exchange Route
// After RALD auth succeeds, exchanges RALD JWT for a Clerk sign-in token
// so the user is silently signed into Clerk-powered apps.
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import type { Bindings, Variables } from "../index";
import { authMiddleware } from "../lib/middleware";

const clerkRouter = new Hono<{ Bindings: Bindings; Variables: Variables }>();

const CLERK_API = "https://api.clerk.com/v1";

// Trusted redirect origins per appId
const APP_REDIRECTS: Record<string, string> = {
  "rald-app":             "https://app.rald.cloud",
  "loop-business":        "https://loop.rald.cloud",
  "messenger":            "https://messenger.rald.cloud",
  "rald-control-center":  "https://admin.rald.cloud",
  "payrald":              "https://payrald.rald.cloud",
};

async function clerkGet<T>(path: string, apiKey: string): Promise<T> {
  const res = await fetch(`${CLERK_API}${path}`, {
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
  });
  const json = await res.json();
  if (!res.ok) throw new Error((json as { message?: string }).message ?? `Clerk GET ${path} failed`);
  return json as T;
}

async function clerkPost<T>(path: string, body: unknown, apiKey: string): Promise<T> {
  const res = await fetch(`${CLERK_API}${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error((json as { message?: string }).message ?? `Clerk POST ${path} failed`);
  return json as T;
}

type ClerkUser = { id: string; email_addresses: Array<{ email_address: string }> };
type ClerkSignInToken = { token: string; url: string };

async function findOrCreateClerkUser(
  email: string,
  name: string | null,
  externalId: string,
  apiKey: string
): Promise<ClerkUser> {
  // Try to find existing user by email
  const searchRes = await fetch(
    `${CLERK_API}/users?email_address=${encodeURIComponent(email)}&limit=1`,
    { headers: { Authorization: `Bearer ${apiKey}` } }
  );
  const users = (await searchRes.json()) as ClerkUser[];
  if (Array.isArray(users) && users.length > 0) return users[0]!;

  // Create new Clerk user
  const parts = (name ?? "RALD User").split(" ");
  const firstName = parts[0] ?? "RALD";
  const lastName  = parts.slice(1).join(" ") || "User";

  return clerkPost<ClerkUser>(
    "/users",
    {
      email_addresses: [{ email_address: email }],
      first_name: firstName,
      last_name: lastName,
      external_id: externalId,
      skip_password_requirement: true,
    },
    apiKey
  );
}

// POST /sso/clerk-exchange
// Requires: Authorization: Bearer <RALD JWT>
// Body: { appId: string, redirectTo?: string }
clerkRouter.post("/clerk-exchange", authMiddleware, async (c) => {
  const clerkKey = c.env.CLERK_SECRET_KEY;
  if (!clerkKey) {
    // Fallback: return a simple RALD redirect without Clerk
    const body = (await c.req.json().catch(() => ({}))) as { appId?: string };
    const appId = body.appId ?? "rald-app";
    const fallback = APP_REDIRECTS[appId] ?? "https://rald.cloud";
    return c.json({
      clerkTicket: "",
      redirectUrl: fallback,
      appId,
      fallback: true,
    });
  }

  const body = (await c.req.json().catch(() => null)) as {
    appId?: string;
    redirectTo?: string;
  } | null;

  const appId      = body?.appId ?? "rald-app";
  const baseUrl    = body?.redirectTo ?? APP_REDIRECTS[appId] ?? "https://rald.cloud";
  const user       = c.get("user")!;

  // Fetch full user record from DB
  const db = c.get("db");
  const { data: users } = await db
    .from("users")
    .select("id,email,name")
    .eq("id", user.id)
    .limit(1);

  const u = users?.[0];
  if (!u) return c.json({ error: "User not found" }, 404);

  try {
    const clerkUser = await findOrCreateClerkUser(u.email, u.name, u.id, clerkKey);

    // Create a short-lived sign-in token (60 seconds)
    const signInToken = await clerkPost<ClerkSignInToken>(
      "/sign_in_tokens",
      { user_id: clerkUser.id, expires_in_seconds: 60 },
      clerkKey
    );

    // Build redirect URL with Clerk ticket
    const redirectUrl = new URL(baseUrl);
    redirectUrl.searchParams.set("__clerk_ticket", signInToken.token);
    redirectUrl.searchParams.set("app_id", appId);

    return c.json({
      clerkTicket: signInToken.token,
      redirectUrl: redirectUrl.toString(),
      appId,
    });
  } catch (err) {
    console.error("[Clerk Exchange Error]", err);
    // Degrade gracefully — return app URL without Clerk ticket
    return c.json({
      clerkTicket: "",
      redirectUrl: baseUrl,
      appId,
      degraded: true,
    });
  }
});

// GET /sso/clerk-exchange/config — public endpoint for apps to discover Clerk pubkey
clerkRouter.get("/clerk-config", (c) => {
  return c.json({
    publishableKey: c.env.CLERK_PUBLISHABLE_KEY ?? "",
    available: !!c.env.CLERK_SECRET_KEY,
  });
});

export default clerkRouter;
