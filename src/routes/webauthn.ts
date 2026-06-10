// RALD Auth Core — WebAuthn / Biometric / Face Authentication (FIDO2)
// POST /auth/webauthn/register/options  → registration challenge (requires auth)
// POST /auth/webauthn/register/verify   → verify + store credential (requires auth)
// POST /auth/webauthn/login/options     → assertion challenge (public)
// POST /auth/webauthn/login/verify      → verify assertion + issue session
// LILCKY STUDIO LIMITED

import { Hono } from "hono";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
} from "@simplewebauthn/server";
import { authMiddleware } from "../lib/middleware";
import type { Bindings, Variables } from "../index";
import { buildSessionCookie } from "../lib/cookie";
import { signJwt } from "../lib/auth";
import { writeAuditLog } from "../lib/audit";
import { getClientIp } from "../lib/rate-limit";

// Cloudflare Workers does not have Buffer — use btoa/atob instead
function uint8ToBase64url(bytes: Uint8Array): string {
  let bStr = "";
  for (let i = 0; i < bytes.byteLength; i++) bStr += String.fromCharCode(bytes[i]!);
  return btoa(bStr).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlToUint8(str: string): Uint8Array<ArrayBuffer> {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const bStr = atob(b64);
  const out = new Uint8Array(bStr.length);
  for (let i = 0; i < bStr.length; i++) out[i] = bStr.charCodeAt(i);
  return out;
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const RP_ID   = "rald.cloud";
const RP_NAME = "RALD Identity";
const ORIGINS = [
  "https://profiles.rald.cloud",
  "https://rald-identity.pages.dev",
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost:4173",
];

const webauthn = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ── Registration options (authenticated user adds biometric) ──────────────────
webauthn.post("/register/options", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const kv   = c.env.RATE_LIMIT_KV;

  // Fetch existing credentials so they can be excluded
  const { data: existing } = await db
    .from("webauthn_credentials")
    .select("credential_id, transports")
    .eq("user_id", user.id);

  const userIdBytes = new TextEncoder().encode(user.id);

  const options = await generateRegistrationOptions({
    rpName:      RP_NAME,
    rpID:        RP_ID,
    userID:      userIdBytes,
    userName:    (user.username as string | undefined) ?? (user.email as string | undefined) ?? user.id,
    userDisplayName: (user.name as string | undefined) ?? (user.username as string | undefined) ?? "RALD User",
    attestationType: "none",
    authenticatorSelection: {
      residentKey:               "preferred",
      userVerification:          "required",
      authenticatorAttachment:   "platform",
    },
    excludeCredentials: (existing ?? []).map((row) => ({
      id:         row.credential_id as string,
      transports: (row.transports as string[]) as AuthenticatorTransportFuture[],
    })),
  });

  await kv.put(`wa:reg-challenge:${user.id}`, options.challenge, {
    expirationTtl: 300,
  });

  return c.json(options);
});

// ── Registration verify ───────────────────────────────────────────────────────
webauthn.post("/register/verify", authMiddleware, async (c) => {
  const user = c.get("user")!;
  const db   = c.get("db");
  const kv   = c.env.RATE_LIMIT_KV;
  const ip   = getClientIp(c.req.raw);

  const body = await c.req.json<{ credential: RegistrationResponseJSON }>().catch(() => null);
  if (!body?.credential) return c.json({ error: "credential required" }, 400);

  const expectedChallenge = await kv.get(`wa:reg-challenge:${user.id}`);
  if (!expectedChallenge) return c.json({ error: "Challenge expired. Please try again." }, 400);
  await kv.delete(`wa:reg-challenge:${user.id}`);

  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response:              body.credential,
      expectedChallenge,
      expectedOrigin:        ORIGINS,
      expectedRPID:          RP_ID,
      requireUserVerification: true,
    });
  } catch (err) {
    return c.json({ error: "Verification failed", detail: (err as Error).message }, 400);
  }

  if (!verification.verified || !verification.registrationInfo) {
    return c.json({ error: "Verification failed" }, 400);
  }

  const { credential, credentialDeviceType, credentialBackedUp } =
    verification.registrationInfo;

  await db.from("webauthn_credentials").insert({
    user_id:       user.id,
    credential_id: credential.id,
    public_key:    uint8ToBase64url(credential.publicKey),
    counter:       credential.counter,
    device_type:   credentialDeviceType,
    backed_up:     credentialBackedUp,
    transports:    body.credential.response.transports ?? [],
  });

  await writeAuditLog(db, {
    user_id:  user.id,
    action:   "webauthn_credential_registered",
    status:   "success",
    ip,
    metadata: { device_type: credentialDeviceType, backed_up: credentialBackedUp },
  });

  return c.json({ ok: true, credentialId: credential.id });
});

// ── Authentication options (public — username lookup) ─────────────────────────
webauthn.post("/login/options", async (c) => {
  const body = await c.req.json<{ username: string }>().catch(() => null);
  if (!body?.username) return c.json({ error: "username required" }, 400);

  const db = c.get("db");
  const kv = c.env.RATE_LIMIT_KV;
  const u  = body.username.trim().toLowerCase();

  const { data: users } = await db
    .from("auth_users")
    .select("id, username, email, name, role")
    .or(`username.ilike.${u},email.ilike.${u}`)
    .limit(1);

  const user = users?.[0];

  if (!user) {
    // Return generic options to avoid username enumeration
    const options = await generateAuthenticationOptions({
      rpID:             RP_ID,
      userVerification: "required",
      allowCredentials: [],
    });
    await kv.put(`wa:auth-challenge:${u}`, JSON.stringify({ challenge: options.challenge, userId: null }), {
      expirationTtl: 300,
    });
    return c.json(options);
  }

  const { data: creds } = await db
    .from("webauthn_credentials")
    .select("credential_id, transports")
    .eq("user_id", user.id);

  if (!creds?.length) {
    return c.json(
      { error: "No biometric login is set up for this account. Please use another sign-in method." },
      404,
    );
  }

  const options = await generateAuthenticationOptions({
    rpID:             RP_ID,
    userVerification: "required",
    allowCredentials: creds.map((row) => ({
      id:         row.credential_id as string,
      transports: (row.transports as string[]) as AuthenticatorTransportFuture[],
    })),
  });

  await kv.put(
    `wa:auth-challenge:${u}`,
    JSON.stringify({ challenge: options.challenge, userId: user.id as string }),
    { expirationTtl: 300 },
  );

  return c.json(options);
});

// ── Authentication verify ─────────────────────────────────────────────────────
webauthn.post("/login/verify", async (c) => {
  const body = await c
    .req.json<{ username: string; credential: AuthenticationResponseJSON }>()
    .catch(() => null);
  if (!body?.username || !body?.credential)
    return c.json({ error: "username and credential required" }, 400);

  const db  = c.get("db");
  const kv  = c.env.RATE_LIMIT_KV;
  const ip  = getClientIp(c.req.raw);
  const u   = body.username.trim().toLowerCase();

  const stored = await kv.get(`wa:auth-challenge:${u}`);
  if (!stored) return c.json({ error: "Challenge expired. Please try again." }, 400);
  await kv.delete(`wa:auth-challenge:${u}`);

  const { challenge, userId } = JSON.parse(stored) as { challenge: string; userId: string | null };
  if (!userId) return c.json({ error: "No biometric login is set up for this account." }, 404);

  // Look up the matching credential
  const { data: credRows } = await db
    .from("webauthn_credentials")
    .select("*")
    .eq("user_id", userId)
    .eq("credential_id", body.credential.id)
    .limit(1);

  const cred = credRows?.[0];
  if (!cred) return c.json({ error: "Credential not found" }, 400);

  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response:          body.credential,
      expectedChallenge: challenge,
      expectedOrigin:    ORIGINS,
      expectedRPID:      RP_ID,
      credential: {
        id:         cred.credential_id as string,
        publicKey:  base64urlToUint8(cred.public_key as string) as Uint8Array<ArrayBuffer>,
        counter:    cred.counter as number,
        transports: (cred.transports as string[]) as AuthenticatorTransportFuture[],
      },
      requireUserVerification: true,
    });
  } catch (err) {
    await writeAuditLog(db, {
      user_id:  userId,
      action:   "webauthn_login_failed",
      status:   "failure",
      ip,
      metadata: { error: (err as Error).message, credential_id: body.credential.id },
    });
    return c.json({ error: "Biometric verification failed" }, 401);
  }

  if (!verification.verified) {
    return c.json({ error: "Biometric verification failed" }, 401);
  }

  // Update usage counter
  await db
    .from("webauthn_credentials")
    .update({
      counter:      verification.authenticationInfo.newCounter,
      last_used_at: new Date().toISOString(),
    })
    .eq("id", cred.id as string);

  // Fetch full user row
  const { data: users } = await db
    .from("auth_users")
    .select("id, username, email, name, role, rald_internal_id")
    .eq("id", userId)
    .limit(1);

  const user = users?.[0];
  if (!user) return c.json({ error: "User not found" }, 404);

  // Issue 30-day session JWT
  const token = await signJwt(
    {
      id:       user.id as string,
      username: user.username as string | undefined,
      email:    user.email as string | undefined,
      role:     user.role as string,
      iss:      "rald.cloud",
      via:      "webauthn",
    },
    c.env.RALD_JWT_SECRET,
  );

  const tokenHash = await sha256Hex(token);

  await db.from("auth_sessions").insert({
    user_id:      user.id,
    token_hash:   tokenHash,
    expires_at:   new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
    ip_address:   ip,
    user_agent:   c.req.header("user-agent") ?? "",
    login_method: "webauthn",
  });

  await writeAuditLog(db, {
    user_id:  user.id as string,
    action:   "webauthn_login_success",
    status:   "success",
    ip,
    metadata: { credential_id: cred.credential_id },
  });

  return c.json(
    {
      ok:   true,
      token,
      user: {
        id:               user.id,
        username:         user.username,
        name:             user.name,
        role:             user.role,
        rald_internal_id: user.rald_internal_id,
      },
    },
    200,
    { "Set-Cookie": buildSessionCookie(token) },
  );
});

export default webauthn;
