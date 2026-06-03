// RALD Auth Core — KV Session Authority
// Phase G.10: Production KV namespace rald-session
// Provides: create, get, revoke, revoke-all, suspend — backed by Cloudflare KV
// LILCKY STUDIO LIMITED

export interface KvSessionStore {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  list(options?: { prefix?: string }): Promise<{ keys: { name: string }[] }>;
  delete(key: string): Promise<void>;
}

export interface KvSession {
  session_id: string;
  user_id:    string;
  device_id:  string | null;
  created_at: string;
  expires_at: string;
  revoked:    boolean;
  app_id?:    string;
  ip?:        string;
  user_agent?: string;
}

const SESSION_TTL_SECONDS = 86400;     // 24h — matches JWT expiry
const REVOKE_TOMBSTONE_TTL = 172800;   // 48h — keep revoked marker longer than token TTL

/** Build the per-session KV key. */
function sessionKey(sessionId: string): string {
  return `sess:${sessionId}`;
}

/** Build the user-index KV key (stores CSV of session IDs). */
function userIndexKey(userId: string): string {
  return `user-sess:${userId}`;
}

/** Build the suspension marker KV key. */
function suspensionKey(userId: string): string {
  return `suspended:${userId}`;
}

// ── Write a new session to KV after login/register ────────────────────────────
export async function createKvSession(
  kv: KvSessionStore,
  session: Omit<KvSession, "revoked">
): Promise<void> {
  try {
    const payload: KvSession = { ...session, revoked: false };
    await kv.put(sessionKey(session.session_id), JSON.stringify(payload), {
      expirationTtl: SESSION_TTL_SECONDS,
    });

    // Append to user index for logout-all
    const idxKey = userIndexKey(session.user_id);
    const existing = await kv.get(idxKey);
    const ids: string[] = existing ? JSON.parse(existing) : [];
    if (!ids.includes(session.session_id)) ids.push(session.session_id);
    // Keep index for 30 days
    await kv.put(idxKey, JSON.stringify(ids), { expirationTtl: 2592000 });
  } catch (err) {
    console.warn("[session-kv] createKvSession failed:", String(err));
  }
}

// ── Read a session from KV ────────────────────────────────────────────────────
export async function getKvSession(
  kv: KvSessionStore,
  sessionId: string
): Promise<KvSession | null> {
  try {
    const raw = await kv.get(sessionKey(sessionId));
    if (!raw) return null;
    return JSON.parse(raw) as KvSession;
  } catch {
    return null;
  }
}

// ── Check if a session is active (not revoked, not expired) ───────────────────
// If session does not exist in KV, we trust the JWT (backward compat).
// If it exists and is revoked, we deny.
export async function isSessionActive(
  kv: KvSessionStore,
  sessionId: string
): Promise<{ active: boolean; reason?: string }> {
  try {
    const sess = await getKvSession(kv, sessionId);
    if (!sess) return { active: true }; // not tracked in KV yet — trust JWT
    if (sess.revoked) return { active: false, reason: "session_revoked" };
    if (new Date(sess.expires_at) < new Date()) return { active: false, reason: "session_expired" };
    return { active: true };
  } catch {
    return { active: true }; // KV failure → fail open (never block legitimate traffic)
  }
}

// ── Check if user account is suspended ────────────────────────────────────────
export async function isUserSuspended(
  kv: KvSessionStore,
  userId: string
): Promise<boolean> {
  try {
    const val = await kv.get(suspensionKey(userId));
    return val === "1";
  } catch {
    return false;
  }
}

// ── Revoke a single session ───────────────────────────────────────────────────
export async function revokeKvSession(
  kv: KvSessionStore,
  sessionId: string
): Promise<void> {
  try {
    const existing = await getKvSession(kv, sessionId);
    const payload: KvSession = existing
      ? { ...existing, revoked: true }
      : {
          session_id: sessionId,
          user_id:    "unknown",
          device_id:  null,
          created_at: new Date().toISOString(),
          expires_at: new Date().toISOString(),
          revoked:    true,
        };
    await kv.put(sessionKey(sessionId), JSON.stringify(payload), {
      expirationTtl: REVOKE_TOMBSTONE_TTL,
    });
  } catch (err) {
    console.warn("[session-kv] revokeKvSession failed:", String(err));
  }
}

// ── Revoke ALL sessions for a user (logout everywhere) ───────────────────────
export async function revokeAllUserSessions(
  kv: KvSessionStore,
  userId: string
): Promise<number> {
  try {
    const idxKey = userIndexKey(userId);
    const raw = await kv.get(idxKey);
    const ids: string[] = raw ? JSON.parse(raw) : [];
    for (const id of ids) {
      await revokeKvSession(kv, id);
    }
    // Clear the index
    await kv.put(idxKey, JSON.stringify([]), { expirationTtl: 60 });
    return ids.length;
  } catch (err) {
    console.warn("[session-kv] revokeAllUserSessions failed:", String(err));
    return 0;
  }
}

// ── Suspend a user account (blocks all future session checks) ─────────────────
export async function suspendUser(
  kv: KvSessionStore,
  userId: string
): Promise<void> {
  try {
    await kv.put(suspensionKey(userId), "1", { expirationTtl: 31536000 }); // 1 year
    await revokeAllUserSessions(kv, userId);
  } catch (err) {
    console.warn("[session-kv] suspendUser failed:", String(err));
  }
}

// ── Unsuspend a user ──────────────────────────────────────────────────────────
export async function unsuspendUser(
  kv: KvSessionStore,
  userId: string
): Promise<void> {
  try {
    await kv.delete(suspensionKey(userId));
  } catch (err) {
    console.warn("[session-kv] unsuspendUser failed:", String(err));
  }
}
