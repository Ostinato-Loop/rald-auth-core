// RALD Ecosystem Finalization Program — Phase 11: Machine Identity
// Machine JWT middleware — replacement for X-Internal-Secret pattern

import type { Context, Next } from "hono";
import type { Env } from "../types";

export interface MachineClaims {
  sub:         string;   // e.g. "svc:loop-worker"
  aud:         string;   // e.g. "svc:auth-core"
  iss:         string;   // "auth.rald.cloud"
  permissions: string[];
  machine:     boolean;
  iat:         number;
  exp:         number;
}

/**
 * Verify a machine JWT.
 *
 * Phase 11: During migration, we accept BOTH X-Internal-Secret (legacy)
 * and MachineBearer (new). Once all callers are migrated, remove the
 * X-Internal-Secret fallback.
 *
 * TODO: Replace symmetric verification with asymmetric ES256/Ed25519
 * once machine key pairs are generated and registered.
 */
export async function verifyMachineAuth(
  c: Context<{ Bindings: Env }>,
  requiredPermission: string
): Promise<MachineClaims | null> {
  const auth = c.req.header("Authorization") ?? "";

  // Legacy: X-Internal-Secret (to be deprecated after Phase 11 migration)
  const internalSecret = c.req.header("X-Internal-Secret");
  if (internalSecret && internalSecret === c.env.INTERNAL_SECRET) {
    // Grant all permissions for legacy callers
    return {
      sub: "svc:legacy-caller",
      aud: "svc:auth-core",
      iss: "auth.rald.cloud",
      permissions: ["*"],
      machine: true,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
    };
  }

  // New: MachineBearer JWT
  if (auth.startsWith("MachineBearer ")) {
    const token = auth.slice("MachineBearer ".length);
    try {
      // TODO: Replace with asymmetric verification once keys are provisioned
      // For now, use RALD_JWT_SECRET with machine:true claim check
      const { jwtVerify } = await import("jose");
      const secret = new TextEncoder().encode(c.env.RALD_JWT_SECRET);
      const { payload } = await jwtVerify(token, secret, {
        audience: "svc:auth-core",
        issuer:   "auth.rald.cloud",
      });

      if (!payload.machine) return null;

      const perms = (payload.permissions as string[]) ?? [];
      if (!perms.includes("*") && !perms.includes(requiredPermission)) return null;

      return payload as unknown as MachineClaims;
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Hono middleware: require machine identity with a specific permission.
 *
 * Usage:
 *   app.post("/internal/route", requireMachine("session.read"), handler)
 */
export function requireMachine(requiredPermission: string) {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    const machine = await verifyMachineAuth(c, requiredPermission);
    if (!machine) {
      return c.json({
        error: "machine_auth_required",
        message: "This endpoint requires a valid machine identity token.",
      }, 401);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (c as any).set("machine", machine);
    return next();
  };
}
