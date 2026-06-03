// RALD Auth Core — Ecosystem Redirect Validation
// Enforces: only *.rald.cloud and *.ostloop.name.ng redirects allowed
// LILCKY STUDIO LIMITED

const ALLOWED_PATTERNS: RegExp[] = [
  /^https:\/\/rald\.cloud(\/.*)?$/,
  /^https:\/\/[\w-]+\.rald\.cloud(\/.*)?$/,
  /^https:\/\/ostloop\.name\.ng(\/.*)?$/,
  /^https:\/\/[\w-]+\.ostloop\.name\.ng(\/.*)?$/,
];

/** Returns true only for safe RALD ecosystem redirect URLs. */
export function validateRedirectUrl(url: string | null | undefined): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    return ALLOWED_PATTERNS.some((r) => r.test(url.split("?")[0] + (url.includes("?") ? "" : "")));
  } catch {
    return false;
  }
}

/** Returns the redirect URL if valid, or the fallback. */
export function safeRedirect(url: string | null | undefined, fallback = "https://profiles.rald.cloud"): string {
  return validateRedirectUrl(url) ? url! : fallback;
}

export const ECOSYSTEM_APPS = [
  { id: "profiles",      name: "Profile",      url: "https://profiles.rald.cloud",      icon: "👤" },
  { id: "loop",          name: "Loop",         url: "https://loop.rald.cloud",           icon: "🎵" },
  { id: "messenger",     name: "Messenger",    url: "https://messenger.rald.cloud",      icon: "💬" },
  { id: "rald-inbox",    name: "Inbox",        url: "https://inbox.rald.cloud",          icon: "📥" },
  { id: "payrald",       name: "PayRald",      url: "https://pay.rald.cloud",            icon: "💳" },
  { id: "dunarald",      name: "DunaRald",     url: "https://duna.rald.cloud",           icon: "🛒" },
  { id: "gitrald",       name: "GitRald",      url: "https://git.rald.cloud",            icon: "⚙️"  },
  { id: "raldtics",      name: "Raldtics",     url: "https://analytics.rald.cloud",      icon: "📊" },
] as const;

export type EcosystemAppId = typeof ECOSYSTEM_APPS[number]["id"];
