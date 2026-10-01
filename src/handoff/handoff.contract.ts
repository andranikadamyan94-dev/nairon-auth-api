import { browserOrigins } from '../shared/browser-origins';

/**
 * One-time cross-app sign-in codes — the rules, kept free of Nest so they can
 * be read and tested on their own. See claude-work/design/SSO-HANDOFF-HARDENING.md.
 *
 * Before: moving from one Nairon app to another put the whole stored session
 * — a 30-day access token plus the user record — into the destination URL's
 * fragment (`#auth=<json>`). After: the source app asks for a code bound to
 * the destination's origin, the URL carries only `#handoff=<code>`, and the
 * destination trades the code, once, within a minute, for its own session.
 */

/** The rollout switch. Off (unset) → both routes answer 404 and clients keep the old fragment. */
export function handoffCodesEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.AUTH_HANDOFF_CODES_ENABLED === 'true';
}

export const HANDOFF_TTL_DEFAULT_SEC = 60;
export const HANDOFF_TTL_MIN_SEC = 10;
export const HANDOFF_TTL_MAX_SEC = 60;

/** AUTH_HANDOFF_CODE_TTL_SEC, clamped to 10–60 s; 60 s when unset or not a number. */
export function handoffTtlSec(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.AUTH_HANDOFF_CODE_TTL_SEC);
  if (!Number.isFinite(raw) || raw <= 0) return HANDOFF_TTL_DEFAULT_SEC;
  return Math.min(HANDOFF_TTL_MAX_SEC, Math.max(HANDOFF_TTL_MIN_SEC, Math.floor(raw)));
}

/** randomToken(32): 256 bits, base64url, always 43 characters. */
export const HANDOFF_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * The origins a code may be bound to: the browser origins this service
 * already serves (CORS), minus the gateways — an API host is never a page a
 * person is sent to.
 */
export function handoffTargets(env: NodeJS.ProcessEnv = process.env): Set<string> {
  return new Set(
    browserOrigins(env).filter((origin) => {
      try {
        return !new URL(origin).hostname.includes('gateway');
      } catch {
        return false;
      }
    }),
  );
}

/**
 * The exact origin a code is requested for, or null.
 *
 * Accepts `https://crm.nairon.am` or `https://crm.nairon.am/`, nothing with a
 * path, query, fragment or credentials, and nothing outside handoffTargets().
 */
export function normalizeTargetOrigin(raw: unknown, env: NodeJS.ProcessEnv = process.env): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 200) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.username || url.password || url.search || url.hash) return null;
  if (url.pathname !== '/' && url.pathname !== '') return null;
  return handoffTargets(env).has(url.origin) ? url.origin : null;
}

/**
 * Only an ordinary sign-in token may be turned into a code.
 *
 * The estate signs several other kinds of token with the same key: delegated
 * AI tokens (`act`, `jti`, `scope`), the MCP OAuth bridge token (`src`), the
 * one-minute probes (`src`). Every one of them passes the session guard, and
 * every one of them is narrower or shorter-lived than a session. Trading one
 * for a code would trade it for a fresh 30-day full session, so the payload
 * must be exactly what login signs — `{ id, email }` plus the JWT times —
 * and nothing more.
 */
const SESSION_CLAIMS = new Set(['id', 'email', 'iat', 'exp']);
export function isSessionPayload(payload: unknown): payload is { id: number; email?: string } {
  if (!payload || typeof payload !== 'object') return false;
  const p = payload as Record<string, unknown>;
  if (!Object.keys(p).every((k) => SESSION_CLAIMS.has(k))) return false;
  return Number.isSafeInteger(p.id) && (p.id as number) > 0;
}
