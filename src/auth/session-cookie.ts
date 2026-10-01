import { Request, Response } from "express";

/**
 * The shared session cookie, in one place.
 *
 * Moved out of auth.controller.ts unchanged (2026-10-01) so the cross-app
 * handoff exchange (handoff/) sets exactly the cookie login sets — same name,
 * same flags, same stale parent-domain clear — rather than a second copy that
 * could drift.
 */
export const COOKIE_NAME = "nairon_session";
const COOKIE_BASE = {
  httpOnly: true,
  sameSite: "strict" as const,
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days (matches JWT TTL)
  path: "/",
};

/**
 * Secure unless the request is plain http to a host that is not localhost.
 *
 * The flag used to follow NODE_ENV alone, and staging and production both
 * issued the cookie without it (2026-09-22 sweep). Now anything that arrived
 * over https — req.protocol honours X-Forwarded-Proto behind the trusted
 * proxy — or answers to localhost (a secure context for browsers, so the
 * flag costs local development nothing) gets Secure; NODE_ENV=production
 * still forces it. The one case left without it is http on a LAN address.
 */
export function cookieOptions(req: Request) {
  const host = (req.hostname ?? "").toLowerCase();
  const local = host === "localhost" || host === "127.0.0.1" || host === "::1";
  const secure = process.env.NODE_ENV === "production" || req.protocol === "https" || local;
  return { ...COOKIE_BASE, secure };
}

/** `gateway.nairon.am` → `.nairon.am`; nothing for localhost / IPs. */
export function parentDomainOf(req: Request): string | null {
  const host = String(req.headers["x-forwarded-host"] ?? req.headers.host ?? "").split(":")[0];
  const labels = host.split(".");
  if (labels.length < 3 || /^\d+$/.test(labels[labels.length - 1])) return null;
  return "." + labels.slice(1).join(".");
}

export function clearStaleParentCookie(req: Request, res: Response) {
  const domain = parentDomainOf(req);
  if (domain) res.clearCookie(COOKIE_NAME, { path: "/", domain });
}
