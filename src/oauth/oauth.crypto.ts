import { createHash, randomBytes, timingSafeEqual } from 'crypto';

/**
 * The small, sharp things: secrets, their hashes, and PKCE.
 *
 * Every credential this server hands out is random bytes; every copy it keeps
 * is a SHA-256 of those bytes. So a dump of the OAuth tables is a list of
 * hashes, not a set of working codes and refresh tokens — the same reason the
 * confirmation store in nairon-ai-api keeps hashes rather than tokens.
 */

/** 256 bits, URL-safe. Used for codes, refresh tokens and client ids. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Constant-time compare for anything an attacker can guess at repeatedly. */
export function safeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a ?? '', 'utf8');
  const right = Buffer.from(b ?? '', 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Verify a PKCE code_verifier against the challenge stored with the code.
 *
 * S256 only. `plain` is still in the spec for historical reasons and is
 * exactly as good as no PKCE at all, so it is not implemented rather than
 * implemented-and-refused: there is no branch here for an attacker to reach.
 */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  // RFC 7636 §4.1: 43–128 characters from the unreserved set.
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier ?? '')) return false;
  const computed = createHash('sha256').update(verifier).digest('base64url');
  return safeEquals(computed, challenge ?? '');
}
