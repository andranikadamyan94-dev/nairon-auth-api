import { OAuthConfig } from './oauth.config';

/**
 * What a client may register as a redirect URI.
 *
 * Two rules, and the difference between them matters. At *registration* a URI
 * is checked against a policy — is this the kind of place we are willing to
 * send an authorization code? At *authorization* it is compared byte-for-byte
 * with what was registered. The policy is deliberately not consulted the
 * second time: loosening a comparison to a rule is how codes end up delivered
 * to a path nobody registered.
 *
 * The policy is host-based rather than a fixed callback because the exact URI
 * ChatGPT uses is not known until it registers one, and a guessed path would
 * break the day OpenAI changed it. The host is the part that must not drift.
 */
export interface RedirectCheck {
  ok: boolean;
  reason?: string;
}

export function checkRedirectUri(raw: string, config: OAuthConfig): RedirectCheck {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'redirect_uri must be an absolute URI' };
  }

  // A fragment cannot survive the redirect anyway, and its presence is a sign
  // the client is doing something other than what this flow expects.
  if (url.hash) return { ok: false, reason: 'redirect_uri must not contain a fragment' };

  const host = url.hostname.toLowerCase();
  const isLoopback = host === 'localhost' || host === '127.0.0.1' || host === '::1';

  if (url.protocol === 'http:') {
    // Native apps get a loopback exception in RFC 8252; everyone else does not,
    // and on a deployment it stays off unless someone turns it on for testing.
    if (!(isLoopback && config.allowLoopbackRedirects)) {
      return { ok: false, reason: 'redirect_uri must use https' };
    }
    return { ok: true };
  }

  if (url.protocol !== 'https:') {
    return { ok: false, reason: 'redirect_uri must use https' };
  }

  const allowed = config.allowedRedirectHosts.some(
    (suffix) => host === suffix || host.endsWith(`.${suffix}`),
  );
  if (!allowed) {
    return {
      ok: false,
      reason: `redirect_uri host is not permitted by this server's policy`,
    };
  }

  return { ok: true };
}

/**
 * The exact-match test used once a client is registered.
 *
 * No normalisation: not of the trailing slash, not of the case, not of the
 * query. The string presented must be the string stored.
 */
export function matchesRegistered(candidate: string, registered: string[]): boolean {
  return registered.includes(candidate);
}
