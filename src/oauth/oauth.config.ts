/**
 * Every URL this authorization server publishes, read from the environment.
 *
 * Nothing here is hard-coded to a domain. The same build runs on a laptop
 * against http://localhost:3002 and on the VPS against https://nairon.am; only
 * these values change. That matters more than it looks: an OAuth issuer that
 * disagrees with itself about its own identity fails discovery in ways that
 * are tedious to diagnose, and the values appear in three separate documents
 * (issuer metadata, resource metadata, and the `iss`/`aud` claims of every
 * token), so they have exactly one source.
 */
export interface OAuthConfig {
  /** The `issuer` claim and the base of every published endpoint. */
  issuer: string;
  /** Where a browser reaches this server. Usually the same as `issuer`. */
  publicBaseUrl: string;
  /** The MCP resource these tokens are bound to. Becomes their `aud`. */
  mcpResource: string;
  /**
   * Signs OAuth access tokens — deliberately NOT the Nairon JWT secret.
   *
   * This is the single most important line in the file. Nairon's services
   * authenticate a person by verifying a JWT with JWT_SECRET; if an OAuth
   * access token were signed with that same key it would *be* a Nairon
   * session token, and the whole point of the token exchange would collapse
   * the moment one leaked into a downstream call. Signed with a different key,
   * an OAuth token presented to crm-api is not a weaker credential — it is not
   * a credential at all.
   */
  tokenSecret: string;
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
  codeTtlSec: number;
  /** How long a half-finished authorize request stays resumable. */
  authzRequestTtlSec: number;
  /** Lifetime of the internal Nairon JWT minted by the exchange. */
  internalTokenTtlSec: number;
  /**
   * Host suffixes a registered redirect URI may use.
   *
   * A policy rather than a fixed callback: the exact URI ChatGPT registers is
   * not known until it registers, and pinning a guess would break the moment
   * OpenAI changed a path. The host is what must not drift.
   */
  allowedRedirectHosts: string[];
  /** Allow http:// loopback redirect URIs. Development only. */
  allowLoopbackRedirects: boolean;
  hrApiUrl?: string;
  /** Outbound only, for naming entities. Never checked on an inbound request. */
  internalSecret?: string;
}

export const OAUTH_SCOPES = {
  /** Use the Nairon MCP resource. Carries no business rights of its own. */
  MCP: 'nairon:mcp',
  /** Ask for a refresh token. */
  OFFLINE: 'offline_access',
} as const;

export const SUPPORTED_SCOPES: string[] = [OAUTH_SCOPES.MCP, OAUTH_SCOPES.OFFLINE];

/*
 * Scope names carry no permissions on purpose.
 *
 * `nairon:mcp` says "this credential may reach the MCP resource" and stops
 * there. What the person may actually read or change is decided, request by
 * request, by their Nairon roles — the same PermissionGuard the browser meets.
 * A read/write split in the scope string would create a second, weaker place
 * where authorization appears to be decided, and the two would drift.
 */

function requireEnv(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(
      `${name} is not set. The OAuth authorization server cannot publish a ` +
        'consistent identity without it.',
    );
  }
  return value.replace(/\/+$/, '');
}

export function oauthConfig(env: NodeJS.ProcessEnv = process.env): OAuthConfig {
  const publicBase = requireEnv('OAUTH_PUBLIC_BASE_URL', env.OAUTH_ISSUER_URL);
  return {
    issuer: requireEnv('OAUTH_ISSUER_URL', publicBase),
    publicBaseUrl: publicBase,
    mcpResource: requireEnv('MCP_RESOURCE_URL'),
    // The dev fallback is deliberately obvious. A deployment that forgets to
    // set this should be recognisable at a glance, not silently insecure.
    tokenSecret: env.OAUTH_TOKEN_SECRET || 'nairon_local_dev_oauth_secret',
    accessTokenTtlSec: Number(env.OAUTH_ACCESS_TOKEN_TTL_SEC ?? 600),
    refreshTokenTtlSec: Number(env.OAUTH_REFRESH_TOKEN_TTL_SEC ?? 30 * 24 * 3600),
    codeTtlSec: Number(env.OAUTH_CODE_TTL_SEC ?? 60),
    authzRequestTtlSec: Number(env.OAUTH_AUTHZ_REQUEST_TTL_SEC ?? 600),
    internalTokenTtlSec: Number(env.OAUTH_INTERNAL_TOKEN_TTL_SEC ?? 300),
    allowedRedirectHosts: (env.OAUTH_ALLOWED_REDIRECT_HOSTS ?? 'chatgpt.com,openai.com')
      .split(',')
      .map((h) => h.trim().toLowerCase())
      .filter(Boolean),
    allowLoopbackRedirects: env.OAUTH_ALLOW_LOOPBACK_REDIRECTS === 'true',
    hrApiUrl: env.HR_API_URL?.replace(/\/+$/, ''),
    // Its own name on purpose. INTERNAL_SECRET set on this service would flip
    // InternalGuard from fail-open to fail-closed on the users, roles and
    // permissions routes that other services already call without the header.
    internalSecret: env.HR_INTERNAL_SECRET,
  };
}
