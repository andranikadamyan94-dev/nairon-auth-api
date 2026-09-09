import { JwtService } from '@nestjs/jwt';

import { AuthService } from '../../auth/auth.service';
import { jwtConstants } from '../../auth/constants';
import { AuthPrismaService } from '../../prisma.service';
import { OAuthError, OAuthService } from '../oauth.service';
import { verifyPkceS256, sha256, randomToken, safeEquals } from '../oauth.crypto';
import { checkRedirectUri, matchesRegistered } from '../redirect-policy';
import { oauthConfig } from '../oauth.config';

/*
 * The authorization server, checked where it decides things.
 *
 * These tests never touch the database or another service. Prisma is a stub
 * and so is the password check, because what is under test is the protocol —
 * who may redeem what, bound to which audience, on whose behalf — and not
 * whether Postgres works.
 */

const ENV = {
  OAUTH_ISSUER_URL: 'https://auth.example.test',
  OAUTH_PUBLIC_BASE_URL: 'https://auth.example.test',
  MCP_RESOURCE_URL: 'http://127.0.0.1:3010/mcp',
  OAUTH_TOKEN_SECRET: 'oauth-signing-key-for-tests',
  OAUTH_ALLOWED_REDIRECT_HOSTS: 'chatgpt.com,openai.com',
  OAUTH_ALLOW_LOOPBACK_REDIRECTS: 'true',
  // Emptied deliberately. Naming workspaces is a best-effort call to hr-api,
  // and a unit test that reached a running service would pass or fail
  // depending on what happened to be up rather than on this code.
  HR_API_URL: '',
  HR_INTERNAL_SECRET: '',
} as NodeJS.ProcessEnv;

/*
 * Nothing in this file may touch the network.
 *
 * The guard is here rather than assumed because the one call that could
 * escape — naming entities — is deliberately failure-tolerant, so a leak
 * would not announce itself as an error. It would just quietly make the suite
 * depend on a service being up.
 */
const realFetch = global.fetch;
beforeAll(() => {
  global.fetch = (async (url: unknown) => {
    throw new Error(`a unit test tried to reach the network: ${String(url)}`);
  }) as unknown as typeof fetch;
});
afterAll(() => {
  global.fetch = realFetch;
});

function withEnv<T>(fn: () => T): T {
  const saved = { ...process.env };
  Object.assign(process.env, ENV);
  try {
    return fn();
  } finally {
    process.env = saved;
  }
}

/*
 * The same environment, but with hr-api configured.
 *
 * The workspace list is the one thing that must reach hr-api, so its tests
 * need the URL set while everything else keeps it empty — a test that
 * accidentally called a real service would pass or fail on what happened to
 * be running.
 */
const ENV_HR = { ...ENV, HR_API_URL: 'http://hr.test' } as NodeJS.ProcessEnv;

function withEnvHr<T>(fn: () => T): T {
  const saved = { ...process.env };
  Object.assign(process.env, ENV_HR);
  try {
    return fn();
  } finally {
    process.env = saved;
  }
}

/** Enough of Prisma to answer the questions the service actually asks. */
function prismaStub(seed: any = {}) {
  const db = {
    clients: new Map<string, any>(),
    grants: new Map<string, any>(),
    codes: new Map<string, any>(),
    refresh: new Map<string, any>(),
    userRoles: seed.userRoles ?? [],
    users: seed.users ?? new Map<number, any>(),
  };
  const table = (map: Map<string, any>, key: string) => ({
    create: async ({ data }: any) => {
      map.set(data[key], { ...data });
      return { ...data };
    },
    findUnique: async ({ where, include }: any) => {
      const row = map.get(where[key]);
      if (!row) return null;
      const out = { ...row };
      if (include?.grant) out.grant = db.grants.get(row.grantId);
      if (include?.user || include?.grant) {
        const grant = out.grant ?? out;
        if (grant?.userId != null) {
          const user = db.users.get(grant.userId);
          if (include?.user) out.user = user;
          if (out.grant) out.grant = { ...out.grant };
        }
      }
      return out;
    },
    update: async ({ where, data }: any) => {
      const row = map.get(where[key]);
      Object.assign(row, data);
      return row;
    },
    updateMany: async ({ where, data }: any) => {
      const row = map.get(where.id);
      if (row && (where.revokedAt !== null || row.revokedAt == null)) Object.assign(row, data);
      return { count: row ? 1 : 0 };
    },
  });

  return {
    db,
    oAuthClient: table(db.clients, 'id'),
    oAuthGrant: {
      ...table(db.grants, 'id'),
      findUnique: async ({ where, include }: any) => {
        const row = db.grants.get(where.id);
        if (!row) return null;
        const out = { ...row };
        if (include?.user) out.user = db.users.get(row.userId);
        return out;
      },
    },
    oAuthAuthorizationCode: table(db.codes, 'codeHash'),
    oAuthRefreshToken: table(db.refresh, 'tokenHash'),
    // The workspace list starts by reading the person, so it can refuse a
    // deactivated account before asking hr-api anything about them.
    user: {
      findUnique: async ({ where }: any) => db.users.get(where.id) ?? null,
    },
    userRole: {
      findMany: async ({ where }: any) =>
        db.userRoles.filter((r: any) => (where.userId ? r.userId === where.userId : true)),
    },
  } as unknown as AuthPrismaService & { db: typeof db };
}

function build(seed: any = {}, env: (fn: () => any) => any = withEnv) {
  const prisma = prismaStub(seed) as any;
  const jwt = new JwtService({ secret: jwtConstants.secret });
  const auth = { signIn: seed.signIn ?? (async () => ({ user: { id: 18 } })) } as unknown as AuthService;
  const service = env(() => new OAuthService(prisma, jwt, auth));
  return { service, prisma, jwt };
}

// ─── PKCE and the small crypto ──────────────────────────────────────────────

describe('PKCE', () => {
  const { createHash } = require('crypto');
  const challengeFor = (v: string) => createHash('sha256').update(v).digest('base64url');

  it('accepts the verifier that produced the challenge', () => {
    const verifier = randomToken(48);
    expect(verifyPkceS256(verifier, challengeFor(verifier))).toBe(true);
  });

  it('refuses any other verifier', () => {
    const verifier = randomToken(48);
    expect(verifyPkceS256(randomToken(48), challengeFor(verifier))).toBe(false);
  });

  it('refuses a verifier outside the length the spec allows', () => {
    expect(verifyPkceS256('short', challengeFor('short'))).toBe(false);
    expect(verifyPkceS256('x'.repeat(200), challengeFor('x'.repeat(200)))).toBe(false);
  });

  it('refuses an empty verifier against an empty challenge', () => {
    expect(verifyPkceS256('', '')).toBe(false);
  });

  it('compares without leaking length through an exception', () => {
    expect(safeEquals('abc', 'abcd')).toBe(false);
    expect(safeEquals('abc', 'abc')).toBe(true);
  });

  it('stores hashes, not secrets', () => {
    const token = randomToken();
    expect(sha256(token)).not.toContain(token);
    expect(sha256(token)).toHaveLength(64);
  });
});

// ─── Redirect URI policy ────────────────────────────────────────────────────

describe('redirect URI policy', () => {
  const config = withEnv(() => oauthConfig());

  it('accepts an https URI on an allowed host', () => {
    expect(checkRedirectUri('https://chatgpt.com/connector_platform_oauth_redirect', config).ok).toBe(true);
    expect(checkRedirectUri('https://platform.openai.com/cb', config).ok).toBe(true);
  });

  it('refuses a host outside the policy', () => {
    expect(checkRedirectUri('https://evil.example/cb', config).ok).toBe(false);
  });

  it('refuses a host that merely ends with an allowed name', () => {
    // "notchatgpt.com" must not pass because it ends with "chatgpt.com".
    expect(checkRedirectUri('https://notchatgpt.com/cb', config).ok).toBe(false);
  });

  it('refuses plain http except on loopback when that is turned on', () => {
    expect(checkRedirectUri('http://chatgpt.com/cb', config).ok).toBe(false);
    expect(checkRedirectUri('http://localhost:8765/callback', config).ok).toBe(true);
    const strict = withEnv(() =>
      oauthConfig({ ...ENV, OAUTH_ALLOW_LOOPBACK_REDIRECTS: 'false' } as NodeJS.ProcessEnv),
    );
    expect(checkRedirectUri('http://localhost:8765/callback', strict).ok).toBe(false);
  });

  it('refuses a fragment and anything that is not a URL', () => {
    expect(checkRedirectUri('https://chatgpt.com/cb#x', config).ok).toBe(false);
    expect(checkRedirectUri('not a url', config).ok).toBe(false);
  });

  /*
   * The policy governs registration. Afterwards only exact equality counts —
   * a trailing slash or a different path is a different URI.
   */
  it('matches a registered URI exactly, with no normalisation', () => {
    const registered = ['https://chatgpt.com/cb'];
    expect(matchesRegistered('https://chatgpt.com/cb', registered)).toBe(true);
    expect(matchesRegistered('https://chatgpt.com/cb/', registered)).toBe(false);
    expect(matchesRegistered('https://chatgpt.com/cb?x=1', registered)).toBe(false);
    expect(matchesRegistered('https://CHATGPT.com/cb', registered)).toBe(false);
  });
});

// ─── Discovery ──────────────────────────────────────────────────────────────

describe('discovery metadata', () => {
  it('publishes endpoints under the configured issuer, with no domain built in', () => {
    const { service } = build();
    const meta = service.authorizationServerMetadata();
    expect(meta.issuer).toBe('https://auth.example.test');
    expect(meta.authorization_endpoint).toBe('https://auth.example.test/oauth/authorize');
    expect(meta.token_endpoint).toBe('https://auth.example.test/oauth/token');
    expect(meta.registration_endpoint).toBe('https://auth.example.test/oauth/register');
  });

  it('offers S256 only, and never plain', () => {
    const { service } = build();
    expect(service.authorizationServerMetadata().code_challenge_methods_supported).toEqual(['S256']);
  });

  it('advertises the two scopes and no read/write split', () => {
    const { service } = build();
    expect(service.authorizationServerMetadata().scopes_supported).toEqual([
      'nairon:mcp',
      'offline_access',
    ]);
  });

  it('names this resource and its authorization server', () => {
    const { service } = build();
    expect(service.protectedResourceMetadata()).toMatchObject({
      resource: 'http://127.0.0.1:3010/mcp',
      authorization_servers: ['https://auth.example.test'],
    });
  });
});

// ─── Authorize request validation ───────────────────────────────────────────

describe('validating an authorize request', () => {
  const baseQuery = {
    response_type: 'code',
    client_id: 'client-1',
    redirect_uri: 'https://chatgpt.com/cb',
    scope: 'nairon:mcp offline_access',
    code_challenge: 'a'.repeat(43),
    code_challenge_method: 'S256',
  };

  async function withClient(overrides: any = {}) {
    const { service, prisma } = build();
    await prisma.oAuthClient.create({
      data: {
        id: 'client-1',
        clientName: 'ChatGPT',
        redirectUris: ['https://chatgpt.com/cb'],
        scopes: ['nairon:mcp', 'offline_access'],
        disabledAt: null,
        ...overrides,
      },
    });
    return service;
  }

  it('accepts a well-formed request', async () => {
    const service = await withClient();
    await expect(service.validateAuthorizeRequest(baseQuery)).resolves.toMatchObject({
      clientId: 'client-1',
      redirectUri: 'https://chatgpt.com/cb',
      scope: 'nairon:mcp offline_access',
    });
  });

  it('refuses an unknown or disabled client', async () => {
    const service = await withClient();
    await expect(
      service.validateAuthorizeRequest({ ...baseQuery, client_id: 'nope' }),
    ).rejects.toMatchObject({ code: 'invalid_client' });

    const disabled = await withClient({ disabledAt: new Date() });
    await expect(disabled.validateAuthorizeRequest(baseQuery)).rejects.toMatchObject({
      code: 'invalid_client',
    });
  });

  /*
   * Checked before anything else, because every later failure is reported by
   * redirecting to this URI. Validating it last would make the endpoint an
   * open redirector for malformed requests.
   */
  it('refuses a redirect_uri that was not registered', async () => {
    const service = await withClient();
    await expect(
      service.validateAuthorizeRequest({ ...baseQuery, redirect_uri: 'https://chatgpt.com/other' }),
    ).rejects.toMatchObject({ code: 'invalid_request' });
  });

  it('insists on PKCE with S256', async () => {
    const service = await withClient();
    await expect(
      service.validateAuthorizeRequest({ ...baseQuery, code_challenge_method: 'plain' }),
    ).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(
      service.validateAuthorizeRequest({ ...baseQuery, code_challenge: undefined }),
    ).rejects.toMatchObject({ code: 'invalid_request' });
  });

  it('refuses a response_type other than code', async () => {
    const service = await withClient();
    await expect(
      service.validateAuthorizeRequest({ ...baseQuery, response_type: 'token' }),
    ).rejects.toMatchObject({ code: 'unsupported_response_type' });
  });

  it('refuses a scope the server or the client does not have', async () => {
    const service = await withClient();
    await expect(
      service.validateAuthorizeRequest({ ...baseQuery, scope: 'nairon:admin' }),
    ).rejects.toMatchObject({ code: 'invalid_scope' });

    const narrow = await withClient({ scopes: ['nairon:mcp'] });
    await expect(
      narrow.validateAuthorizeRequest({ ...baseQuery, scope: 'offline_access' }),
    ).rejects.toMatchObject({ code: 'invalid_scope' });
  });

  it('refuses a resource that is not this one', async () => {
    const service = await withClient();
    await expect(
      service.validateAuthorizeRequest({ ...baseQuery, resource: 'https://elsewhere.test/mcp' }),
    ).rejects.toMatchObject({ code: 'invalid_target' });
  });
});

// ─── The sealed request ─────────────────────────────────────────────────────

describe('the request carried between the two screens', () => {
  const request = {
    clientId: 'client-1',
    redirectUri: 'https://chatgpt.com/cb',
    scope: 'nairon:mcp',
    codeChallenge: 'a'.repeat(43),
  };

  it('round-trips what was validated', () => {
    const { service } = build();
    expect(service.openRequest(service.sealRequest(request))).toMatchObject(request);
  });

  it('carries the identity only after it has been established', () => {
    const { service } = build();
    expect(service.openRequest(service.sealRequest(request)).userId).toBeUndefined();
    expect(service.openRequest(service.sealRequest({ ...request, userId: 18 })).userId).toBe(18);
  });

  /*
   * The browser holds this blob between the password screen and the workspace
   * screen. If it could be edited, the second step would accept someone else's
   * id — so it is signed, and a tampered one is simply not opened.
   */
  it('refuses a tampered blob', () => {
    const { service } = build();
    const sealed = service.sealRequest({ ...request, userId: 18 });
    const tampered = sealed.slice(0, -4) + 'AAAA';
    expect(() => service.openRequest(tampered)).toThrow(OAuthError);
  });

  it('refuses a token of the wrong type signed with the same key', () => {
    const { service, jwt } = build();
    const wrongType = jwt.sign(
      { typ: 'something_else', ...request },
      { secret: 'oauth-signing-key-for-tests' },
    );
    expect(() => service.openRequest(wrongType)).toThrow(OAuthError);
  });
});

// ─── Workspaces ─────────────────────────────────────────────────────────────

/*
 * The workspace list is Nairon's answer, not this service's.
 *
 * These stub hr-api rather than the role tables on purpose: the point of the
 * rewrite is that role assignments no longer decide this. A test that seeded
 * UserRole and expected a particular list would be asserting the old bug.
 */
describe('choosing a workspace', () => {
  function withHr(entities: { id: number; name?: string }[] | { status: number }) {
    const seen: { url: string; init: any }[] = [];
    const built = build(
      { users: new Map([[18, { id: 18, email: 'a@example.test', deactivatedAt: null }]]) },
      withEnvHr,
    );
    (global as any).fetch = async (url: string, init: any) => {
      seen.push({ url, init });
      if (!Array.isArray(entities)) {
        return { ok: false, status: entities.status, json: async () => ({}) };
      }
      return { ok: true, status: 200, json: async () => entities };
    };
    return { ...built, seen };
  }

  it('offers exactly what hr-api returns for that person', async () => {
    const { service, seen } = withHr([
      { id: 3, name: 'Սյունար' },
      { id: 7, name: 'Յազարյան Հոլդինգ' },
    ]);
    await expect(withEnvHr(() => service.workspacesFor(18))).resolves.toEqual([
      { id: 3, name: 'Սյունար' },
      { id: 7, name: 'Յազարյան Հոլդինգ' },
    ]);
    expect(seen[0].url).toMatch(/\/api\/entities$/);
  });

  it('asks as the person signing in, and names no entity', async () => {
    const { service, seen, jwt } = withHr([{ id: 3 }]);
    await withEnvHr(() => service.workspacesFor(18));

    const auth: string = seen[0].init.headers.authorization;
    expect(auth).toMatch(/^Bearer /);
    const claims: any = jwt.verify(auth.slice(7), { secret: jwtConstants.secret });
    expect(claims.id).toBe(18);
    // Nothing is selected yet — selecting one is what the screen is for.
    expect(seen[0].init.headers['x-entity-id']).toBeUndefined();
  });

  it('offers a single workspace when that is all the person has', async () => {
    const { service } = withHr([{ id: 5, name: 'Ամաս' }]);
    await expect(withEnvHr(() => service.workspacesFor(18))).resolves.toEqual([
      { id: 5, name: 'Ամաս' },
    ]);
  });

  it('offers nothing when the person belongs nowhere', async () => {
    const { service } = withHr([]);
    await expect(withEnvHr(() => service.workspacesFor(18))).resolves.toEqual([]);
  });

  /*
   * Fail closed. Guessing a list is what the previous version did, and it
   * offered workspaces the person's own switcher would not have shown.
   */
  it('offers nothing when hr-api refuses', async () => {
    const { service } = withHr({ status: 403 });
    await expect(withEnvHr(() => service.workspacesFor(18))).resolves.toEqual([]);
  });

  it('offers nothing when hr-api cannot be reached', async () => {
    const { service } = withHr([{ id: 3 }]);
    (global as any).fetch = async () => {
      throw new Error('connect ECONNREFUSED');
    };
    await expect(withEnvHr(() => service.workspacesFor(18))).resolves.toEqual([]);
  });

  it('offers nothing to a deactivated account', async () => {
    const { service } = withHr([{ id: 3 }]);
    (service as any).prisma.db.users.set(18, {
      id: 18,
      email: 'a@example.test',
      deactivatedAt: new Date(),
    });
    await expect(withEnvHr(() => service.workspacesFor(18))).resolves.toEqual([]);
  });

  it('refuses a workspace hr-api did not offer', async () => {
    const { service } = withHr([{ id: 3, name: 'Սյունար' }]);
    await expect(withEnvHr(() => service.assertWorkspaceAllowed(18, 7))).rejects.toMatchObject({
      code: 'access_denied',
      status: 403,
    });
    await expect(withEnvHr(() => service.assertWorkspaceAllowed(18, 3))).resolves.toBeUndefined();
  });

  /*
   * The entity a person picks is written onto the grant and read back at every
   * token exchange, so this is the one place it can be influenced — and it is
   * re-checked here against Nairon's own answer, not against what the form said.
   */
  it('refuses to issue a code for a workspace that was not offered', async () => {
    const { service } = withHr([{ id: 3 }]);
    await expect(
      withEnvHr(() =>
        service.issueCode(
          { clientId: 'c', redirectUri: 'https://chatgpt.com/cb', scope: 'nairon:mcp', codeChallenge: 'x' },
          18,
          7,
        ),
      ),
    ).rejects.toMatchObject({ code: 'access_denied' });
  });

  it('re-asks on every authorization, so a membership change lands at once', async () => {
    const { service, seen } = withHr([{ id: 3 }]);
    await withEnvHr(() => service.workspacesFor(18));
    await withEnvHr(() => service.workspacesFor(18));
    expect(seen.length).toBe(2);
  });
});

// ─── Token exchange ─────────────────────────────────────────────────────────

describe('exchanging an access token for an internal one', () => {
  const config = withEnv(() => oauthConfig());

  function issueAccessToken(
    jwt: JwtService,
    claims: Record<string, unknown> = {},
    options: Record<string, unknown> = {},
  ) {
    return jwt.sign(
      { typ: 'mcp_access', sub: '18', gid: 'grant-1', scope: 'nairon:mcp', ent: 7, ...claims },
      {
        secret: config.tokenSecret,
        expiresIn: 600,
        issuer: config.issuer,
        audience: config.mcpResource,
        ...options,
      },
    );
  }

  function seeded() {
    const built = build();
    built.prisma.db.users.set(18, {
      id: 18,
      email: 'a@example.test',
      firstName: 'Անդրանիկ',
      lastName: 'Ադամյան',
      deactivatedAt: null,
    });
    built.prisma.db.grants.set('grant-1', {
      id: 'grant-1',
      userId: 18,
      clientId: 'client-1',
      entityId: 7,
      scope: 'nairon:mcp',
      revokedAt: null,
    });
    return built;
  }

  it('returns a Nairon token for the person behind the grant', async () => {
    const { service, jwt } = seeded();
    const result = await withEnv(() => service.exchangeForInternalToken(issueAccessToken(jwt)));

    expect(result.subject.id).toBe(18);
    expect(result.entity_id).toBe(7);
    expect(result.expires_in).toBeLessThanOrEqual(300);
  });

  /*
   * The core separation. The token that comes out verifies with the Nairon
   * secret and carries the claims every existing guard reads; the token that
   * went in does neither. That is what lets crm-api stay untouched.
   */
  it('mints a token the Nairon services accept, and never echoes the OAuth one', async () => {
    const { service, jwt } = seeded();
    const oauthToken = issueAccessToken(jwt);
    const result = await withEnv(() => service.exchangeForInternalToken(oauthToken));

    expect(result.access_token).not.toBe(oauthToken);
    const internal: any = jwt.verify(result.access_token, { secret: jwtConstants.secret });
    expect(internal.id).toBe(18);
    expect(internal.email).toBe('a@example.test');

    // And the reverse: the OAuth token does not verify as a Nairon token.
    expect(() => jwt.verify(oauthToken, { secret: jwtConstants.secret })).toThrow();
  });

  it('refuses a token minted for a different audience', async () => {
    const { service, jwt } = seeded();
    const elsewhere = issueAccessToken(jwt, {}, { audience: 'https://elsewhere.test/mcp' });
    await expect(
      withEnv(() => service.exchangeForInternalToken(elsewhere)),
    ).rejects.toMatchObject({ code: 'invalid_token', status: 401 });
  });

  it('refuses a token from a different issuer', async () => {
    const { service, jwt } = seeded();
    const elsewhere = issueAccessToken(jwt, {}, { issuer: 'https://evil.test' });
    await expect(
      withEnv(() => service.exchangeForInternalToken(elsewhere)),
    ).rejects.toMatchObject({ status: 401 });
  });

  it('refuses an expired token, and says so', async () => {
    const { service, jwt } = seeded();
    const expired = issueAccessToken(jwt, {}, { expiresIn: -10 });
    await expect(
      withEnv(() => service.exchangeForInternalToken(expired)),
    ).rejects.toMatchObject({ code: 'expired_token', status: 401 });
  });

  it('refuses a token signed with the Nairon secret rather than the OAuth one', async () => {
    const { service, jwt } = seeded();
    const impostor = jwt.sign(
      { typ: 'mcp_access', sub: '18', gid: 'grant-1' },
      { secret: jwtConstants.secret, issuer: config.issuer, audience: config.mcpResource },
    );
    await expect(
      withEnv(() => service.exchangeForInternalToken(impostor)),
    ).rejects.toMatchObject({ code: 'invalid_token' });
  });

  it('refuses a token of the wrong type', async () => {
    const { service, jwt } = seeded();
    const wrong = issueAccessToken(jwt, { typ: 'oauth_authz_request' });
    await expect(
      withEnv(() => service.exchangeForInternalToken(wrong)),
    ).rejects.toMatchObject({ code: 'invalid_token' });
  });

  it('refuses once the grant is revoked', async () => {
    const { service, jwt, prisma } = seeded();
    const token = issueAccessToken(jwt);
    prisma.db.grants.get('grant-1').revokedAt = new Date();
    await expect(
      withEnv(() => service.exchangeForInternalToken(token)),
    ).rejects.toMatchObject({ code: 'invalid_token', status: 401 });
  });

  it('refuses when the token names a different person than its grant', async () => {
    const { service, jwt } = seeded();
    const mismatched = issueAccessToken(jwt, { sub: '20' });
    await expect(
      withEnv(() => service.exchangeForInternalToken(mismatched)),
    ).rejects.toMatchObject({ code: 'invalid_token' });
  });

  it('refuses a deactivated account even with a valid token', async () => {
    const { service, jwt, prisma } = seeded();
    const token = issueAccessToken(jwt);
    prisma.db.users.get(18).deactivatedAt = new Date();
    await expect(
      withEnv(() => service.exchangeForInternalToken(token)),
    ).rejects.toMatchObject({ code: 'invalid_token' });
  });

  /*
   * The entity is not read from the token even though the token carries one:
   * the grant is the record of what the person agreed to, and the claim is
   * there for traceability.
   */
  it('takes the entity from the grant, not from the token claim', async () => {
    const { service, jwt, prisma } = seeded();
    const lying = issueAccessToken(jwt, { ent: 3 });
    prisma.db.grants.get('grant-1').entityId = 7;
    const result = await withEnv(() => service.exchangeForInternalToken(lying));
    expect(result.entity_id).toBe(7);
  });
});
