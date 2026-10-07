import { Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { AuthService } from '../../auth/auth.service';
import { AuthPrismaService } from '../../prisma.service';
import { HubNotifier } from '../../shared/hub-notifier';
import { sha256 } from '../oauth.crypto';
import { OAuthService } from '../oauth.service';

/*
 * Notifications phase 3 (2026-10-07): system.app_access_granted on consent to
 * a new client, system.app_access_revoked when the server cuts a grant off
 * (code replay, refresh-token reuse), both through hr-api's hub — and the hub
 * call never decides the outcome of the OAuth request.
 */

process.env.JWT_SECRET ||= 'nairon-jwt-secret-for-unit-tests';

const ENV = {
  OAUTH_ISSUER_URL: 'https://auth.example.test',
  OAUTH_PUBLIC_BASE_URL: 'https://auth.example.test',
  MCP_RESOURCE_URL: 'http://127.0.0.1:3010/mcp',
  OAUTH_TOKEN_SECRET: 'oauth-signing-key-for-tests',
  HR_API_URL: '',
  HR_INTERNAL_SECRET: '',
} as NodeJS.ProcessEnv;

function withEnv<T>(fn: () => T): T {
  const saved = { ...process.env };
  Object.assign(process.env, ENV);
  try {
    return fn();
  } finally {
    process.env = saved;
  }
}

const flush = async () => {
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
};

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
  jest.restoreAllMocks();
});

function prismaStub() {
  const db = {
    clients: new Map<string, any>([['client-1', { id: 'client-1', clientName: 'ChatGPT' }], ['client-2', { id: 'client-2', clientName: 'Claude' }]]),
    grants: new Map<string, any>(),
    codes: new Map<string, any>(),
    refresh: new Map<string, any>(),
    users: new Map<number, any>([[18, { id: 18, email: 'a@example.test', deactivatedAt: null }]]),
  };
  const prisma: any = {
    db,
    oAuthClient: {
      findUnique: async ({ where }: any) => db.clients.get(where.id) ?? null,
    },
    oAuthGrant: {
      create: async ({ data }: any) => {
        const row = { revokedAt: null, ...data };
        db.grants.set(data.id, row);
        return { ...row };
      },
      findFirst: async ({ where }: any) =>
        [...db.grants.values()].find(
          (g) => g.userId === where.userId && g.clientId === where.clientId && g.revokedAt == null,
        ) ?? null,
      findUnique: async ({ where, include }: any) => {
        const row = db.grants.get(where.id);
        if (!row) return null;
        return include?.user ? { ...row, user: db.users.get(row.userId) } : { ...row };
      },
      update: async ({ where, data }: any) => Object.assign(db.grants.get(where.id), data),
      updateMany: async ({ where, data }: any) => {
        const row = db.grants.get(where.id);
        if (!row || row.revokedAt != null) return { count: 0 };
        Object.assign(row, data);
        return { count: 1 };
      },
    },
    oAuthAuthorizationCode: {
      create: async ({ data }: any) => db.codes.set(data.codeHash, { ...data }),
      findUnique: async ({ where }: any) => {
        const row = db.codes.get(where.codeHash);
        return row ? { ...row, grant: { ...db.grants.get(row.grantId) } } : null;
      },
      update: async ({ where, data }: any) => Object.assign(db.codes.get(where.codeHash), data),
    },
    oAuthRefreshToken: {
      create: async ({ data }: any) => db.refresh.set(data.tokenHash, { ...data }),
      findUnique: async ({ where }: any) => {
        const row = db.refresh.get(where.tokenHash);
        return row ? { ...row, grant: { ...db.grants.get(row.grantId) } } : null;
      },
      update: async ({ where, data }: any) => Object.assign(db.refresh.get(where.tokenHash), data),
    },
  };
  return prisma as AuthPrismaService & { db: typeof db };
}

function build(notify: jest.Mock = jest.fn().mockResolvedValue(true)) {
  const prisma = prismaStub() as any;
  const jwt = new JwtService({ secret: 'x' });
  const service = withEnv(() => new OAuthService(prisma, jwt, {} as AuthService));
  service.notifier = { notify } as unknown as HubNotifier;
  jest.spyOn(service, 'assertWorkspaceAllowed').mockResolvedValue(undefined);
  return { service, prisma, notify };
}

const request = (clientId = 'client-1') => ({
  clientId,
  redirectUri: 'https://chatgpt.com/cb',
  scope: 'nairon:mcp offline_access',
  codeChallenge: 'x'.repeat(43),
});

describe('app_access_granted', () => {
  it('tells the person once per new client, not on every code', async () => {
    const { service, notify } = build();
    await service.issueCode(request(), 18, 3);
    await service.issueCode(request(), 18, 3);
    await service.issueCode(request(), 18, 4);
    await flush();

    expect(notify).toHaveBeenCalledTimes(1);
    const notice = notify.mock.calls[0][0];
    expect(notice).toMatchObject({ userId: 18, type: 'system.app_access_granted', url: '/profile' });
    expect(notice.body).toContain('«ChatGPT»');
    expect(notice.email.subject).toContain('ChatGPT');
    expect(notice.email.details).toEqual(expect.arrayContaining([{ label: 'Հավելված', value: 'ChatGPT' }]));
  });

  it('tells again for another client, and after every grant for the client was revoked', async () => {
    const { service, prisma, notify } = build();
    await service.issueCode(request('client-1'), 18, 3);
    await service.issueCode(request('client-2'), 18, 3);
    for (const g of prisma.db.grants.values()) g.revokedAt = new Date();
    await service.issueCode(request('client-1'), 18, 3);
    await flush();

    expect(notify).toHaveBeenCalledTimes(3);
    expect(notify.mock.calls[1][0].body).toContain('«Claude»');
  });

  it('issues the code even when the hub call fails', async () => {
    const { service } = build(jest.fn().mockRejectedValue(new Error('hr-api down')));
    await expect(service.issueCode(request(), 18, 3)).resolves.toHaveProperty('code');
    await flush();
  });
});

describe('app_access_revoked', () => {
  async function codeFor(service: OAuthService, prisma: any) {
    const { code } = await service.issueCode(request(), 18, 3);
    prisma.db.codes.get(sha256(code)).consumedAt = new Date();
    return code;
  }
  const exchangeBody = (code: string) => ({
    code,
    client_id: 'client-1',
    redirect_uri: 'https://chatgpt.com/cb',
    code_verifier: 'v'.repeat(43),
  });

  it('tells the person when a replayed code kills the grant — once', async () => {
    const { service, prisma, notify } = build();
    const code = await codeFor(service, prisma);
    await flush();
    notify.mockClear();

    await expect(service.exchangeCode(exchangeBody(code))).rejects.toMatchObject({ code: 'invalid_grant' });
    await expect(service.exchangeCode(exchangeBody(code))).rejects.toMatchObject({ code: 'invalid_grant' });
    await flush();

    expect(notify).toHaveBeenCalledTimes(1);
    const notice = notify.mock.calls[0][0];
    expect(notice).toMatchObject({ userId: 18, type: 'system.app_access_revoked', url: '/profile' });
    expect(notice.body).toContain('«ChatGPT»');
    expect(notice.body).toContain('մուտքի կոդը կրկին օգտագործվեց');
  });

  it('tells the person when a reused refresh token kills the grant', async () => {
    const { service, prisma, notify } = build();
    await service.issueCode(request(), 18, 3);
    await flush();
    notify.mockClear();
    const grantId = [...prisma.db.grants.keys()][0];
    prisma.db.refresh.set(sha256('rt'), { tokenHash: sha256('rt'), grantId, usedAt: new Date(), expiresAt: new Date(Date.now() + 1e6) });

    await expect(service.refresh({ refresh_token: 'rt', client_id: 'client-1' })).rejects.toMatchObject({ code: 'invalid_grant' });
    await flush();

    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify.mock.calls[0][0].type).toBe('system.app_access_revoked');
    expect(notify.mock.calls[0][0].body).toContain('թարմացման թոքենը կրկին օգտագործվեց');
  });

  it('stays silent on a revoke the client asked for (RFC 7009)', async () => {
    const { service, prisma, notify } = build();
    await service.issueCode(request(), 18, 3);
    await flush();
    notify.mockClear();
    const grantId = [...prisma.db.grants.keys()][0];
    prisma.db.refresh.set(sha256('rt'), { tokenHash: sha256('rt'), grantId, expiresAt: new Date(Date.now() + 1e6) });

    await service.revokeByToken('rt');
    await flush();
    expect(prisma.db.grants.get(grantId).revokedAt).toBeInstanceOf(Date);
    expect(notify).not.toHaveBeenCalled();
  });

  it('still refuses the replay when the hub call fails', async () => {
    const { service, prisma } = build(jest.fn().mockRejectedValue(new Error('hr-api down')));
    const code = await codeFor(service, prisma);
    await expect(service.exchangeCode(exchangeBody(code))).rejects.toMatchObject({ code: 'invalid_grant' });
    await flush();
  });
});

describe('HubNotifier', () => {
  const notice = { userId: 18, type: 'system.app_access_granted', title: 't', body: 'b', url: '/profile' };
  const env = { HR_API_URL: 'http://hr.test/', INTERNAL_SECRET: 'top-secret' } as NodeJS.ProcessEnv;

  it('posts the notice to the hub with the internal secret', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 201 });
    global.fetch = fetchMock as any;
    await expect(new HubNotifier(env).notify(notice)).resolves.toBe(true);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('http://hr.test/api/notifications/internal');
    expect(init.method).toBe('POST');
    expect(init.headers['x-internal-secret']).toBe('top-secret');
    expect(JSON.parse(init.body)).toEqual(notice);
  });

  it('never throws when hr-api is down, and never logs the secret', async () => {
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    global.fetch = jest.fn().mockRejectedValue(new Error('connect ECONNREFUSED top-secret')) as any;
    await expect(new HubNotifier(env).notify(notice)).resolves.toBe(false);

    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 500 }) as any;
    await expect(new HubNotifier(env).notify(notice)).resolves.toBe(false);

    expect(warn).toHaveBeenCalled();
    for (const [line] of warn.mock.calls) expect(String(line)).not.toContain('top-secret');
  });

  it('does not call out at all when unconfigured', async () => {
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const fetchMock = jest.fn();
    global.fetch = fetchMock as any;
    await expect(new HubNotifier({ HR_API_URL: 'http://hr.test' } as any).notify(notice)).resolves.toBe(false);
    await expect(new HubNotifier({ INTERNAL_SECRET: 's' } as any).notify(notice)).resolves.toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
