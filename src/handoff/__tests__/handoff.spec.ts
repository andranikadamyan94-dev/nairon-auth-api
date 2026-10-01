/*
 * Synthetic key, set before anything reads it. Never a real credential, and
 * never read from the environment.
 */
const TEST_JWT_SECRET = 'synthetic-jwt-key-for-handoff-tests';
process.env.JWT_SECRET = TEST_JWT_SECRET;

import { INestApplication, Module } from '@nestjs/common';
import { APP_GUARD, NestFactory } from '@nestjs/core';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { AddressInfo } from 'net';

import { AuthService } from '../../auth/auth.service';
import { AuthGuard } from '../../auth/guards/auth.guard';
import { sha256 } from '../../oauth/oauth.crypto';
import { AuthPrismaService } from '../../prisma.service';
import { armenianValidationPipe } from '../../shared/validation-messages';
import {
  handoffTargets,
  handoffTtlSec,
  isSessionPayload,
  normalizeTargetOrigin,
} from '../handoff.contract';
import { HandoffCodesEnabledGuard, HandoffController } from '../handoff.controller';
import { HandoffService } from '../handoff.service';

/*
 * The handoff code, over real HTTP against the real controller, guards and
 * service. Prisma is an in-memory stub; nothing leaves this process.
 */

// ─── Stubs ──────────────────────────────────────────────────────────────────

interface Row {
  codeHash: string;
  userId: number;
  targetOrigin: string;
  expiresAt: Date;
  consumedAt: Date | null;
  createdAt: Date;
}

const db = {
  users: new Map<number, { id: number; email: string; password: string; deactivatedAt: Date | null; roles: unknown[] }>(),
  codes: new Map<string, Row>(),
};

function matches(row: Row, where: any): boolean {
  if (where.codeHash !== undefined && row.codeHash !== where.codeHash) return false;
  if (where.consumedAt === null && row.consumedAt !== null) return false;
  if (where.expiresAt?.gt && !(row.expiresAt.getTime() > where.expiresAt.gt.getTime())) return false;
  if (where.expiresAt?.lt && !(row.expiresAt.getTime() < where.expiresAt.lt.getTime())) return false;
  return true;
}

const prismaStub = {
  user: {
    findUnique: async ({ where }: any) => {
      const u = db.users.get(where.id);
      return u ? { ...u } : null;
    },
  },
  authHandoffCode: {
    create: async ({ data }: any) => {
      const row: Row = { consumedAt: null, createdAt: new Date(), ...data };
      db.codes.set(row.codeHash, row);
      return { ...row };
    },
    findUnique: async ({ where }: any) => {
      const row = db.codes.get(where.codeHash);
      return row ? { ...row } : null;
    },
    // Synchronous inside, like a single UPDATE statement: no interleaving.
    updateMany: async ({ where, data }: any) => {
      let count = 0;
      for (const row of db.codes.values()) {
        if (matches(row, where)) {
          Object.assign(row, data);
          count++;
        }
      }
      return { count };
    },
    deleteMany: async ({ where }: any) => {
      let count = 0;
      for (const [k, row] of db.codes) {
        if (matches(row, where)) {
          db.codes.delete(k);
          count++;
        }
      }
      return { count };
    },
  },
};

// ─── App under test ─────────────────────────────────────────────────────────

@Module({
  imports: [JwtModule.register({ global: true, secret: TEST_JWT_SECRET, signOptions: { expiresIn: '30d' } })],
  controllers: [HandoffController],
  providers: [
    AuthService,
    HandoffService,
    HandoffCodesEnabledGuard,
    { provide: AuthPrismaService, useValue: prismaStub },
    // The app-wide session guard, as in production.
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
})
class TestModule {}

let app: INestApplication;
let base: string;
let jwt: JwtService;
const savedEnv = { ...process.env };

const CRM = 'https://crm.nairon.am';
const HR = 'https://nairon.am';

beforeAll(async () => {
  app = await NestFactory.create(TestModule, { logger: false });
  app.setGlobalPrefix('api');
  app.useGlobalPipes(armenianValidationPipe({ transformOptions: { enableImplicitConversion: true } }));
  await app.listen(0, '127.0.0.1');
  const { port } = app.getHttpServer().address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
  jwt = app.get(JwtService);
});

afterAll(async () => {
  await app?.close();
  process.env = savedEnv;
});

beforeEach(() => {
  process.env.JWT_SECRET = TEST_JWT_SECRET;
  process.env.AUTH_HANDOFF_CODES_ENABLED = 'true';
  delete process.env.AUTH_HANDOFF_CODE_TTL_SEC;
  delete process.env.FRONTEND_URL;
  db.users.clear();
  db.codes.clear();
  db.users.set(18, { id: 18, email: 'owner@example.test', password: 'bcrypt-hash', deactivatedAt: null, roles: [] });
});

const sessionToken = (claims: Record<string, unknown> = { id: 18, email: 'owner@example.test' }) =>
  jwt.sign(claims, { secret: TEST_JWT_SECRET, expiresIn: '30d' });

async function call(path: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${base}/api/auth/handoff${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : undefined };
}

const issue = (target: string, token = sessionToken()) =>
  call('', { target }, { authorization: `Bearer ${token}`, origin: HR });
const exchange = (code: string, origin?: string) =>
  call('/exchange', { code }, origin ? { origin } : {});

// ─── Flag ───────────────────────────────────────────────────────────────────

describe('flag', () => {
  it('answers 404 on both routes while AUTH_HANDOFF_CODES_ENABLED is unset', async () => {
    delete process.env.AUTH_HANDOFF_CODES_ENABLED;
    expect((await issue(CRM)).status).toBe(404);
    expect((await exchange('x'.repeat(43), CRM)).status).toBe(404);
    expect(db.codes.size).toBe(0);
  });

  it('treats anything but the exact string "true" as off', async () => {
    process.env.AUTH_HANDOFF_CODES_ENABLED = '1';
    expect((await issue(CRM)).status).toBe(404);
  });
});

// ─── Issue ──────────────────────────────────────────────────────────────────

describe('issue', () => {
  it('needs a session token', async () => {
    const res = await call('', { target: CRM }, { origin: HR });
    expect(res.status).toBe(401);
  });

  it('returns a 43-character code and keeps only its hash', async () => {
    const res = await issue(CRM);
    expect(res.status).toBe(200);
    expect(res.body.code).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(res.body.expiresIn).toBe(60);
    expect(db.codes.has(res.body.code)).toBe(false);
    const row = db.codes.get(sha256(res.body.code))!;
    expect(row).toMatchObject({ userId: 18, targetOrigin: CRM, consumedAt: null });
    expect(row.expiresAt.getTime() - Date.now()).toBeLessThanOrEqual(60_000);
    expect(row.expiresAt.getTime() - Date.now()).toBeGreaterThan(50_000);
  });

  it('accepts the origin with a trailing slash and stores it without', async () => {
    const res = await issue(`${CRM}/`);
    expect(res.status).toBe(200);
    expect(db.codes.get(sha256(res.body.code))!.targetOrigin).toBe(CRM);
  });

  it.each([
    'https://evil.example',
    'https://crm.nairon.am.evil.example',
    'http://crm.nairon.am',
    'https://crm.nairon.am/home',
    'https://crm.nairon.am/?x=1',
    'https://user:pw@crm.nairon.am',
    'https://gateway.nairon.am',
    'javascript:alert(1)',
    '',
  ])('refuses the target %p', async (target) => {
    const res = await issue(target);
    expect(res.status).toBe(400);
    expect(db.codes.size).toBe(0);
  });

  it.each([
    ['a delegated AI token', { id: 18, email: 'owner@example.test', act: { sub: 'ai' }, scope: 'read' }],
    ['the MCP OAuth bridge token', { id: 18, email: 'owner@example.test', src: 'mcp-oauth' }],
    ['a token with no id', { email: 'owner@example.test' }],
  ])('refuses %s — only a plain sign-in token becomes a code', async (_label, claims) => {
    const res = await issue(CRM, sessionToken(claims));
    expect(res.status).toBe(403);
    expect(db.codes.size).toBe(0);
  });

  it('refuses a deactivated account', async () => {
    db.users.get(18)!.deactivatedAt = new Date();
    expect((await issue(CRM)).status).toBe(401);
  });

  it('honours AUTH_HANDOFF_CODE_TTL_SEC within 10–60 s', async () => {
    process.env.AUTH_HANDOFF_CODE_TTL_SEC = '30';
    expect((await issue(CRM)).body.expiresIn).toBe(30);
  });

  it('prunes long-expired rows as it issues', async () => {
    db.codes.set('old', {
      codeHash: 'old', userId: 18, targetOrigin: CRM, consumedAt: null, createdAt: new Date(0),
      expiresAt: new Date(Date.now() - 60 * 60 * 1000),
    });
    await issue(CRM);
    await new Promise((r) => setTimeout(r, 10));
    expect(db.codes.has('old')).toBe(false);
  });
});

// ─── Exchange ───────────────────────────────────────────────────────────────

describe('exchange', () => {
  it('trades the code for a session and the shared cookie, from the bound origin', async () => {
    const { code } = (await issue(CRM)).body;
    const res = await exchange(code, CRM);
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ id: 18, email: 'owner@example.test' });
    expect(res.body.user.password).toBeUndefined();
    const claims = jwt.verify(res.body.access_token, { secret: TEST_JWT_SECRET });
    expect(Object.keys(claims).sort()).toEqual(['email', 'exp', 'iat', 'id']);
    expect(claims.id).toBe(18);
    const cookie = res.headers.get('set-cookie') ?? '';
    expect(cookie).toMatch(/nairon_session=/);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Strict/i);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(db.codes.get(sha256(code))!.consumedAt).not.toBeNull();
  });

  it('works once only', async () => {
    const { code } = (await issue(CRM)).body;
    expect((await exchange(code, CRM)).status).toBe(200);
    const again = await exchange(code, CRM);
    expect(again.status).toBe(401);
    expect(again.body.access_token).toBeUndefined();
  });

  it('lets exactly one of several simultaneous exchanges through', async () => {
    const { code } = (await issue(CRM)).body;
    const results = await Promise.all([1, 2, 3, 4, 5].map(() => exchange(code, CRM)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 401)).toHaveLength(4);
  });

  it('refuses another origin and burns the code', async () => {
    const { code } = (await issue(CRM)).body;
    expect((await exchange(code, 'https://finance.nairon.am')).status).toBe(401);
    expect((await exchange(code, CRM)).status).toBe(401);
  });

  it('refuses a request with no Origin', async () => {
    const { code } = (await issue(CRM)).body;
    expect((await exchange(code)).status).toBe(401);
    // Not burnt: a missing header is not evidence of a leak.
    expect((await exchange(code, CRM)).status).toBe(200);
  });

  it('refuses an expired code', async () => {
    const { code } = (await issue(CRM)).body;
    db.codes.get(sha256(code))!.expiresAt = new Date(Date.now() - 1);
    expect((await exchange(code, CRM)).status).toBe(401);
  });

  it('refuses an unknown or malformed code with the same answer', async () => {
    const unknown = await exchange('A'.repeat(43), CRM);
    const malformed = await exchange('not a code', CRM);
    expect(unknown.status).toBe(401);
    expect(malformed.status).toBe(401);
    expect(unknown.body.message).toBe(malformed.body.message);
  });

  it('refuses a person deactivated between issue and exchange', async () => {
    const { code } = (await issue(CRM)).body;
    db.users.get(18)!.deactivatedAt = new Date();
    expect((await exchange(code, CRM)).status).toBe(401);
  });

  it('rejects extra body fields (the global whitelist pipe)', async () => {
    const { code } = (await issue(CRM)).body;
    const res = await call('/exchange', { code, userId: 1 }, { origin: CRM });
    expect(res.status).toBe(400);
  });
});

// ─── Contract ───────────────────────────────────────────────────────────────

describe('contract', () => {
  it('clamps the TTL to 10–60 s and defaults to 60', () => {
    expect(handoffTtlSec({})).toBe(60);
    expect(handoffTtlSec({ AUTH_HANDOFF_CODE_TTL_SEC: 'abc' })).toBe(60);
    expect(handoffTtlSec({ AUTH_HANDOFF_CODE_TTL_SEC: '1' })).toBe(10);
    expect(handoffTtlSec({ AUTH_HANDOFF_CODE_TTL_SEC: '3600' })).toBe(60);
    expect(handoffTtlSec({ AUTH_HANDOFF_CODE_TTL_SEC: '45' })).toBe(45);
  });

  it('targets the apps, never a gateway, and follows FRONTEND_URL', () => {
    const targets = handoffTargets({ FRONTEND_URL: 'https://staging-marketing.nairon.am, https://staging-gateway.nairon.am' });
    expect(targets.has('https://crm.nairon.am')).toBe(true);
    expect(targets.has('https://staging-marketing.nairon.am')).toBe(true);
    expect(targets.has('https://gateway.nairon.am')).toBe(false);
    expect(targets.has('https://staging-gateway.nairon.am')).toBe(false);
    expect(normalizeTargetOrigin('http://localhost:3004', {})).toBe('http://localhost:3004');
    expect(normalizeTargetOrigin(42, {})).toBeNull();
  });

  it('knows a sign-in token from the other tokens the estate signs', () => {
    expect(isSessionPayload({ id: 1, email: 'a@b', iat: 1, exp: 2 })).toBe(true);
    expect(isSessionPayload({ id: 1, email: 'a@b', jti: 'x' })).toBe(false);
    expect(isSessionPayload({ id: '1', email: 'a@b' })).toBe(false);
    expect(isSessionPayload({ id: 0 })).toBe(false);
    expect(isSessionPayload(null)).toBe(false);
  });
});
