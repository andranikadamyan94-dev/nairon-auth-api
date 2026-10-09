/*
 * Synthetic keys, set before anything reads them. Never real credentials, and
 * never read from the environment.
 */
const TEST_JWT_SECRET = 'synthetic-jwt-key-for-ensure-permissions-tests';
const TEST_INTERNAL_SECRET = 'synthetic-internal-secret-for-ensure-permissions-tests';
process.env.JWT_SECRET = TEST_JWT_SECRET;

import { INestApplication, Module } from '@nestjs/common';
import { APP_GUARD, NestFactory } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { AddressInfo } from 'net';

import { AuthGuard } from '../../auth/guards/auth.guard';
import { DirectCallOnlyGuard, PROXY_HEADERS, cameThroughProxy } from '../../auth/guards/direct-call.guard';
import { assertInternalSecret } from '../../auth/guards/internal.guard';
import { AuthPrismaService } from '../../prisma.service';
import { armenianValidationPipe } from '../../shared/validation-messages';
import {
  MAX_ENSURE_NAMES,
  SKILL_PERMISSION_NAME,
  parseEnsurePermissionsRequest,
} from '../ensure-permissions.contract';
import { EnsurePermissionsController } from '../ensure-permissions.controller';
import { EnsurePermissionsService } from '../ensure-permissions.service';
import { PermissionsModule } from '../permissions.module';

/*
 * POST /api/internal/permissions/ensure, over real HTTP against the real
 * controller, guards, global pipe and service. Prisma is a stub holding an
 * in-memory "Permission" table that answers the one statement the service may
 * send; "RolePermission" is a stub that records any write. Nothing leaves this
 * process.
 */

// ─── Stub database ──────────────────────────────────────────────────────────

/** The one statement the route may run, whitespace-normalised, `?` per bound value. */
const ENSURE_SQL =
  'INSERT INTO "Permission" ("name") SELECT unnest(?::text[]) ON CONFLICT ("name") DO NOTHING RETURNING "name"';

const db = {
  permission: new Map<string, number>(),
  nextId: 1,
  statements: [] as { sql: string; values: unknown[] }[],
};

const rolePermissionWrites = {
  create: jest.fn(),
  createMany: jest.fn(),
  upsert: jest.fn(),
  update: jest.fn(),
  updateMany: jest.fn(),
  delete: jest.fn(),
  deleteMany: jest.fn(),
};
const otherRawCalls = {
  $executeRaw: jest.fn(),
  $executeRawUnsafe: jest.fn(),
  $queryRawUnsafe: jest.fn(),
  $transaction: jest.fn(),
};

const prismaStub = {
  $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?').replace(/\s+/g, ' ').trim();
    db.statements.push({ sql, values });
    if (sql !== ENSURE_SQL) throw new Error(`unexpected SQL: ${sql}`);
    // INSERT … ON CONFLICT ("name") DO NOTHING RETURNING "name", row by row.
    const inserted: { name: string }[] = [];
    for (const name of values[0] as string[]) {
      if (db.permission.has(name)) continue;
      db.permission.set(name, db.nextId++);
      inserted.push({ name });
    }
    return inserted;
  },
  rolePermission: rolePermissionWrites,
  ...otherRawCalls,
};

function seed(...names: string[]) {
  for (const name of names) db.permission.set(name, db.nextId++);
}

/** No "RolePermission" write of any kind, by model call or by SQL. */
function expectNoGrant() {
  for (const fn of Object.values(rolePermissionWrites)) expect(fn).not.toHaveBeenCalled();
  for (const fn of Object.values(otherRawCalls)) expect(fn).not.toHaveBeenCalled();
  for (const { sql } of db.statements) expect(sql).not.toMatch(/RolePermission/i);
}

// ─── App under test ─────────────────────────────────────────────────────────

@Module({
  imports: [JwtModule.register({ global: true, secret: TEST_JWT_SECRET, signOptions: { expiresIn: '30d' } })],
  controllers: [EnsurePermissionsController],
  providers: [
    EnsurePermissionsService,
    { provide: AuthPrismaService, useValue: prismaStub },
    // The app-wide session guard, as in production: the route must pass it via @Public().
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
})
class TestModule {}

let app: INestApplication;
let base: string;
const savedEnv = { ...process.env };

beforeAll(async () => {
  app = await NestFactory.create(TestModule, { logger: false });
  app.setGlobalPrefix('api');
  // The same global pipe main.ts installs, so the body reaches the route as production delivers it.
  app.useGlobalPipes(armenianValidationPipe({ transformOptions: { enableImplicitConversion: true } }));
  await app.listen(0, '127.0.0.1');
  const { port } = app.getHttpServer().address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await app?.close();
  process.env = savedEnv;
});

beforeEach(() => {
  process.env.JWT_SECRET = TEST_JWT_SECRET;
  process.env.INTERNAL_SECRET = TEST_INTERNAL_SECRET;
  db.permission.clear();
  db.nextId = 1;
  db.statements.length = 0;
  for (const fn of [...Object.values(rolePermissionWrites), ...Object.values(otherRawCalls)]) fn.mockReset();
  // Rows that exist on every real database: a skill call must never touch them.
  seed('use_ai_assistant', 'ai_write_actions', 'assign_permissions');
});

const SECRET = { 'x-internal-secret': TEST_INTERNAL_SECRET };
const PATH = '/api/internal/permissions/ensure';

async function ensure(body: unknown, headers: Record<string, string> = SECRET, path = PATH) {
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined };
}

/** Nothing was written: not a statement, not a row, not a grant. */
function expectNothingWritten(before: Map<string, number>) {
  expect(db.statements).toHaveLength(0);
  expect([...db.permission.entries()]).toEqual([...before.entries()]);
  expectNoGrant();
}

const snapshot = () => new Map(db.permission);
const GOOD = { names: ['use_ai_skills', 'ai_skill_report_writer'] };

// ─── Authentication ─────────────────────────────────────────────────────────

describe('the secret', () => {
  it('no x-internal-secret header → 401, nothing written', async () => {
    const before = snapshot();
    const r = await ensure(GOOD, {});
    expect(r.status).toBe(401);
    expect(r.body?.created).toBeUndefined();
    expectNothingWritten(before);
  });

  it.each([
    ['a wrong secret', 'not-the-secret'],
    ['blank', ''],
    ['a prefix of the secret', TEST_INTERNAL_SECRET.slice(0, -1)],
    ['the secret with a byte appended', `${TEST_INTERNAL_SECRET}x`],
    ['the secret in another case', TEST_INTERNAL_SECRET.toUpperCase()],
  ])('x-internal-secret: %s → 401, nothing written', async (_label, secret) => {
    const before = snapshot();
    const r = await ensure(GOOD, { 'x-internal-secret': secret });
    expect(r.status).toBe(401);
    expectNothingWritten(before);
  });

  it('INTERNAL_SECRET unset on this service → 401 for everyone, nothing written', async () => {
    delete process.env.INTERNAL_SECRET;
    const before = snapshot();
    expect((await ensure(GOOD)).status).toBe(401);
    expect((await ensure(GOOD, { 'x-internal-secret': '' })).status).toBe(401);
    expect((await ensure(GOOD, { 'x-internal-secret': 'undefined' })).status).toBe(401);
    expectNothingWritten(before);
  });

  it('a session token is not a substitute for the secret', async () => {
    const { JwtService } = await import('@nestjs/jwt');
    const token = new JwtService({ secret: TEST_JWT_SECRET }).sign({ id: 1, email: 'admin@example.test' });
    const before = snapshot();
    const r = await ensure(GOOD, { authorization: `Bearer ${token}` });
    expect(r.status).toBe(401);
    expectNothingWritten(before);
  });

  it('the shared rule compares in constant time but keeps its truth table', () => {
    const saved = process.env.INTERNAL_SECRET;
    process.env.INTERNAL_SECRET = 'abc';
    try {
      expect(() => assertInternalSecret('abc')).not.toThrow();
      for (const wrong of ['ab', 'abcd', 'abd', 'ABC', '', ' abc']) expect(() => assertInternalSecret(wrong)).toThrow();
    } finally {
      process.env.INTERNAL_SECRET = saved;
    }
  });
});

// ─── Not through the public gateway ─────────────────────────────────────────

describe('public paths', () => {
  it.each(PROXY_HEADERS.map((h) => [h]))('a request carrying %s → 403 even with the right secret, nothing written', async (header) => {
    const before = snapshot();
    const r = await ensure(GOOD, { ...SECRET, [header]: '203.0.113.7' });
    expect(r.status).toBe(403);
    expectNothingWritten(before);
  });

  it('the proxy check comes first: a forwarded request never learns whether its secret was right', async () => {
    const forwarded = { 'x-forwarded-for': '203.0.113.7' };
    const right = await ensure(GOOD, { ...SECRET, ...forwarded });
    const wrong = await ensure(GOOD, { 'x-internal-secret': 'guess', ...forwarded });
    const none = await ensure(GOOD, forwarded);
    expect([right.status, wrong.status, none.status]).toEqual([403, 403, 403]);
    expect(right.body).toEqual(wrong.body);
    expect(right.body).toEqual(none.body);
  });

  it('what the gateway makes of /api-auth/api/internal/permissions/ensure does not exist', async () => {
    // api-gateway proxy.factory.ts: /api-auth is stripped, then anything not
    // under /auth, /oauth/* or /.well-known/ gets /api/auth prepended.
    const gatewayRewrite = (p: string) => (p.startsWith('/auth') ? p.replace('/auth', '/api/auth') : `/api/auth${p}`);
    const upstream = gatewayRewrite('/api/internal/permissions/ensure');
    expect(upstream).toBe('/api/auth/api/internal/permissions/ensure');
    const before = snapshot();
    const r = await ensure(GOOD, SECRET, upstream);
    expect(r.status).toBe(404);
    expectNothingWritten(before);
  });

  it('only POST: GET is an unknown route', async () => {
    const res = await fetch(`${base}${PATH}`, { headers: SECRET });
    expect(res.status).toBe(404);
    expect(db.statements).toHaveLength(0);
  });

  it('presence is the rule, values are never trusted', () => {
    expect(cameThroughProxy({ 'x-forwarded-for': '127.0.0.1' })).toBe(true);
    expect(cameThroughProxy({ 'x-real-ip': '' })).toBe(true);
    expect(cameThroughProxy({ 'content-type': 'application/json', 'x-internal-secret': 's' })).toBe(false);
    expect(cameThroughProxy(undefined)).toBe(false);
    const guard = new DirectCallOnlyGuard();
    const ctx = (headers: Record<string, string>) => ({ switchToHttp: () => ({ getRequest: () => ({ headers }) }) }) as never;
    expect(guard.canActivate(ctx({}))).toBe(true);
    expect(() => guard.canActivate(ctx({ forwarded: 'for=192.0.2.60' }))).toThrow();
  });
});

// ─── The body ───────────────────────────────────────────────────────────────

describe('names', () => {
  it('is the pattern ai-api sends, literally', () => {
    expect(SKILL_PERMISSION_NAME.source).toBe('^(use_ai_skills|ai_skill_[a-z0-9_]{2,48})$');
    expect(MAX_ENSURE_NAMES).toBe(101);
  });

  it.each([
    ['an existing non-skill right', 'use_ai_assistant'],
    ['the AI write right', 'ai_write_actions'],
    ['a role-admin right', 'assign_permissions'],
    ['a hyphenated slug', 'ai_skill_report-writer'],
    ['upper case', 'ai_skill_Report'],
    ['a one-character slug', 'ai_skill_x'],
    ['a 49-character slug', `ai_skill_${'a'.repeat(49)}`],
    ['the bare prefix', 'ai_skill_'],
    ['leading space', ' use_ai_skills'],
    ['trailing newline', 'use_ai_skills\n'],
    ['SQL', "ai_skill_x'); DELETE FROM \"Permission\"; --"],
    ['a number', 7],
    ['null', null],
    ['an object', { name: 'ai_skill_ok' }],
  ])('one bad name among good ones (%s) → 400, nothing written', async (_label, bad) => {
    const before = snapshot();
    const r = await ensure({ names: ['use_ai_skills', 'ai_skill_report_writer', bad] });
    expect(r.status).toBe(400);
    expect(r.body.message).toBe('names[2] is not use_ai_skills or ai_skill_<slug>');
    expectNothingWritten(before);
  });

  it(`too many names (${MAX_ENSURE_NAMES + 1}) → 400, nothing written`, async () => {
    const names = ['use_ai_skills', ...Array.from({ length: MAX_ENSURE_NAMES }, (_, i) => `ai_skill_s${i}`)];
    expect(names).toHaveLength(102);
    const before = snapshot();
    const r = await ensure({ names });
    expect(r.status).toBe(400);
    expectNothingWritten(before);
  });

  it.each([
    ['an empty list', { names: [] }],
    ['no names', {}],
    ['names as a string', { names: 'use_ai_skills' }],
    ['names as an object', { names: { 0: 'use_ai_skills' } }],
    ['a bare array', ['use_ai_skills']],
    ['a grant request riding along', { names: ['use_ai_skills'], roleIds: [1] }],
    ['null', null],
    ['malformed JSON', '{"names": ["use_ai_skills"'],
  ])('%s → 400, nothing written', async (_label, body) => {
    const before = snapshot();
    const r = await ensure(body);
    expect(r.status).toBe(400);
    expectNothingWritten(before);
  });

  it('parses to the de-duplicated names in request order', () => {
    expect(parseEnsurePermissionsRequest({ names: ['ai_skill_b2', 'use_ai_skills', 'ai_skill_b2'] })).toEqual([
      'ai_skill_b2',
      'use_ai_skills',
    ]);
  });
});

// ─── Writing ────────────────────────────────────────────────────────────────

describe('ensure', () => {
  it('creates the missing rows and answers 200 {created, existing}', async () => {
    const r = await ensure(GOOD);
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ created: ['use_ai_skills', 'ai_skill_report_writer'], existing: [] });
    expect(db.permission.has('use_ai_skills')).toBe(true);
    expect(db.permission.has('ai_skill_report_writer')).toBe(true);
    expect(db.statements).toHaveLength(1);
    expect(db.statements[0].sql).toBe(ENSURE_SQL);
    expect(db.statements[0].values).toEqual([['use_ai_skills', 'ai_skill_report_writer']]);
    expectNoGrant();
  });

  it('separates created from existing, in request order, and leaves existing rows untouched', async () => {
    seed('use_ai_skills', 'ai_skill_old_one');
    const ids = { use: db.permission.get('use_ai_skills'), old: db.permission.get('ai_skill_old_one') };
    const r = await ensure({ names: ['ai_skill_new_one', 'use_ai_skills', 'ai_skill_old_one', 'ai_skill_new_two'] });
    expect(r.status).toBe(200);
    expect(r.body).toEqual({
      created: ['ai_skill_new_one', 'ai_skill_new_two'],
      existing: ['use_ai_skills', 'ai_skill_old_one'],
    });
    expect(db.permission.get('use_ai_skills')).toBe(ids.use);
    expect(db.permission.get('ai_skill_old_one')).toBe(ids.old);
    expectNoGrant();
  });

  it('is idempotent: the second identical call creates nothing and changes nothing', async () => {
    const first = await ensure(GOOD);
    const afterFirst = snapshot();
    const second = await ensure(GOOD);
    expect(first.body).toEqual({ created: ['use_ai_skills', 'ai_skill_report_writer'], existing: [] });
    expect(second.status).toBe(200);
    expect(second.body).toEqual({ created: [], existing: ['use_ai_skills', 'ai_skill_report_writer'] });
    expect([...db.permission.entries()]).toEqual([...afterFirst.entries()]);
    expectNoGrant();
  });

  it(`accepts exactly ${MAX_ENSURE_NAMES} names and the slug-length bounds`, async () => {
    const names = [
      'use_ai_skills',
      'ai_skill_ab',
      `ai_skill_${'z'.repeat(48)}`,
      ...Array.from({ length: MAX_ENSURE_NAMES - 3 }, (_, i) => `ai_skill_s${i}`),
    ];
    expect(names).toHaveLength(101);
    const r = await ensure({ names });
    expect(r.status).toBe(200);
    expect(r.body.created).toHaveLength(101);
    expect(r.body.existing).toEqual([]);
    expectNoGrant();
  });

  it('a repeated name is sent and reported once', async () => {
    const r = await ensure({ names: ['use_ai_skills', 'use_ai_skills', 'ai_skill_dup'] });
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ created: ['use_ai_skills', 'ai_skill_dup'], existing: [] });
    expect(db.statements[0].values).toEqual([['use_ai_skills', 'ai_skill_dup']]);
  });

  it('never writes RolePermission across a full import cycle', async () => {
    await ensure(GOOD);
    await ensure({ names: ['use_ai_skills', 'ai_skill_second'] });
    await ensure(GOOD);
    expect(db.statements).toHaveLength(3);
    expectNoGrant();
  });
});

// ─── Wiring ─────────────────────────────────────────────────────────────────

describe('wiring', () => {
  it('is mounted by PermissionsModule (so by AppModule)', () => {
    expect(Reflect.getMetadata('controllers', PermissionsModule)).toContain(EnsurePermissionsController);
    expect(Reflect.getMetadata('providers', PermissionsModule)).toContain(EnsurePermissionsService);
  });

  it('runs the proxy check before the secret check', () => {
    const guards = Reflect.getMetadata('__guards__', EnsurePermissionsController);
    expect(guards.map((g: { name: string }) => g.name)).toEqual(['DirectCallOnlyGuard', 'InternalGuard']);
  });
});
