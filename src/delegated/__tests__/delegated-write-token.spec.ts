/*
 * Synthetic keys, set before anything reads them. Never real credentials.
 */
const TEST_JWT_SECRET = 'synthetic-jwt-key-for-delegated-write-token-tests';
const TEST_INTERNAL_SECRET = 'synthetic-internal-secret-for-delegated-write-tests';
const TEST_WRITE_SECRET = 'synthetic-goal-write-secret-0123456789abcdef';
process.env.JWT_SECRET = TEST_JWT_SECRET;

import { INestApplication, Module } from '@nestjs/common';
import { APP_GUARD, NestFactory } from '@nestjs/core';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { AddressInfo } from 'net';

import { AuthGuard } from '../../auth/guards/auth.guard';
import { ALL_PERMISSIONS } from '../../permissions/permissions.service';
import { AuthPrismaService } from '../../prisma.service';
import { armenianValidationPipe } from '../../shared/validation-messages';
import { DelegatedTokenController, DelegatedTokensEnabledGuard } from '../delegated-token.controller';
import { DelegatedTokenService } from '../delegated-token.service';
import {
  DELEGATED_WRITE_TOKEN_TTL_SEC,
  WRITE_REQUIRED_AI_PERMISSIONS,
  WRITE_TOOLS,
  delegatedWriteTokensEnabled,
  goalWriteSecret,
  parseDelegatedWriteTokenRequest,
} from '../delegated-write-token.contract';
import {
  DelegatedWriteTokenController,
  DelegatedWriteTokensEnabledGuard,
  GoalWriteSecretGuard,
} from '../delegated-write-token.controller';

/*
 * The V3.4 write identity, over real HTTP against the real controllers,
 * guards and service. Prisma is a stub, hr-api a stub behind a fake fetch.
 */

interface Grant {
  entityId: number;
  name: string;
}
interface Assignment {
  entityId: number;
  isSuperAdmin?: boolean;
  grants: Grant[];
}

const g = (name: string, entityId = 0): Grant => ({ entityId, name });
const AI_WRITE_GRANTS = [...WRITE_REQUIRED_AI_PERMISSIONS].map((n) => g(n));

const db = {
  users: new Map<number, { id: number; email: string; deactivatedAt: Date | null }>(),
  roles: new Map<number, Assignment[]>(),
};

const prismaStub = {
  user: { findUnique: async ({ where }: any) => (db.users.get(where.id) ? { ...db.users.get(where.id)! } : null) },
  userRole: {
    findMany: async ({ where, select }: any) => {
      const entities: number[] = where.entityId.in;
      const permEntities: number[] = select.role.select.permissions.where.entityId.in;
      return (db.roles.get(where.userId) ?? [])
        .filter((a) => entities.includes(a.entityId))
        .map((a) => ({
          role: { permissions: a.grants.filter((x) => permEntities.includes(x.entityId)).map((x) => ({ permission: { name: x.name } })) },
        }));
    },
  },
};

const hr = { entities: new Map<number, number[] | number | null>(), calls: [] as string[] };
const realFetch = global.fetch;
const jwtCheck = new JwtService({ secret: TEST_JWT_SECRET });

function fakeFetch(url: any, init?: any): Promise<Response> {
  const href = String(url);
  if (!href.startsWith('http://hr.test/')) return realFetch(url, init);
  hr.calls.push(href);
  const who = (jwtCheck.decode(String(init?.headers?.authorization ?? '').replace(/^Bearer /, '')) as any)?.id;
  const answer = hr.entities.get(who);
  if (answer === null || answer === undefined) return Promise.reject(new Error('connect ECONNREFUSED'));
  if (typeof answer === 'number') return Promise.resolve(new Response('{}', { status: answer }));
  return Promise.resolve(new Response(JSON.stringify(answer.map((id) => ({ id }))), { status: 200, headers: { 'content-type': 'application/json' } }));
}

@Module({
  imports: [JwtModule.register({ global: true, secret: TEST_JWT_SECRET, signOptions: { expiresIn: '30d' } })],
  controllers: [DelegatedTokenController, DelegatedWriteTokenController],
  providers: [
    DelegatedTokenService,
    DelegatedTokensEnabledGuard,
    DelegatedWriteTokensEnabledGuard,
    GoalWriteSecretGuard,
    { provide: AuthPrismaService, useValue: prismaStub },
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
})
class TestModule {}

let app: INestApplication;
let base: string;
const savedEnv = { ...process.env };

beforeAll(async () => {
  global.fetch = fakeFetch as typeof fetch;
  app = await NestFactory.create(TestModule, { logger: false });
  app.setGlobalPrefix('api');
  app.useGlobalPipes(armenianValidationPipe({ transformOptions: { enableImplicitConversion: true } }));
  await app.listen(0, '127.0.0.1');
  base = `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
});

afterAll(async () => {
  await app?.close();
  global.fetch = realFetch;
  process.env = savedEnv;
});

beforeEach(() => {
  process.env.JWT_SECRET = TEST_JWT_SECRET;
  process.env.INTERNAL_SECRET = TEST_INTERNAL_SECRET;
  process.env.AI_GOALS_WRITE_TOKEN_SECRET = TEST_WRITE_SECRET;
  process.env.AUTH_DELEGATED_WRITE_TOKENS_ENABLED = 'true';
  delete process.env.AUTH_DELEGATED_TOKENS_ENABLED;
  delete process.env.MCP_EXCHANGE_SECRET;
  process.env.HR_API_URL = 'http://hr.test';

  db.users.clear();
  db.roles.clear();
  hr.entities.clear();
  hr.calls.length = 0;

  // Person 18: the four AI switches and manage_reservations in organisation 4; member of 4 and 7.
  db.users.set(18, { id: 18, email: 'owner@example.test', deactivatedAt: null });
  db.roles.set(18, [{ entityId: 4, grants: [...AI_WRITE_GRANTS, g('manage_reservations')] }]);
  hr.entities.set(18, [4, 7]);
});

const RESERVE = {
  userId: 18, entityId: 4, goalId: 'goal-3f2a', runId: 'run-0001', approvalId: 'appr-9c1e', tool: 'warehouse.reservations.create', scope: 'write',
  target: { taskId: 2462, itemId: 31, quantity: 2 } as Record<string, number>,
};
const MESSAGE = { ...RESERVE, tool: 'chat.messages.send', approvalId: 'appr-77aa', target: { chatId: 77 } as Record<string, number> };

async function call(path: string, body: unknown, headers: Record<string, string>) {
  const res = await realFetch(`${base}/api/internal/${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : undefined };
}
const mint = (body: unknown, headers: Record<string, string> = { 'x-goal-write-secret': TEST_WRITE_SECRET }) =>
  call('delegated-write-token', body, headers);

/** ai-api's own acceptance check (goal-write-token.http.ts), copied literally: the contract. */
function clientAccepts(body: any, req: typeof RESERVE): boolean {
  const scope = `goal:write:${req.tool}:${req.approvalId}`;
  const token = body?.access_token;
  return (
    typeof token === 'string' && token.length > 20 && !/\s/.test(token) &&
    body?.scope === scope && Number(body?.entity_id) === req.entityId &&
    body?.act?.sub === 'ai-goal' && body?.act?.goalId === req.goalId && body?.act?.approvalId === req.approvalId &&
    sameTarget(body?.target, req.target)
  );
}
function sameTarget(a: any, b: any): boolean {
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && a[k] === b[k] && typeof a[k] === 'number');
}

// ─── Flag ───────────────────────────────────────────────────────────────────

describe('AUTH_DELEGATED_WRITE_TOKENS_ENABLED off', () => {
  it.each([undefined, '', 'false', '0', '1', 'TRUE', 'yes'])('answers 404 when the flag is %p, even with the right secret', async (value) => {
    if (value === undefined) delete process.env.AUTH_DELEGATED_WRITE_TOKENS_ENABLED;
    else process.env.AUTH_DELEGATED_WRITE_TOKENS_ENABLED = value;
    const r = await mint(RESERVE);
    expect(r.status).toBe(404);
    expect(r.body?.access_token).toBeUndefined();
    expect(r.body.message).toBe('Cannot POST /api/internal/delegated-write-token');
    expect(hr.calls).toHaveLength(0);
  });

  it('looks exactly like a route that does not exist', async () => {
    delete process.env.AUTH_DELEGATED_WRITE_TOKENS_ENABLED;
    const off = await mint(RESERVE, {});
    const unknown = await realFetch(`${base}/api/internal/no-such-route`, { method: 'POST' });
    expect(off.status).toBe(unknown.status);
    expect(off.body.error).toBe((await unknown.json()).error);
  });

  it('leaves the read route exactly as it was: its own flag, its own secret, scope "read" only', async () => {
    // Write flag on, read flag off: the read route is still 404.
    expect((await call('delegated-token', { userId: 18, entityId: 4, goalId: 'g', scope: 'read' }, { 'x-internal-secret': TEST_INTERNAL_SECRET })).status).toBe(404);
    process.env.AUTH_DELEGATED_TOKENS_ENABLED = 'true';
    // The read route never mints a write scope, whatever it is asked.
    const asked = await call('delegated-token', { ...RESERVE }, { 'x-internal-secret': TEST_INTERNAL_SECRET });
    expect(asked.status).toBe(400);
    expect(asked.body?.access_token).toBeUndefined();
  });

  it('the read flag does not switch the write route on', async () => {
    delete process.env.AUTH_DELEGATED_WRITE_TOKENS_ENABLED;
    process.env.AUTH_DELEGATED_TOKENS_ENABLED = 'true';
    expect((await mint(RESERVE)).status).toBe(404);
  });

  it('is the flag rule, literally', () => {
    expect(delegatedWriteTokensEnabled({ AUTH_DELEGATED_WRITE_TOKENS_ENABLED: 'true' } as any)).toBe(true);
    expect(delegatedWriteTokensEnabled({} as any)).toBe(false);
    expect(delegatedWriteTokensEnabled({ AUTH_DELEGATED_TOKENS_ENABLED: 'true' } as any)).toBe(false);
  });
});

// ─── Its own secret ─────────────────────────────────────────────────────────

describe('AI_GOALS_WRITE_TOKEN_SECRET — its own, constant time, fail-closed', () => {
  it.each([
    ['absent', {}],
    ['empty', { 'x-goal-write-secret': '' }],
    ['wrong', { 'x-goal-write-secret': 'synthetic-goal-write-secret-0123456789abcdeX' }],
    ['a prefix of it', { 'x-goal-write-secret': TEST_WRITE_SECRET.slice(0, -1) }],
    ['INTERNAL_SECRET in its place', { 'x-goal-write-secret': TEST_INTERNAL_SECRET }],
    ['the right value in x-internal-secret', { 'x-internal-secret': TEST_WRITE_SECRET }],
    ['INTERNAL_SECRET in x-internal-secret', { 'x-internal-secret': TEST_INTERNAL_SECRET }],
  ])('refuses %s with 401', async (_label, headers) => {
    const r = await mint(RESERVE, headers as Record<string, string>);
    expect(r.status).toBe(401);
    expect(r.body?.access_token).toBeUndefined();
    expect(hr.calls).toHaveLength(0);
  });

  it('refuses everyone when the secret is unset or blank — no fallback', async () => {
    delete process.env.AI_GOALS_WRITE_TOKEN_SECRET;
    expect((await mint(RESERVE, { 'x-goal-write-secret': 'undefined' })).status).toBe(401);
    process.env.AI_GOALS_WRITE_TOKEN_SECRET = '   ';
    expect((await mint(RESERVE, { 'x-goal-write-secret': '   ' })).status).toBe(401);
  });

  it('refuses everyone when the secret EQUALS INTERNAL_SECRET, even presented correctly', async () => {
    const same = 'one-value-for-both-secrets-is-refused-0123456789';
    process.env.INTERNAL_SECRET = same;
    process.env.AI_GOALS_WRITE_TOKEN_SECRET = same;
    expect((await mint(RESERVE, { 'x-goal-write-secret': same })).status).toBe(401);
    expect(goalWriteSecret()).toBeNull();
  });

  it('refuses a secret shared with JWT_SECRET or MCP_EXCHANGE_SECRET, and a short one', () => {
    expect(goalWriteSecret({ AI_GOALS_WRITE_TOKEN_SECRET: TEST_WRITE_SECRET, JWT_SECRET: TEST_WRITE_SECRET } as any)).toBeNull();
    expect(goalWriteSecret({ AI_GOALS_WRITE_TOKEN_SECRET: TEST_WRITE_SECRET, MCP_EXCHANGE_SECRET: TEST_WRITE_SECRET } as any)).toBeNull();
    expect(goalWriteSecret({ AI_GOALS_WRITE_TOKEN_SECRET: 'short-secret' } as any)).toBeNull();
    expect(goalWriteSecret({ AI_GOALS_WRITE_TOKEN_SECRET: TEST_WRITE_SECRET, INTERNAL_SECRET: TEST_INTERNAL_SECRET } as any)).toBe(TEST_WRITE_SECRET);
  });

  it('does not accept a session token, or a delegated read token, in place of the secret', async () => {
    const session = jwtCheck.sign({ id: 18, email: 'owner@example.test' }, { expiresIn: '30d' });
    expect((await mint(RESERVE, { authorization: `Bearer ${session}` })).status).toBe(401);
  });
});

// ─── Request shape ──────────────────────────────────────────────────────────

describe('request validation', () => {
  it.each([
    ['a read scope', { ...RESERVE, scope: 'read' }],
    ['a full scope string', { ...RESERVE, scope: 'goal:write:warehouse.reservations.create:appr-9c1e' }],
    ['no approval', (({ approvalId: _a, ...rest }) => rest)(RESERVE)],
    ['no run', (({ runId: _r, ...rest }) => rest)(RESERVE)],
    ['no tool', (({ tool: _t, ...rest }) => rest)(RESERVE)],
    ['an approval id with a colon (it would forge the scope)', { ...RESERVE, approvalId: 'appr:chat.messages.send' }],
    ['entity 0 (every entity)', { ...RESERVE, entityId: 0 }],
    ['a workflow instead of a goal', { ...(({ goalId: _g, ...rest }) => rest)(RESERVE), workflowId: 'wf-1' }],
    ['an unexpected field', { ...RESERVE, arguments: { quantity: 99 } }],
    ['a finance mutation', { ...RESERVE, tool: 'finance.transfers.create' }],
    ['a delete', { ...RESERVE, tool: 'crm.tasks.delete' }],
    ['a tool outside the two', { ...RESERVE, tool: 'crm.tasks.create' }],
    ['a tool name with a colon', { ...RESERVE, tool: 'chat.messages.send:x' }],
    ['no target', (({ target: _t, ...rest }) => rest)(RESERVE)],
    ['a target that is not an object', { ...RESERVE, target: 2462 }],
    ['a reservation target without its item', { ...RESERVE, target: { taskId: 2462, quantity: 2 } }],
    ['a reservation target with a chat id', { ...RESERVE, target: { taskId: 2462, itemId: 31, quantity: 2, chatId: 77 } }],
    ['a reservation target with a second item', { ...RESERVE, target: { taskId: 2462, itemId: 31, quantity: 2, itemId2: 32 } }],
    ['a target id as a string', { ...RESERVE, target: { taskId: '2462', itemId: 31, quantity: 2 } }],
    ['a zero quantity', { ...RESERVE, target: { taskId: 2462, itemId: 31, quantity: 0 } }],
    ['a chat target for a reservation', { ...RESERVE, target: { chatId: 77 } }],
    ['a reservation target for a chat', { ...MESSAGE, target: { taskId: 2462, itemId: 31, quantity: 2 } }],
    ['a chat target with an extra field', { ...MESSAGE, target: { chatId: 77, userId: 19 } }],
  ])('answers 400 to %s — never delegation_refused', async (_label, body) => {
    const r = await mint(body);
    expect(r.status).toBe(400);
    expect(r.body?.error).not.toBe('delegation_refused');
    expect(r.body?.access_token).toBeUndefined();
  });

  it('names exactly the two V3.4 whitelist tools', () => {
    expect(Object.keys(WRITE_TOOLS).sort()).toEqual(['chat.messages.send', 'warehouse.reservations.create']);
    expect(parseDelegatedWriteTokenRequest(RESERVE)).toEqual(RESERVE);
  });

  it('signs a project into a reservation target only when the approval froze one', async () => {
    const r = await mint({ ...RESERVE, target: { projectId: 9, taskId: 2462, itemId: 31, quantity: 2 } });
    expect(r.status).toBe(200);
    expect(r.body.target).toEqual({ itemId: 31, projectId: 9, quantity: 2, taskId: 2462 });
    expect((jwtCheck.verify(r.body.access_token) as any).target).toEqual({ itemId: 31, projectId: 9, quantity: 2, taskId: 2462 });
  });
});

// ─── Minting ────────────────────────────────────────────────────────────────

describe('a successful mint', () => {
  it('returns a short write token that ai-api\'s client accepts, scoped to one tool and one approval', async () => {
    const r = await mint(RESERVE);
    expect(r.status).toBe(200);
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(r.body).toMatchObject({
      token_type: 'Bearer',
      expires_in: DELEGATED_WRITE_TOKEN_TTL_SEC,
      scope: 'goal:write:warehouse.reservations.create:appr-9c1e',
      entity_id: 4,
      target: { taskId: 2462, itemId: 31, quantity: 2 },
      act: { sub: 'ai-goal', goalId: 'goal-3f2a', runId: 'run-0001', approvalId: 'appr-9c1e' },
    });
    expect(clientAccepts(r.body, RESERVE)).toBe(true);
    expect(clientAccepts(r.body, { ...RESERVE, target: { taskId: 2462, itemId: 31, quantity: 3 } })).toBe(false);
    // …and not for the other tool, approval, goal or organisation.
    expect(clientAccepts(r.body, MESSAGE as any)).toBe(false);
    expect(clientAccepts(r.body, { ...RESERVE, approvalId: 'appr-other' })).toBe(false);
    expect(clientAccepts(r.body, { ...RESERVE, goalId: 'goal-other' })).toBe(false);
    expect(clientAccepts(r.body, { ...RESERVE, entityId: 7 })).toBe(false);

    const claims: any = jwtCheck.verify(r.body.access_token);
    expect(claims).toMatchObject({
      id: 18, email: 'owner@example.test', sub: '18', entityId: 4,
      scope: 'goal:write:warehouse.reservations.create:appr-9c1e',
      act: { sub: 'ai-goal', goalId: 'goal-3f2a', runId: 'run-0001', approvalId: 'appr-9c1e' },
      target: { taskId: 2462, itemId: 31, quantity: 2 },
      src: 'ai-delegated',
    });
    expect(typeof claims.jti).toBe('string');
    expect(claims.exp - claims.iat).toBe(DELEGATED_WRITE_TOKEN_TTL_SEC);
    expect(DELEGATED_WRITE_TOKEN_TTL_SEC).toBeLessThanOrEqual(300);
  });

  it('mints a chat token with the four AI switches alone (crm-api checks chat membership on the call)', async () => {
    db.roles.set(18, [{ entityId: 4, grants: AI_WRITE_GRANTS }]);
    const r = await mint(MESSAGE);
    expect(r.status).toBe(200);
    expect(r.body.scope).toBe('goal:write:chat.messages.send:appr-77aa');
    expect(r.body.target).toEqual({ chatId: 77 });
    expect((jwtCheck.verify(r.body.access_token) as any).target).toEqual({ chatId: 77 });
    expect(clientAccepts(r.body, MESSAGE)).toBe(true);
  });

  it('accepts view_warehouse or manage_warehouse as the reservation right, like the domain route', async () => {
    for (const right of ['view_warehouse', 'manage_warehouse']) {
      db.roles.set(18, [{ entityId: 4, grants: [...AI_WRITE_GRANTS, g(right)] }]);
      expect((await mint(RESERVE)).status).toBe(200);
    }
  });

  it('asks hr-api about membership at every mint', async () => {
    await mint(RESERVE);
    await mint(RESERVE);
    expect(hr.calls).toEqual(['http://hr.test/api/entities', 'http://hr.test/api/entities']);
  });
});

// ─── Rights, re-read at every mint ──────────────────────────────────────────

describe('a right lost is refused at issue (403 delegation_refused)', () => {
  it.each([...WRITE_REQUIRED_AI_PERMISSIONS])('without %s', async (lost) => {
    db.roles.set(18, [{ entityId: 4, grants: [...AI_WRITE_GRANTS.filter((x) => x.name !== lost), g('manage_reservations')] }]);
    const r = await mint(RESERVE);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'missing_permission', missing: [lost] });
    expect(r.body.access_token).toBeUndefined();
  });

  it('without the reservation right', async () => {
    db.roles.set(18, [{ entityId: 4, grants: AI_WRITE_GRANTS }]);
    const r = await mint(RESERVE);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'missing_tool_permission' });
  });

  it('revoked between two runs: the first mint succeeds, the next is refused', async () => {
    expect((await mint(RESERVE)).status).toBe(200);
    db.roles.set(18, [{ entityId: 4, grants: [...AI_WRITE_GRANTS.filter((x) => x.name !== 'ai_standing_approvals'), g('manage_reservations')] }]);
    expect((await mint(RESERVE)).body).toMatchObject({ error: 'delegation_refused', missing: ['ai_standing_approvals'] });
  });

  it('super admin stands in for none of them', async () => {
    db.roles.set(18, [{ entityId: 0, isSuperAdmin: true, grants: [] }]);
    const r = await mint(RESERVE);
    expect(r.status).toBe(403);
    expect(r.body.missing).toEqual([...WRITE_REQUIRED_AI_PERMISSIONS]);
  });

  it('a grant in another organisation does not count', async () => {
    db.roles.set(18, [{ entityId: 7, grants: [...AI_WRITE_GRANTS, g('manage_reservations')] }]);
    expect((await mint(RESERVE)).status).toBe(403);
    db.roles.set(18, [{ entityId: 4, grants: [...AI_WRITE_GRANTS.map((x) => g(x.name, 7)), g('manage_reservations')] }]);
    expect((await mint(RESERVE)).status).toBe(403);
  });

  it('another organisation: not a member there → refused', async () => {
    hr.entities.set(18, [7]);
    const r = await mint(RESERVE);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'no_organisation_access' });
  });

  it('a deactivated or unknown owner → refused', async () => {
    db.users.set(18, { id: 18, email: 'owner@example.test', deactivatedAt: new Date() });
    expect((await mint(RESERVE)).body).toMatchObject({ error: 'delegation_refused', reason: 'user_inactive' });
    expect((await mint({ ...RESERVE, userId: 99 })).body).toMatchObject({ error: 'delegation_refused', reason: 'user_not_found' });
  });

  it('hr-api unreachable is a 503 (retry later), never a token and never delegation_refused', async () => {
    hr.entities.set(18, null);
    const r = await mint(RESERVE);
    expect(r.status).toBe(503);
    expect(r.body.error).not.toBe('delegation_refused');
    expect(r.body.access_token).toBeUndefined();
  });
});

describe('ai_standing_approvals in the catalogue', () => {
  it('is seeded with the other AI switches', () => {
    expect(ALL_PERMISSIONS).toContain('ai_standing_approvals');
    expect(ALL_PERMISSIONS.filter((p) => p === 'ai_standing_approvals')).toHaveLength(1);
  });
});
