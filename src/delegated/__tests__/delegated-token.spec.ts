/*
 * Synthetic keys, set before anything reads them. Never real credentials, and
 * never read from the environment.
 */
const TEST_JWT_SECRET = 'synthetic-jwt-key-for-delegated-token-tests';
const TEST_INTERNAL_SECRET = 'synthetic-internal-secret-for-delegated-token-tests';
process.env.JWT_SECRET = TEST_JWT_SECRET;

import { INestApplication, Module } from '@nestjs/common';
import { APP_GUARD, NestFactory } from '@nestjs/core';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { AddressInfo } from 'net';

import { AuthService } from '../../auth/auth.service';
import { AuthGuard } from '../../auth/guards/auth.guard';
import { ALL_PERMISSIONS } from '../../permissions/permissions.service';
import { AuthPrismaService } from '../../prisma.service';
import { armenianValidationPipe } from '../../shared/validation-messages';
import {
  DELEGATED_TOKEN_TTL_SEC,
  REQUIRED_PERMISSIONS,
  delegatedTokensEnabled,
  delegatedWorkflowTokensEnabled,
  parseDelegatedTokenRequest,
  requiredPermissions,
} from '../delegated-token.contract';
import { DelegatedTokenController, DelegatedTokensEnabledGuard } from '../delegated-token.controller';
import { DelegatedTokenService } from '../delegated-token.service';

/*
 * The delegated token, tested over real HTTP against the real controller,
 * guards and service. Prisma is a stub and hr-api is a stub reached through a
 * fake fetch; nothing leaves this process.
 */

// ─── Stubs ──────────────────────────────────────────────────────────────────

interface Grant {
  entityId: number;
  name: string;
}
interface Assignment {
  entityId: number;
  isSuperAdmin?: boolean;
  grants: Grant[];
}

/** Everything a goal or a workflow owner needs, at the base (entity 0) of the role. */
const AI_GRANTS: Grant[] = ['use_ai_assistant', 'ai_long_goals', 'ai_workflow_author'].map((name) => ({ entityId: 0, name }));

const db = {
  users: new Map<number, { id: number; email: string; deactivatedAt: Date | null }>(),
  roles: new Map<number, Assignment[]>(),
};

const prismaStub = {
  user: {
    findUnique: async ({ where }: any) => {
      const u = db.users.get(where.id);
      return u ? { ...u } : null;
    },
  },
  userRole: {
    findMany: async ({ where, select }: any) => {
      const entities: number[] = where.entityId.in;
      const permEntities: number[] = select.role.select.permissions.where.entityId.in;
      return (db.roles.get(where.userId) ?? [])
        .filter((a) => entities.includes(a.entityId))
        .map((a) => ({
          role: {
            permissions: a.grants
              .filter((g) => permEntities.includes(g.entityId))
              .map((g) => ({ permission: { name: g.name } })),
          },
        }));
    },
  },
};

/** hr-api's /api/entities, per person. `null` = unreachable, a number = that HTTP status. */
const hr = {
  entities: new Map<number, number[] | number | null>(),
  calls: [] as { url: string; authorization: string }[],
};

const realFetch = global.fetch;
const jwtCheck = new JwtService({ secret: TEST_JWT_SECRET });

function fakeFetch(url: any, init?: any): Promise<Response> {
  const href = String(url);
  if (!href.startsWith('http://hr.test/')) return realFetch(url, init);
  const authorization = String(init?.headers?.authorization ?? '');
  hr.calls.push({ url: href, authorization });
  const who = (jwtCheck.decode(authorization.replace(/^Bearer /, '')) as any)?.id;
  const answer = hr.entities.get(who);
  if (answer === null || answer === undefined) return Promise.reject(new Error('connect ECONNREFUSED'));
  if (typeof answer === 'number') {
    return Promise.resolve(new Response('{}', { status: answer }));
  }
  return Promise.resolve(
    new Response(JSON.stringify(answer.map((id) => ({ id, name: `Org ${id}` }))), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
}

// ─── App under test ─────────────────────────────────────────────────────────

@Module({
  imports: [JwtModule.register({ global: true, secret: TEST_JWT_SECRET, signOptions: { expiresIn: '30d' } })],
  controllers: [DelegatedTokenController],
  providers: [
    DelegatedTokenService,
    DelegatedTokensEnabledGuard,
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
  global.fetch = fakeFetch as typeof fetch;
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
  global.fetch = realFetch;
  process.env = savedEnv;
});

beforeEach(() => {
  process.env.JWT_SECRET = TEST_JWT_SECRET;
  process.env.INTERNAL_SECRET = TEST_INTERNAL_SECRET;
  process.env.AUTH_DELEGATED_TOKENS_ENABLED = 'true';
  process.env.AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED = 'true';
  process.env.HR_API_URL = 'http://hr.test';

  db.users.clear();
  db.roles.clear();
  hr.entities.clear();
  hr.calls.length = 0;

  // Person 18: active, AI assistant plus the goal and workflow switches
  // granted in organisation 4, member of 4 and 7.
  db.users.set(18, { id: 18, email: 'owner@example.test', deactivatedAt: null });
  db.roles.set(18, [{ entityId: 4, grants: [...AI_GRANTS, { entityId: 0, name: 'view_all_projects' }] }]);
  hr.entities.set(18, [4, 7]);
});

const GOAL = { userId: 18, entityId: 4, goalId: 'goal-3f2a', runId: 'run-0001', scope: 'read' };
const WORKFLOW = { userId: 18, entityId: 4, workflowId: 'wf-77', workflowVersionId: 'wfv-77.3', scope: 'read' };
const APPROVER = { ...WORKFLOW, role: 'approver' };

async function mint(body: unknown, headers: Record<string, string> = { 'x-internal-secret': TEST_INTERNAL_SECRET }) {
  const res = await realFetch(`${base}/api/internal/delegated-token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : undefined };
}

// ─── Flag ───────────────────────────────────────────────────────────────────

describe('AUTH_DELEGATED_TOKENS_ENABLED off', () => {
  it.each([undefined, '', 'false', '0', '1', 'TRUE', 'yes'])('answers 404 when the flag is %p, even with the right secret', async (value) => {
    if (value === undefined) delete process.env.AUTH_DELEGATED_TOKENS_ENABLED;
    else process.env.AUTH_DELEGATED_TOKENS_ENABLED = value;
    const r = await mint(GOAL);
    expect(r.status).toBe(404);
    expect(r.body?.access_token).toBeUndefined();
    expect(hr.calls).toHaveLength(0);
  });

  it('looks exactly like a route that does not exist', async () => {
    delete process.env.AUTH_DELEGATED_TOKENS_ENABLED;
    const off = await mint(GOAL, {});
    const unknown = await realFetch(`${base}/api/internal/no-such-route`, { method: 'POST' });
    const unknownBody = await unknown.json();
    expect(off.status).toBe(unknown.status);
    expect(off.body.error).toBe(unknownBody.error);
    expect(off.body.message).toBe('Cannot POST /api/internal/delegated-token');
  });

  it('is the flag rule, literally', () => {
    expect(delegatedTokensEnabled({ AUTH_DELEGATED_TOKENS_ENABLED: 'true' } as any)).toBe(true);
    expect(delegatedTokensEnabled({} as any)).toBe(false);
    expect(delegatedTokensEnabled({ AUTH_DELEGATED_TOKENS_ENABLED: 'True' } as any)).toBe(false);
  });
});

// ─── Service authentication ─────────────────────────────────────────────────

describe('INTERNAL_SECRET, fail-closed', () => {
  it.each([
    ['absent', {}],
    ['empty', { 'x-internal-secret': '' }],
    ['wrong', { 'x-internal-secret': 'not-the-secret' }],
  ])('refuses a %s header with 401', async (_label, headers) => {
    const r = await mint(GOAL, headers as Record<string, string>);
    expect(r.status).toBe(401);
    expect(r.body?.access_token).toBeUndefined();
  });

  it('refuses everyone when INTERNAL_SECRET is unset — no fallback value', async () => {
    delete process.env.INTERNAL_SECRET;
    expect((await mint(GOAL, {})).status).toBe(401);
    expect((await mint(GOAL, { 'x-internal-secret': 'undefined' })).status).toBe(401);
    expect((await mint(GOAL, { 'x-internal-secret': 'nairon-internal' })).status).toBe(401);
  });

  it('refuses everyone when INTERNAL_SECRET is blank', async () => {
    process.env.INTERNAL_SECRET = '   ';
    expect((await mint(GOAL, { 'x-internal-secret': '   ' })).status).toBe(401);
  });

  it('does not accept a user session token in place of the secret', async () => {
    const session = jwtCheck.sign({ id: 18, email: 'owner@example.test' }, { expiresIn: '30d' });
    expect((await mint(GOAL, { authorization: `Bearer ${session}` })).status).toBe(401);
  });

  it('never echoes the secret', async () => {
    const r = await mint(GOAL, { 'x-internal-secret': 'wrong' });
    expect(JSON.stringify(r.body)).not.toContain(TEST_INTERNAL_SECRET);
  });
});

// ─── Request shape ──────────────────────────────────────────────────────────

describe('request validation', () => {
  it.each([
    ['a write scope', { ...GOAL, scope: 'write' }],
    ['no scope', { userId: 18, entityId: 4, goalId: 'g1' }],
    ['entity 0 (every entity)', { ...GOAL, entityId: 0 }],
    ['no entity', { userId: 18, goalId: 'g1', scope: 'read' }],
    ['a negative user', { ...GOAL, userId: -1 }],
    ['both a goal and a workflow', { ...GOAL, workflowId: 'wf-1' }],
    ['neither a goal nor a workflow', { userId: 18, entityId: 4, scope: 'read' }],
    ['a malformed goal id', { ...GOAL, goalId: '../../etc' }],
    ['an unexpected field', { ...GOAL, act: { sub: 'root' } }],
    ['an array body', [GOAL]],
  ])('answers 400 to %s', async (_label, body) => {
    const r = await mint(body);
    expect(r.status).toBe(400);
    expect(r.body?.access_token).toBeUndefined();
  });

  it('derives the actor from the id it is given', () => {
    expect(parseDelegatedTokenRequest({ userId: 1, entityId: 2, goalId: 'g', scope: 'read' }).actor).toBe('ai-goal');
    expect(parseDelegatedTokenRequest({ userId: 1, entityId: 2, workflowId: 'w', workflowVersionId: 'v', scope: 'read' }).actor).toBe('ai-workflow');
  });

  it('defaults a workflow request to the author role, and keeps goals free of workflow fields', () => {
    const wf = parseDelegatedTokenRequest({ userId: 1, entityId: 2, workflowId: 'w', workflowVersionId: 'v', scope: 'read' });
    expect(wf).toMatchObject({ actor: 'ai-workflow', subjectId: 'w', workflowVersionId: 'v', role: 'author' });
    const ap = parseDelegatedTokenRequest({ userId: 1, entityId: 2, workflowId: 'w', workflowVersionId: 'v', role: 'approver', scope: 'read' });
    expect(ap.role).toBe('approver');
    const goal = parseDelegatedTokenRequest({ userId: 1, entityId: 2, goalId: 'g', scope: 'read' });
    expect(goal).not.toHaveProperty('role');
    expect(goal).not.toHaveProperty('workflowVersionId');
  });
});

describe('workflow request validation', () => {
  it.each([
    ['a workflow without workflowVersionId', { userId: 18, entityId: 4, workflowId: 'wf-77', scope: 'read' }],
    ['a null workflowVersionId', { ...WORKFLOW, workflowVersionId: null }],
    ['a malformed workflowVersionId', { ...WORKFLOW, workflowVersionId: '../v1' }],
    ['a numeric workflowVersionId', { ...WORKFLOW, workflowVersionId: 3 }],
    ['an unknown role', { ...WORKFLOW, role: 'admin' }],
    ['an upper-case role', { ...WORKFLOW, role: 'Author' }],
    ['an empty role', { ...WORKFLOW, role: '' }],
    ['a null role', { ...WORKFLOW, role: null }],
    ['a role that is not a string', { ...WORKFLOW, role: ['author'] }],
    ['workflowVersionId on a goal', { ...GOAL, workflowVersionId: 'wfv-77.3' }],
    ['role on a goal', { ...GOAL, role: 'author' }],
    ['role approver on a goal', { ...GOAL, role: 'approver' }],
    ['a null role on a goal', { ...GOAL, role: null }],
    ['both a goal and a workflow, fully formed', { ...WORKFLOW, goalId: 'goal-3f2a' }],
    ['an unexpected field on a workflow', { ...WORKFLOW, approverId: 9 }],
    ['a write scope on a workflow', { ...WORKFLOW, scope: 'write' }],
  ])('answers 400 to %s', async (_label, body) => {
    const r = await mint(body);
    expect(r.status).toBe(400);
    expect(r.body?.access_token).toBeUndefined();
    expect(hr.calls).toHaveLength(0);
  });
});

// ─── Minting ────────────────────────────────────────────────────────────────

describe('a successful mint', () => {
  it('returns a five-minute read token for a goal, with the agreed claims', async () => {
    const r = await mint(GOAL);
    expect(r.status).toBe(200);
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(r.body).toMatchObject({
      token_type: 'Bearer',
      expires_in: 300,
      scope: 'read',
      entity_id: 4,
      act: { sub: 'ai-goal', goalId: 'goal-3f2a', runId: 'run-0001' },
    });

    // Verifies with the same key every downstream service already holds.
    const claims: any = jwtCheck.verify(r.body.access_token);
    expect(claims).toMatchObject({
      id: 18,
      email: 'owner@example.test',
      sub: '18',
      entityId: 4,
      scope: 'read',
      act: { sub: 'ai-goal', goalId: 'goal-3f2a', runId: 'run-0001' },
      src: 'ai-delegated',
    });
    expect(typeof claims.jti).toBe('string');
    expect(claims.exp - claims.iat).toBe(DELEGATED_TOKEN_TTL_SEC);
    expect(DELEGATED_TOKEN_TTL_SEC).toBe(300);
  });

  it('returns act.sub=ai-workflow with the workflow, its version and the author role for a workflow run', async () => {
    const r = await mint(WORKFLOW);
    expect(r.status).toBe(200);
    const claims: any = jwtCheck.verify(r.body.access_token);
    expect(claims.act).toEqual({ sub: 'ai-workflow', workflowId: 'wf-77', workflowVersionId: 'wfv-77.3', role: 'author' });
    expect(claims.act.goalId).toBeUndefined();
  });

  it('gives every token its own jti', async () => {
    const a: any = jwtCheck.decode((await mint(GOAL)).body.access_token);
    const b: any = jwtCheck.decode((await mint(GOAL)).body.access_token);
    expect(a.jti).not.toBe(b.jti);
  });

  it('asks hr-api about membership as the person, with a short token that is not delegated', async () => {
    await mint(GOAL);
    expect(hr.calls).toHaveLength(1);
    expect(hr.calls[0].url).toBe('http://hr.test/api/entities');
    const probe: any = jwtCheck.verify(hr.calls[0].authorization.replace(/^Bearer /, ''));
    expect(probe.id).toBe(18);
    expect(probe.exp - probe.iat).toBe(60);
  });
});

// ─── Expiry ─────────────────────────────────────────────────────────────────

describe('expiry', () => {
  it('is valid until five minutes and not a second after', async () => {
    const token = (await mint(GOAL)).body.access_token;
    const { iat, exp }: any = jwtCheck.decode(token);
    expect(() => jwtCheck.verify(token, { clockTimestamp: iat + 299 })).not.toThrow();
    expect(() => jwtCheck.verify(token, { clockTimestamp: exp })).toThrow(/jwt expired/);
    expect(() => jwtCheck.verify(token, { clockTimestamp: exp + 1 })).toThrow(/jwt expired/);
  });

  it('does not verify under any other key', async () => {
    const token = (await mint(GOAL)).body.access_token;
    expect(() => new JwtService({ secret: 'another-key' }).verify(token)).toThrow();
  });
});

// ─── Refusals: the person is re-read at every mint ───────────────────────────

describe('refusals', () => {
  it('refuses an inactive (deactivated) user with 403 user_inactive', async () => {
    db.users.set(18, { id: 18, email: 'owner@example.test', deactivatedAt: new Date('2026-09-29T00:00:00Z') });
    const r = await mint(GOAL);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'user_inactive' });
    expect(r.body.access_token).toBeUndefined();
  });

  it('refuses a user that no longer exists with 403 user_not_found', async () => {
    db.users.delete(18);
    const r = await mint(GOAL);
    expect(r.status).toBe(403);
    expect(r.body.reason).toBe('user_not_found');
  });

  it('refuses a user who lost the organisation with 403 no_organisation_access', async () => {
    hr.entities.set(18, [7]);
    const r = await mint(GOAL);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'no_organisation_access' });
  });

  it('refuses a user who belongs to no organisation at all', async () => {
    hr.entities.set(18, []);
    expect((await mint(GOAL)).body.reason).toBe('no_organisation_access');
  });

  it('refuses without use_ai_assistant in that organisation', async () => {
    db.roles.set(18, [{ entityId: 4, grants: AI_GRANTS.filter((g) => g.name !== 'use_ai_assistant') }]);
    const r = await mint(GOAL);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ reason: 'missing_permission', missing: ['use_ai_assistant'] });
  });

  it('does not borrow a grant held only in another organisation', async () => {
    db.roles.set(18, [{ entityId: 7, grants: AI_GRANTS }]);
    expect((await mint(GOAL)).body.reason).toBe('missing_permission');
    db.roles.set(18, [{ entityId: 0, grants: AI_GRANTS.map((g) => ({ ...g, entityId: 7 })) }]);
    expect((await mint(GOAL)).body.reason).toBe('missing_permission');
  });

  it('accepts a wildcard assignment (entity 0) that grants it everywhere', async () => {
    db.roles.set(18, [{ entityId: 0, grants: AI_GRANTS }]);
    expect((await mint(GOAL)).status).toBe(200);
  });

  it('does not let super admin stand in for the AI grant', async () => {
    db.roles.set(18, [{ entityId: 0, isSuperAdmin: true, grants: [{ entityId: 0, name: 'view_all_projects' }] }]);
    const goal = await mint(GOAL);
    expect(goal.body.reason).toBe('missing_permission');
    expect(goal.body.missing).toEqual(['use_ai_assistant', 'ai_long_goals']);
    const workflow = await mint(WORKFLOW);
    expect(workflow.body.reason).toBe('missing_permission');
    expect(workflow.body.missing).toEqual(['use_ai_assistant', 'ai_workflow_author']);
  });

  it('does not let super admin stand in for ai_long_goals or ai_workflow_author either', async () => {
    db.roles.set(18, [{ entityId: 0, isSuperAdmin: true, grants: [{ entityId: 0, name: 'use_ai_assistant' }] }]);
    expect((await mint(GOAL)).body).toMatchObject({ reason: 'missing_permission', missing: ['ai_long_goals'] });
    expect((await mint(WORKFLOW)).body).toMatchObject({ reason: 'missing_permission', missing: ['ai_workflow_author'] });
  });
});

// ─── The dedicated switches: ai_long_goals (V3), ai_workflow_author (V5) ─────

describe('the switch each actor needs on top of use_ai_assistant', () => {
  it('is ai_long_goals for a goal, ai_workflow_author for a workflow author and nothing more for an approver, literally', () => {
    expect(REQUIRED_PERMISSIONS).toEqual({
      'ai-goal': ['use_ai_assistant', 'ai_long_goals'],
      'ai-workflow:author': ['use_ai_assistant', 'ai_workflow_author'],
      'ai-workflow:approver': ['use_ai_assistant'],
    });
    expect(requiredPermissions({ actor: 'ai-goal' })).toEqual(['use_ai_assistant', 'ai_long_goals']);
    expect(requiredPermissions({ actor: 'ai-workflow', role: 'author' })).toEqual(['use_ai_assistant', 'ai_workflow_author']);
    expect(requiredPermissions({ actor: 'ai-workflow', role: 'approver' })).toEqual(['use_ai_assistant']);
    // A workflow request without a role is checked as the stricter author, never as an approver.
    expect(requiredPermissions({ actor: 'ai-workflow' })).toEqual(['use_ai_assistant', 'ai_workflow_author']);
  });

  it('names only permissions that are in the catalogue the owner grants from', () => {
    for (const name of Object.values(REQUIRED_PERMISSIONS).flat()) {
      expect(ALL_PERMISSIONS).toContain(name);
    }
  });

  it('refuses a goal without ai_long_goals, even with use_ai_assistant', async () => {
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 0, name: 'ai_workflow_author' }] }]);
    const r = await mint(GOAL);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'missing_permission', missing: ['ai_long_goals'] });
    expect(r.body.access_token).toBeUndefined();
    // Refused before membership is even asked.
    expect(hr.calls).toHaveLength(0);
  });

  it('refuses a workflow without ai_workflow_author, even with use_ai_assistant', async () => {
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 0, name: 'ai_long_goals' }] }]);
    const r = await mint(WORKFLOW);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'missing_permission', missing: ['ai_workflow_author'] });
    expect(r.body.access_token).toBeUndefined();
  });

  it('refuses either without use_ai_assistant, even with the dedicated switch', async () => {
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'ai_long_goals' }, { entityId: 0, name: 'ai_workflow_author' }] }]);
    expect((await mint(GOAL)).body).toMatchObject({ reason: 'missing_permission', missing: ['use_ai_assistant'] });
    expect((await mint(WORKFLOW)).body).toMatchObject({ reason: 'missing_permission', missing: ['use_ai_assistant'] });
  });

  it('mints a goal token with use_ai_assistant + ai_long_goals alone', async () => {
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 0, name: 'ai_long_goals' }] }]);
    expect((await mint(GOAL)).status).toBe(200);
    expect((await mint(WORKFLOW)).body.missing).toEqual(['ai_workflow_author']);
  });

  it('mints a workflow token with use_ai_assistant + ai_workflow_author alone', async () => {
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 0, name: 'ai_workflow_author' }] }]);
    expect((await mint(WORKFLOW)).status).toBe(200);
    expect((await mint(GOAL)).body.missing).toEqual(['ai_long_goals']);
  });

  it('accepts the switch granted as an extra for that organisation only', async () => {
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 4, name: 'ai_long_goals' }] }]);
    expect((await mint(GOAL)).status).toBe(200);
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 7, name: 'ai_long_goals' }] }]);
    expect((await mint(GOAL)).body.missing).toEqual(['ai_long_goals']);
  });

  it('re-reads the switch on every mint: taking it away suspends the next run', async () => {
    expect((await mint(GOAL)).status).toBe(200);
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }] }]);
    expect((await mint(GOAL)).body.reason).toBe('missing_permission');
  });

  it('re-reads on every mint: a change of status or membership lands at the next run', async () => {
    expect((await mint(GOAL)).status).toBe(200);
    hr.entities.set(18, [7]);
    expect((await mint(GOAL)).body.reason).toBe('no_organisation_access');
    hr.entities.set(18, [4]);
    expect((await mint(GOAL)).status).toBe(200);
    db.users.set(18, { id: 18, email: 'owner@example.test', deactivatedAt: new Date() });
    expect((await mint(GOAL)).body.reason).toBe('user_inactive');
  });

  it('answers 503 (retry, do not suspend) when hr-api cannot be reached', async () => {
    hr.entities.set(18, null);
    const r = await mint(GOAL);
    expect(r.status).toBe(503);
    expect(r.body).toMatchObject({ error: 'membership_unavailable' });
    expect(r.body.access_token).toBeUndefined();
  });

  it('answers 503 when hr-api refuses the lookup', async () => {
    hr.entities.set(18, 500);
    expect((await mint(GOAL)).status).toBe(503);
  });

  it('answers 503, never a token, when HR_API_URL is not configured', async () => {
    delete process.env.HR_API_URL;
    const r = await mint(GOAL);
    expect(r.status).toBe(503);
    expect(r.body.access_token).toBeUndefined();
  });
});

// ─── The workflow form: its own switch ──────────────────────────────────────

describe('AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED', () => {
  it.each([undefined, '', 'false', '0', '1', 'TRUE', 'yes'])(
    'answers a workflow request 404 when the sub-flag is %p (read flag on), and still mints for a goal',
    async (value) => {
      if (value === undefined) delete process.env.AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED;
      else process.env.AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED = value;
      for (const body of [WORKFLOW, APPROVER]) {
        const r = await mint(body);
        expect(r.status).toBe(404);
        expect(r.body?.access_token).toBeUndefined();
      }
      expect(hr.calls).toHaveLength(0);
      const goal = await mint(GOAL);
      expect(goal.status).toBe(200);
      expect(goal.body.act).toEqual({ sub: 'ai-goal', goalId: 'goal-3f2a', runId: 'run-0001' });
    },
  );

  it('with the sub-flag off, a workflow request looks exactly like a route that does not exist', async () => {
    delete process.env.AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED;
    const wfOff = await realFetch(`${base}/api/internal/delegated-token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-secret': TEST_INTERNAL_SECRET },
      body: JSON.stringify(WORKFLOW),
    });
    const wfOffBody = await wfOff.json();

    // The 404 the read flag gives when the whole route is off…
    delete process.env.AUTH_DELEGATED_TOKENS_ENABLED;
    const routeOff = await realFetch(`${base}/api/internal/delegated-token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(WORKFLOW),
    });
    const routeOffBody = await routeOff.json();
    // …and the one Nest gives a route that does not exist.
    const unknown = await realFetch(`${base}/api/internal/no-such-route`, { method: 'POST' });
    const unknownBody = await unknown.json();

    expect(wfOff.status).toBe(404);
    expect(wfOff.status).toBe(routeOff.status);
    expect(wfOff.status).toBe(unknown.status);
    expect(wfOffBody).toEqual(routeOffBody);
    expect(wfOffBody).toEqual({ ...unknownBody, message: 'Cannot POST /api/internal/delegated-token' });
    expect(wfOff.headers.get('cache-control')).toBe(unknown.headers.get('cache-control'));
    expect(wfOff.headers.get('content-type')).toBe(unknown.headers.get('content-type'));
  });

  it('still checks the secret first: a workflow request without it is 401, not 404', async () => {
    delete process.env.AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED;
    expect((await mint(WORKFLOW, {})).status).toBe(401);
    expect((await mint(WORKFLOW, { 'x-internal-secret': 'wrong' })).status).toBe(401);
  });

  it('decides after the body parses: a malformed workflow body is still a 400', async () => {
    delete process.env.AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED;
    expect((await mint({ ...WORKFLOW, workflowVersionId: undefined })).status).toBe(400);
    expect((await mint({ ...WORKFLOW, role: 'admin' })).status).toBe(400);
  });

  it('does not switch the route on by itself', async () => {
    delete process.env.AUTH_DELEGATED_TOKENS_ENABLED;
    process.env.AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED = 'true';
    expect((await mint(WORKFLOW)).status).toBe(404);
    expect((await mint(GOAL)).status).toBe(404);
  });

  it('is the flag rule, literally: both flags exactly "true"', () => {
    const on = { AUTH_DELEGATED_TOKENS_ENABLED: 'true', AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED: 'true' } as any;
    expect(delegatedWorkflowTokensEnabled(on)).toBe(true);
    expect(delegatedWorkflowTokensEnabled({} as any)).toBe(false);
    expect(delegatedWorkflowTokensEnabled({ AUTH_DELEGATED_TOKENS_ENABLED: 'true' } as any)).toBe(false);
    expect(delegatedWorkflowTokensEnabled({ AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED: 'true' } as any)).toBe(false);
    for (const v of ['True', 'TRUE', '1', 'yes', ' true', '']) {
      expect(delegatedWorkflowTokensEnabled({ ...on, AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED: v })).toBe(false);
      expect(delegatedWorkflowTokensEnabled({ ...on, AUTH_DELEGATED_TOKENS_ENABLED: v })).toBe(false);
    }
  });
});

// ─── Workflow author ────────────────────────────────────────────────────────

describe('a workflow token for the author', () => {
  it('is a five-minute read token whose act names the workflow, its version, the role and the run', async () => {
    const r = await mint({ ...WORKFLOW, role: 'author', runId: 'wfrun-9' });
    expect(r.status).toBe(200);
    expect(r.headers.get('cache-control')).toBe('no-store');
    const act = { sub: 'ai-workflow', workflowId: 'wf-77', workflowVersionId: 'wfv-77.3', role: 'author', runId: 'wfrun-9' };
    expect(r.body).toMatchObject({ token_type: 'Bearer', expires_in: 300, scope: 'read', entity_id: 4 });
    expect(r.body.act).toEqual(act);

    const claims: any = jwtCheck.verify(r.body.access_token);
    expect(claims).toMatchObject({ id: 18, email: 'owner@example.test', sub: '18', entityId: 4, scope: 'read', src: 'ai-delegated' });
    expect(claims.act).toEqual(act);
    expect(claims.exp - claims.iat).toBe(300);
    expect(() => new JwtService({ secret: 'another-key' }).verify(r.body.access_token)).toThrow();
  });

  it('is refused 403 missing_permission without ai_workflow_author, and minted with it', async () => {
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 0, name: 'ai_long_goals' }] }]);
    const refused = await mint(WORKFLOW);
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({ error: 'delegation_refused', reason: 'missing_permission', missing: ['ai_workflow_author'] });
    expect(refused.body.access_token).toBeUndefined();
    expect(hr.calls).toHaveLength(0);

    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 0, name: 'ai_workflow_author' }] }]);
    const minted = await mint(WORKFLOW);
    expect(minted.status).toBe(200);
    expect(minted.body.act.role).toBe('author');
  });

  it('does not let super admin stand in for ai_workflow_author', async () => {
    db.roles.set(18, [{ entityId: 0, isSuperAdmin: true, grants: [{ entityId: 0, name: 'use_ai_assistant' }] }]);
    expect((await mint({ ...WORKFLOW, role: 'author' })).body).toMatchObject({
      error: 'delegation_refused',
      reason: 'missing_permission',
      missing: ['ai_workflow_author'],
    });
  });

  it('re-reads the switch on every mint: losing ai_workflow_author refuses the next mint', async () => {
    expect((await mint(WORKFLOW)).status).toBe(200);
    db.roles.set(18, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }, { entityId: 0, name: 'ai_long_goals' }] }]);
    const next = await mint(WORKFLOW);
    expect(next.status).toBe(403);
    expect(next.body).toMatchObject({ reason: 'missing_permission', missing: ['ai_workflow_author'] });
  });
});

// ─── Workflow approver ──────────────────────────────────────────────────────

describe('a workflow token for an approver', () => {
  beforeEach(() => {
    // Person 25: an approver with the assistant and nothing else AI-related.
    db.users.set(25, { id: 25, email: 'approver@example.test', deactivatedAt: null });
    db.roles.set(25, [{ entityId: 4, grants: [{ entityId: 0, name: 'use_ai_assistant' }] }]);
    hr.entities.set(25, [4]);
  });

  const AS_APPROVER = { ...APPROVER, userId: 25, runId: 'wfrun-9' };

  it('mints with use_ai_assistant alone, and says so in act', async () => {
    const r = await mint(AS_APPROVER);
    expect(r.status).toBe(200);
    const act = { sub: 'ai-workflow', workflowId: 'wf-77', workflowVersionId: 'wfv-77.3', role: 'approver', runId: 'wfrun-9' };
    expect(r.body.act).toEqual(act);
    const claims: any = jwtCheck.verify(r.body.access_token);
    expect(claims).toMatchObject({ id: 25, sub: '25', entityId: 4, scope: 'read', src: 'ai-delegated' });
    expect(claims.act).toEqual(act);
    expect(claims.exp - claims.iat).toBe(300);
  });

  it('gives the same person no author token', async () => {
    const r = await mint({ ...AS_APPROVER, role: 'author' });
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ reason: 'missing_permission', missing: ['ai_workflow_author'] });
  });

  it('refuses 403 without use_ai_assistant, whatever else the person holds', async () => {
    db.roles.set(25, [{ entityId: 4, grants: ['ai_workflow_author', 'ai_long_goals', 'ai_write_actions'].map((name) => ({ entityId: 0, name })) }]);
    const r = await mint(AS_APPROVER);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'missing_permission', missing: ['use_ai_assistant'] });
    expect(r.body.access_token).toBeUndefined();
  });

  it('does not let super admin stand in for use_ai_assistant', async () => {
    db.roles.set(25, [{ entityId: 0, isSuperAdmin: true, grants: [{ entityId: 0, name: 'view_all_projects' }] }]);
    expect((await mint(AS_APPROVER)).body).toMatchObject({ reason: 'missing_permission', missing: ['use_ai_assistant'] });
  });

  it('refuses an inactive approver with 403 user_inactive', async () => {
    db.users.set(25, { id: 25, email: 'approver@example.test', deactivatedAt: new Date('2026-09-30T00:00:00Z') });
    const r = await mint(AS_APPROVER);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'user_inactive' });
  });

  it('refuses an approver who is not a member of the organisation with 403 no_organisation_access', async () => {
    hr.entities.set(25, [7]);
    const r = await mint(AS_APPROVER);
    expect(r.status).toBe(403);
    expect(r.body).toMatchObject({ error: 'delegation_refused', reason: 'no_organisation_access' });
    expect(r.body.access_token).toBeUndefined();
  });
});

// ─── The normal login token is untouched ─────────────────────────────────────

describe('normal login tokens', () => {
  it('still carry only id and email, live 30 days, and have no act or scope', async () => {
    const password = bcrypt.hashSync('correct horse', 4);
    const prisma = {
      user: {
        findFirst: async () => ({ id: 18, email: 'owner@example.test', password, deactivatedAt: null, roles: [] }),
      },
    } as unknown as AuthPrismaService;
    const jwt = new JwtService({ secret: TEST_JWT_SECRET, signOptions: { expiresIn: '30d' } });
    const { access_token } = await new AuthService(prisma, jwt).signIn('owner@example.test', 'correct horse');

    const claims: any = jwtCheck.verify(access_token);
    expect(Object.keys(claims).sort()).toEqual(['email', 'exp', 'iat', 'id']);
    expect(claims.exp - claims.iat).toBe(30 * 24 * 3600);
  });
});
