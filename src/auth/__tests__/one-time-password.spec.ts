/*
 * Synthetic key, set before anything reads it. Never a real credential.
 */
process.env.JWT_SECRET = 'synthetic-auth-otp-test-key';

import { ForbiddenException, INestApplication, Module } from '@nestjs/common';
import { APP_GUARD, NestFactory } from '@nestjs/core';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import type { AddressInfo } from 'net';

import { AuthController } from '../auth.controller';
import { AuthService } from '../auth.service';
import { AuthGuard } from '../guards/auth.guard';
import { ONE_TIME_PASSWORD_SESSION_TTL_SEC, isOneTimePasswordToken } from '../one-time-password';
import { AuthPrismaService } from '../../prisma.service';
import { OAuthError, OAuthService, OneTimePasswordFirstError } from '../../oauth/oauth.service';
import { UsersService } from '../../users/users.service';

/*
 * One-time-password sessions (2026-10-07). With ONE_TIME_PASSWORD_SESSIONS on,
 * the session of an account in one-time-password state carries `otp: true`
 * and lives an hour; the gateway and the domain guards then let it set its
 * password and read /auth/me, nothing else. /auth/me ends it once the account
 * has left the state. Off, every session is minted exactly as before.
 */

const SECRET = process.env.JWT_SECRET!;
const jwt = new JwtService({ secret: SECRET });
const TEMP = 'Temp-12345';
const MINE = 'Mine-12345';

type Row = { id: number; email: string; password: string; isOneTimePassword: boolean; deactivatedAt: Date | null; roles: [] };

function world() {
  const rows = new Map<number, Row>([
    [21, { id: 21, email: 'otp@example.test', password: bcrypt.hashSync(TEMP, 4), isOneTimePassword: true, deactivatedAt: null, roles: [] }],
    [22, { id: 22, email: 'settled@example.test', password: bcrypt.hashSync(MINE, 4), isOneTimePassword: false, deactivatedAt: null, roles: [] }],
  ]);
  const prisma: any = {
    user: {
      findFirst: async ({ where }: any) => [...rows.values()].find((r) => r.email === where.email) ?? null,
      findUnique: async ({ where }: any) => (rows.has(where.id) ? { ...rows.get(where.id)! } : null),
      update: async ({ where, data }: any) => Object.assign(rows.get(where.id)!, data),
    },
    permission: { count: async () => 0 },
  };
  /** What hr-api / crm-api password-reset does to the row: a new password and the flag off. */
  const reset = (id: number, password: string) =>
    Object.assign(rows.get(id)!, { password: bcrypt.hashSync(password, 4), isOneTimePassword: false });
  return { rows, prisma, reset };
}

const saved = process.env.ONE_TIME_PASSWORD_SESSIONS;
const setFlag = (v: string | undefined) => {
  if (v === undefined) delete process.env.ONE_TIME_PASSWORD_SESSIONS;
  else process.env.ONE_TIME_PASSWORD_SESSIONS = v;
};
afterEach(() => setFlag(saved));

const claims = (token: string) => jwt.verify(token) as Record<string, any>;

describe('flag off (the default): sessions are minted exactly as before', () => {
  it('a one-time-password account gets an ordinary 30-day session', async () => {
    setFlag(undefined);
    const { prisma } = world();
    // The module's own sign options (auth.module.ts): 30 days.
    const auth = new AuthService(prisma, new JwtService({ secret: SECRET, signOptions: { expiresIn: '30d' } }));
    const { access_token, user } = await auth.signIn('otp@example.test', TEMP);
    expect(claims(access_token).otp).toBeUndefined();
    expect(claims(access_token).exp - claims(access_token).iat).toBe(30 * 24 * 3600);
    expect((user as any).isOneTimePassword).toBe(true);
    // ...and /me does not judge it.
    await expect(auth.getMe(access_token)).resolves.toMatchObject({ user: { id: 21 } });
  });

  it.each(['false', '1', 'TRUE', ''])('ONE_TIME_PASSWORD_SESSIONS=%p is off', async (v) => {
    setFlag(v);
    const auth = new AuthService(world().prisma, new JwtService({ secret: SECRET, signOptions: { expiresIn: '30d' } }));
    expect(claims((await auth.signIn('otp@example.test', TEMP)).access_token).otp).toBeUndefined();
  });
});

describe('flag on: the tokens', () => {
  beforeEach(() => setFlag('true'));

  it('signIn marks a one-time-password account with otp: true and one hour', async () => {
    const auth = new AuthService(world().prisma, jwt);
    const c = claims((await auth.signIn('otp@example.test', TEMP)).access_token);
    expect(c).toMatchObject({ id: 21, email: 'otp@example.test', otp: true });
    expect(c.exp - c.iat).toBe(ONE_TIME_PASSWORD_SESSION_TTL_SEC);
    expect(ONE_TIME_PASSWORD_SESSION_TTL_SEC).toBe(3600);
  });

  it('an account with its own password is not marked', async () => {
    const auth = new AuthService(world().prisma, jwt);
    expect(claims((await auth.signIn('settled@example.test', MINE)).access_token).otp).toBeUndefined();
  });

  it('the handoff session (sessionForUser) is marked the same way — no full session in the next app', async () => {
    const auth = new AuthService(world().prisma, jwt);
    expect(claims((await auth.sessionForUser(21))!.access_token).otp).toBe(true);
    expect(claims((await auth.sessionForUser(22))!.access_token).otp).toBeUndefined();
  });

  it('the claim reading fails closed', () => {
    expect(isOneTimePasswordToken({ otp: true })).toBe(true);
    expect(isOneTimePasswordToken({ otp: 'yes' })).toBe(true);
    expect(isOneTimePasswordToken({ otp: false })).toBe(false);
    expect(isOneTimePasswordToken({})).toBe(false);
  });
});

describe('HTTP, flag on: sign in, /auth/me, reset, sign in again', () => {
  let app: INestApplication;
  let base = '';
  const w = world();

  // The real controller, service and global guard on a real port (this repo
  // carries no @nestjs/testing or supertest; fetch is enough).
  @Module({
    imports: [JwtModule.register({ global: true, secret: SECRET, signOptions: { expiresIn: '30d' } })],
    controllers: [AuthController],
    providers: [AuthService, { provide: AuthPrismaService, useValue: w.prisma }, { provide: APP_GUARD, useClass: AuthGuard }],
  })
  class OtpTestModule {}

  beforeAll(async () => {
    app = await NestFactory.create(OtpTestModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    base = `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
  });
  afterAll(async () => app?.close());
  beforeEach(() => setFlag('true'));

  type Answer = { status: number; body: any; cookies: string[] };
  const call = async (method: 'GET' | 'POST', path: string, opts: { body?: unknown; cookie?: string } = {}): Promise<Answer> => {
    const res = await fetch(base + path, {
      method,
      headers: {
        ...(opts.body ? { 'content-type': 'application/json' } : {}),
        ...(opts.cookie ? { cookie: opts.cookie } : {}),
      },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null, cookies: res.headers.getSetCookie() };
  };
  const server = {
    login: (email: string, password: string) => call('POST', '/auth/login', { body: { email, password } }),
    me: (cookie: string) => call('GET', '/auth/me', { cookie }),
  };
  const cookieOf = (res: Answer) => res.cookies.find((c) => c.startsWith('nairon_session=') && !c.startsWith('nairon_session=;'))!.split(';')[0];

  it('walks the whole one-time-password session', async () => {
    // 1. Sign in with the one-time password: a marked session, cookie and token alike.
    const login = await server.login('otp@example.test', TEMP);
    expect(login.status).toBe(200);
    expect(login.body.user.isOneTimePassword).toBe(true);
    expect(claims(login.body.access_token).otp).toBe(true);
    const cookie = cookieOf(login);
    expect(claims(decodeURIComponent(cookie.split('=')[1])).otp).toBe(true);

    // 2. /auth/me answers it (200) — the client reads isOneTimePassword from here too.
    const me = await server.me(cookie);
    expect(me.status).toBe(200);
    expect(me.body.user).toMatchObject({ id: 21, isOneTimePassword: true });
    expect(me.body.user).not.toHaveProperty('password');

    // 3. The password is replaced (hr-api / crm-api POST /users/password-reset).
    w.reset(21, MINE);

    // 4. The marked session is over: /me is 401, never an upgraded session.
    expect((await server.me(cookie)).status).toBe(401);

    // 5. Signing in again with the new password gives an ordinary session.
    const again = await server.login('otp@example.test', MINE);
    expect(again.status).toBe(200);
    expect(claims(again.body.access_token).otp).toBeUndefined();
    expect((await server.me(cookieOf(again))).status).toBe(200);
    // The one-time password no longer works at all.
    expect((await server.login('otp@example.test', TEMP)).status).toBe(400);
  });

  it('an unmarked session of an account in one-time-password state ends at /me (from before the flag, or before set-otp)', async () => {
    const old = `nairon_session=${jwt.sign({ id: 22, email: 'settled@example.test' }, { expiresIn: '30d' })}`;
    expect((await server.me(old)).status).toBe(200);
    w.rows.get(22)!.isOneTimePassword = true; // an admin sets a one-time password
    expect((await server.me(old)).status).toBe(401);
    // Flag off, that rule is off too.
    setFlag(undefined);
    expect((await server.me(old)).status).toBe(200);
    w.rows.get(22)!.isOneTimePassword = false;
  });

  it('a marked token is ended by /me even with the flag turned off again (rollback)', async () => {
    const marked = jwt.sign({ id: 22, email: 'settled@example.test', otp: true }, { expiresIn: 3600 });
    setFlag(undefined);
    expect((await server.me(`nairon_session=${marked}`)).status).toBe(401);
  });
});

describe('flag on: an MCP client is never the way round it', () => {
  const ENV = {
    OAUTH_ISSUER_URL: 'https://auth.example.test',
    OAUTH_PUBLIC_BASE_URL: 'https://auth.example.test',
    MCP_RESOURCE_URL: 'http://127.0.0.1:3010/mcp',
    OAUTH_TOKEN_SECRET: 'oauth-signing-key-for-otp-tests',
    OAUTH_ALLOWED_REDIRECT_HOSTS: 'chatgpt.com',
    HR_API_URL: '',
  } as NodeJS.ProcessEnv;
  const withEnv = <T>(fn: () => T): T => {
    const before = { ...process.env };
    Object.assign(process.env, ENV);
    try {
      return fn();
    } finally {
      process.env = before;
    }
  };

  function oauth(isOneTimePassword: boolean) {
    const user = { id: 21, email: 'otp@example.test', firstName: 'A', lastName: 'B', deactivatedAt: null, isOneTimePassword };
    const prisma: any = {
      oAuthGrant: {
        findUnique: async () => ({ id: 'grant-1', userId: 21, entityId: 7, revokedAt: null, user }),
      },
    };
    const auth: any = { signIn: async () => ({ user }) };
    const service = withEnv(() => new OAuthService(prisma, jwt, auth));
    const accessToken = withEnv(() =>
      jwt.sign(
        { typ: 'mcp_access', sub: '21', gid: 'grant-1', scope: 'nairon:mcp', ent: 7 },
        { secret: ENV.OAUTH_TOKEN_SECRET, expiresIn: 600, issuer: ENV.OAUTH_ISSUER_URL, audience: ENV.MCP_RESOURCE_URL },
      ),
    );
    return { service, accessToken };
  }

  beforeEach(() => setFlag('true'));

  it('authorize: the right one-time password is not enough', async () => {
    await expect(oauth(true).service.authenticate('otp@example.test', TEMP)).rejects.toBeInstanceOf(OneTimePasswordFirstError);
    await expect(oauth(false).service.authenticate('otp@example.test', MINE)).resolves.toMatchObject({ id: 21 });
  });

  it('exchange: a grant whose person has since been given a one-time password yields nothing', async () => {
    const otp = oauth(true);
    await expect(withEnv(() => otp.service.exchangeForInternalToken(otp.accessToken))).rejects.toBeInstanceOf(OAuthError);
    const ok = oauth(false);
    const result: any = await withEnv(() => ok.service.exchangeForInternalToken(ok.accessToken));
    expect(result.subject.id).toBe(21);
  });

  it('flag off: both behave as before', async () => {
    setFlag(undefined);
    await expect(oauth(true).service.authenticate('otp@example.test', TEMP)).resolves.toMatchObject({ id: 21 });
    const otp = oauth(true);
    await expect(withEnv(() => otp.service.exchangeForInternalToken(otp.accessToken))).resolves.toMatchObject({ subject: { id: 21 } });
  });
});

describe("auth-api's own internal POST /users/password-reset", () => {
  it('only while the account has a one-time password', async () => {
    const { prisma, rows } = world();
    const users = new UsersService(prisma);
    await expect(users.resetPassword(22, 'Another-1')).rejects.toBeInstanceOf(ForbiddenException);
    expect(bcrypt.compareSync(MINE, rows.get(22)!.password)).toBe(true);
    await users.resetPassword(21, 'Another-1');
    expect(rows.get(21)!.isOneTimePassword).toBe(false);
    await expect(users.resetPassword(21, 'Again-12345')).rejects.toBeInstanceOf(ForbiddenException);
  });
});
