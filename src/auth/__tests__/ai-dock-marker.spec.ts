import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';

import { AI_DOCK_MARKER, AuthService } from '../auth.service';
import { AI_DOCK_PERMISSIONS } from '../../permissions/permissions.service';

/**
 * AI dock controls (2026-10-06): every session response carries `user.aiDockPermissions: true` while the catalogue
 * holds all nine dock rows, so the dock reads them literally (unticked = off). No rows, or a failed read: no marker,
 * and the dock keeps every control on as before. Never fails a sign-in.
 */
const jwt = new JwtService({ secret: 'synthetic-key-for-dock-marker-tests' });
const password = bcrypt.hashSync('correct horse', 4);
const row = { id: 18, email: 'owner@example.test', password, deactivatedAt: null, roles: [] };

function service(count: () => Promise<number>) {
  const counted = jest.fn(count);
  const prisma = {
    user: { findFirst: async () => row, findUnique: async () => row },
    permission: { count: counted },
  };
  return { auth: new AuthService(prisma as never, jwt), counted };
}

describe('the AI dock marker on a session', () => {
  it('is named aiDockPermissions and asks for exactly the nine rows', async () => {
    expect(AI_DOCK_MARKER).toBe('aiDockPermissions');
    const { auth, counted } = service(async () => 9);
    await auth.signIn('owner@example.test', 'correct horse');
    expect(counted).toHaveBeenCalledWith({ where: { name: { in: [...AI_DOCK_PERMISSIONS] } } });
    expect(AI_DOCK_PERMISSIONS).toHaveLength(9);
  });

  it('all nine rows: signIn, getMe and the handoff session carry aiDockPermissions: true at the top level and on user', async () => {
    const { auth } = service(async () => 9);
    const signed = await auth.signIn('owner@example.test', 'correct horse');
    expect(signed).toMatchObject({ aiDockPermissions: true, user: { id: 18, aiDockPermissions: true } });
    expect((signed as Record<string, unknown>).aiDockPermissions).toBe(true);
    expect(signed.user).not.toHaveProperty('password');
    const me = await auth.getMe(signed.access_token);
    expect(me).toMatchObject({ access_token: signed.access_token, aiDockPermissions: true, user: { id: 18, aiDockPermissions: true } });
    expect(await auth.sessionForUser(18)).toMatchObject({ aiDockPermissions: true, user: { aiDockPermissions: true } });
  });

  it('rows missing: no marker anywhere — absent, never false (the dock keeps every control on)', async () => {
    const { auth } = service(async () => 8);
    const signed = await auth.signIn('owner@example.test', 'correct horse');
    expect(Object.keys(signed).sort()).toEqual(['access_token', 'user']);
    expect(signed.user).not.toHaveProperty('aiDockPermissions');
  });

  it('a failed read never fails the sign-in: no marker, and the next session asks again', async () => {
    let fail = true;
    const { auth, counted } = service(async () => { if (fail) throw new Error('db down'); return 9; });
    const first = await auth.signIn('owner@example.test', 'correct horse');
    expect(first.user).not.toHaveProperty('aiDockPermissions');
    fail = false;
    expect((await auth.signIn('owner@example.test', 'correct horse')).user).toMatchObject({ aiDockPermissions: true });
    expect(counted).toHaveBeenCalledTimes(2);
  });

  it('once present it is remembered; absent is re-read after a minute', async () => {
    const present = service(async () => 9);
    for (let i = 0; i < 3; i++) await present.auth.signIn('owner@example.test', 'correct horse');
    expect(present.counted).toHaveBeenCalledTimes(1);

    const now = jest.spyOn(Date, 'now').mockReturnValue(1_000_000);
    try {
      const absent = service(async () => 0);
      await absent.auth.signIn('owner@example.test', 'correct horse');
      await absent.auth.signIn('owner@example.test', 'correct horse');
      expect(absent.counted).toHaveBeenCalledTimes(1);
      now.mockReturnValue(1_000_000 + 60_001);
      await absent.auth.signIn('owner@example.test', 'correct horse');
      expect(absent.counted).toHaveBeenCalledTimes(2);
    } finally {
      now.mockRestore();
    }
  });
});
