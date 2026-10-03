import { BadRequestException, ConflictException } from '@nestjs/common';
import { M } from '../../constants/messages';
import { RolesService } from '../roles.service';

/*
 * Read-only super administrator (2026-10-03): a second super-admin role
 * (isSuperAdmin + readOnly) that is assigned exactly like the first one and
 * is told apart by `readOnly` wherever roles are returned.
 */
const SUPER = { id: 1, name: 'Admin', level: 0, isSuperAdmin: true, readOnly: false, permissions: [] };
const READ_ONLY = { id: 2, name: 'Read-Only Super Admin', level: 0, isSuperAdmin: true, readOnly: true, permissions: [] };
const HR = { id: 3, name: 'HR', level: 1, isSuperAdmin: false, readOnly: false, permissions: [] };
const ROLES = [SUPER, READ_ONLY, HR];

type UserRow = { id: number; deactivatedAt: Date | null };
type UserRoleRow = { userId: number; roleId: number; entityId: number };

/**
 * A Prisma stand-in over three tables in memory. Writes queued through
 * deleteMany/createMany are thunks that `$transaction` runs, as the service
 * composes them.
 */
function fakePrisma(users: UserRow[], userRoles: UserRoleRow[]) {
  const state = { userRoles: [...userRoles] };
  const roleById = (id: number) => ROLES.find((r) => r.id === id)!;
  const matchRole = (r: typeof SUPER, where: any = {}) =>
    (where.isSuperAdmin === undefined || r.isSuperAdmin === where.isSuperAdmin) &&
    (where.readOnly === undefined || r.readOnly === where.readOnly) &&
    (where.id === undefined || (where.id.in ? where.id.in.includes(r.id) : r.id === where.id));
  const prisma: any = {
    role: {
      findMany: async ({ where = {} }: any) => ROLES.filter((r) => matchRole(r, where)),
      findFirst: async ({ where = {} }: any) => ROLES.find((r) => matchRole(r, where)) ?? null,
      findUnique: async ({ where }: any) => ROLES.find((r) => r.id === where.id) ?? null,
    },
    userRole: {
      findMany: async ({ where }: any) =>
        state.userRoles.filter(
          (ur) => ur.userId === where.userId && (where.roleId === undefined || where.roleId.in.includes(ur.roleId)),
        ),
      deleteMany: ({ where }: any) => () => {
        state.userRoles = state.userRoles.filter(
          (ur) => !(ur.userId === where.userId && (where.role === undefined || matchRole(roleById(ur.roleId), where.role))),
        );
      },
      createMany: ({ data }: any) => () => {
        state.userRoles.push(...data);
      },
    },
    user: {
      count: async ({ where }: any) =>
        users.filter(
          (u) =>
            u.id !== where.id.not &&
            u.deactivatedAt === null &&
            state.userRoles.some((ur) => ur.userId === u.id && matchRole(roleById(ur.roleId), where.roles.some.role)),
        ).length,
    },
    $transaction: async (ops: (() => void)[]) => ops.forEach((op) => op()),
  };
  return { prisma, state };
}

const active = (...ids: number[]): UserRow[] => ids.map((id) => ({ id, deactivatedAt: null }));
const sortRows = (rows: UserRoleRow[]) =>
  [...rows].sort((a, b) => a.userId - b.userId || a.roleId - b.roleId || a.entityId - b.entityId);

describe('Միայն դիտող սուպեր ադմինի դերը', () => {
  it('դերերի ցուցակը ցույց է տալիս readOnly դրոշը, սուպեր դերերը՝ միայն includeSuperAdmin-ով', async () => {
    const { prisma } = fakePrisma([], []);
    const service = new RolesService(prisma);

    const withSuper = await service.getAllRoles(undefined, true);
    expect(withSuper.map((r: any) => [r.name, r.isSuperAdmin, r.readOnly])).toEqual([
      ['Admin', true, false],
      ['Read-Only Super Admin', true, true],
      ['HR', false, false],
    ]);

    const plain = await service.getAllRoles();
    expect(plain.map((r: any) => r.name)).toEqual(['HR']);
    expect(plain.every((r: any) => r.readOnly === false)).toBe(true);
  });

  it('նշանակվում է նույն manageSuperAdmin ճանապարհով, ինչ սովորական սուպեր ադմինի դերը', async () => {
    const { prisma, state } = fakePrisma(active(1, 5), [{ userId: 1, roleId: SUPER.id, entityId: 0 }]);
    const service = new RolesService(prisma);

    // Without the super-admin path the role is as untouchable as the first one.
    await expect(
      service.assignRoleMapToUser(5, [{ entityId: 0, roleIds: [READ_ONLY.id] }]),
    ).rejects.toThrow(new BadRequestException(M.role.superAdminUntouchable));
    expect(state.userRoles.some((ur) => ur.userId === 5)).toBe(false);

    await service.assignRoleMapToUser(5, [{ entityId: 0, roleIds: [READ_ONLY.id, HR.id] }], {
      manageSuperAdmin: true,
      actorId: 1,
    });
    expect(sortRows(state.userRoles.filter((ur) => ur.userId === 5))).toEqual([
      { userId: 5, roleId: READ_ONLY.id, entityId: 0 },
      { userId: 5, roleId: HR.id, entityId: 0 },
    ]);
  });

  it('վերջին սուպեր ադմինի կանոնը միայն դիտողին չի հաշվում', async () => {
    const { prisma, state } = fakePrisma(active(1, 2), [
      { userId: 1, roleId: SUPER.id, entityId: 0 },
      { userId: 2, roleId: READ_ONLY.id, entityId: 0 },
    ]);
    const service = new RolesService(prisma);

    // User 2 (read-only) is the only other super holder: user 1 is still the
    // last writing super-admin, so dropping the role is refused.
    await expect(
      service.assignRoleMapToUser(1, [{ entityId: 0, roleIds: [HR.id] }], { manageSuperAdmin: true, actorId: 2 }),
    ).rejects.toThrow(new ConflictException(M.role.lastSuperAdmin));
    expect(state.userRoles).toContainEqual({ userId: 1, roleId: SUPER.id, entityId: 0 });

    // Dropping the read-only role never trips the rule.
    await service.assignRoleMapToUser(2, [{ entityId: 0, roleIds: [HR.id] }], { manageSuperAdmin: true, actorId: 1 });
    expect(state.userRoles.filter((ur) => ur.userId === 2)).toEqual([{ userId: 2, roleId: HR.id, entityId: 0 }]);
  });

  it('երկրորդ գրող սուպեր ադմինի առկայությամբ դերը հեռացվում է', async () => {
    const { prisma, state } = fakePrisma(active(1, 2, 3), [
      { userId: 1, roleId: SUPER.id, entityId: 0 },
      { userId: 2, roleId: READ_ONLY.id, entityId: 0 },
      { userId: 3, roleId: SUPER.id, entityId: 0 },
    ]);
    const service = new RolesService(prisma);
    await service.assignRoleMapToUser(1, [{ entityId: 0, roleIds: [HR.id] }], { manageSuperAdmin: true, actorId: 3 });
    expect(state.userRoles.filter((ur) => ur.userId === 1)).toEqual([{ userId: 1, roleId: HR.id, entityId: 0 }]);
  });

  it('սեփական միայն դիտող սուպեր ադմինի դերը հեռացնել հնարավոր չէ', async () => {
    const { prisma, state } = fakePrisma(active(1, 2), [
      { userId: 1, roleId: SUPER.id, entityId: 0 },
      { userId: 2, roleId: READ_ONLY.id, entityId: 0 },
    ]);
    const service = new RolesService(prisma);
    await expect(
      service.assignRoleMapToUser(2, [{ entityId: 0, roleIds: [HR.id] }], { manageSuperAdmin: true, actorId: 2 }),
    ).rejects.toThrow(new BadRequestException(M.role.superAdminSelfRemoval));
    expect(state.userRoles).toContainEqual({ userId: 2, roleId: READ_ONLY.id, entityId: 0 });
  });

  it('երկու սուպեր դերերը միաժամանակ մերժվում են 400-ով և ոչինչ չի գրվում', async () => {
    const before = [{ userId: 5, roleId: HR.id, entityId: 0 }];
    const { prisma, state } = fakePrisma(active(1, 5), [{ userId: 1, roleId: SUPER.id, entityId: 0 }, ...before]);
    const service = new RolesService(prisma);

    await expect(
      service.assignRoleMapToUser(5, [{ entityId: 0, roleIds: [SUPER.id, READ_ONLY.id] }], {
        manageSuperAdmin: true,
        actorId: 1,
      }),
    ).rejects.toThrow(new BadRequestException(M.role.superAdminBothRoles));
    // Split across entities it is still one account holding both.
    await expect(
      service.assignRoleMapToUser(5, [{ entityId: 0, roleIds: [SUPER.id] }, { entityId: 7, roleIds: [READ_ONLY.id] }], {
        manageSuperAdmin: true,
        actorId: 1,
      }),
    ).rejects.toThrow(new BadRequestException(M.role.superAdminBothRoles));
    expect(state.userRoles.filter((ur) => ur.userId === 5)).toEqual(before);
  });
});
